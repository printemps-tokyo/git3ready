//! End-to-end tests against the built binary.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use git3ready::json::{self, Value};

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_git3ready"));
    c.env_remove("NO_COLOR");
    c
}

/// A Git invocation isolated from the developer's own configuration.
fn git(dir: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_DEFAULT_HASH")
        .env_remove("GIT_DEFAULT_REF_FORMAT")
        .env_remove("GIT_DEFAULT_REF_STORAGE_FORMAT")
        .env_remove("GIT_DIR")
        .output()
        .expect("git runs")
}

fn have_git() -> bool {
    Command::new("git").arg("version").output().is_ok()
}

fn write(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, text).unwrap();
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn parse(o: &Output) -> Value {
    json::parse(&stdout(o)).unwrap_or_else(|e| panic!("bad json: {e}\n{}", stdout(o)))
}

fn findings(v: &Value) -> Vec<(String, String)> {
    v.get("findings")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|f| {
            (
                f.get("rule").and_then(Value::as_str).unwrap().to_string(),
                f.get("path").and_then(Value::as_str).unwrap().to_string(),
            )
        })
        .collect()
}

fn fixture() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    write(
        r,
        "scripts/deploy.sh",
        "#!/bin/sh\nbranch=$(sed 's#ref: refs/heads/##' .git/HEAD)\n[ \"${#sha}\" -eq 40 ] || exit 1\n",
    );
    write(
        r,
        "hooks/pre-receive",
        "#!/bin/sh\nzero=0000000000000000000000000000000000000000\nwhile read old new ref; do :; done\n",
    );
    write(
        r,
        "test/helper.js",
        "execFileSync('git', ['init'], { cwd })\nexpect(branch).toBe('master')\n",
    );
    write(r, "src/ids.py", "SHA = re.compile(r'^[0-9a-f]{40}$')\n");
    write(
        r,
        ".github/workflows/ci.yml",
        "- run: make NO_RUST=YesPlease\n",
    );
    write(
        r,
        "notes/data.bin.txt",
        "cat .git/packed-refs # git3ready:ignore\n",
    );
    // An unknown extension is never read, even if it mentions .git/HEAD.
    write(r, "assets/logo.svg", "<svg>.git/HEAD</svg>\n");
    // Extensionless without a shebang is not a script.
    write(r, "LICENSE", "git whatchanged\n");
    d
}

#[test]
fn scan_reports_each_kind_with_locations() {
    let d = fixture();
    let out = bin()
        .args(["scan", "--json"])
        .arg(d.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let v = parse(&out);
    let got = findings(&v);
    for (rule, path) in [
        ("head-file-read", "scripts/deploy.sh"),
        ("oid-fixed-width", "scripts/deploy.sh"),
        ("sha1-constant-oid", "hooks/pre-receive"),
        ("master-after-init", "test/helper.js"),
        ("hex40-pattern", "src/ids.py"),
        ("git-source-build", ".github/workflows/ci.yml"),
    ] {
        assert!(
            got.contains(&(rule.to_string(), path.to_string())),
            "missing {rule} in {path}: {got:?}"
        );
    }
    assert!(!got
        .iter()
        .any(|(_, p)| p == "assets/logo.svg" || p == "LICENSE"));
    let summary = v.get("summary").unwrap();
    assert_eq!(
        summary.get("suppressed"),
        Some(&Value::Number(1.0)),
        "{summary:?}"
    );
    assert_eq!(
        v.get("source")
            .and_then(|s| s.get("commit"))
            .and_then(Value::as_str),
        Some("53d995c53fb100920464c0709389f4fa55c6f215")
    );
}

#[test]
fn text_report_is_plain_when_not_a_tty() {
    let d = fixture();
    let out = bin().arg("scan").arg(d.path()).output().unwrap();
    let text = stdout(&out);
    assert!(text.contains("BREAK  head-file-read"));
    assert!(text.contains("scripts/deploy.sh:2:"));
    assert!(text.contains("(git init at line 1 does not choose a branch)"));
    assert!(text.contains("Git 3.0 has no planned release date."));
    assert!(!text.contains('\x1b'));
}

#[test]
fn fail_on_moves_the_threshold() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "Dockerfile", "RUN make WITH_RUST=YesPlease\n");
    let run = |extra: &[&str]| {
        bin()
            .arg("scan")
            .args(extra)
            .arg(d.path())
            .output()
            .unwrap()
            .status
            .code()
    };
    assert_eq!(run(&[]), Some(0));
    assert_eq!(run(&["--fail-on", "risk"]), Some(0));
    assert_eq!(run(&["--fail-on", "info"]), Some(1));
    assert_eq!(run(&["--fail-on", "fatal"]), Some(2));
}

#[test]
fn only_skip_exclude_and_ignore_file() {
    let d = fixture();
    let only = bin()
        .args(["scan", "--json", "--only", "hex40-pattern"])
        .arg(d.path())
        .output()
        .unwrap();
    let got = findings(&parse(&only));
    assert_eq!(got, vec![("hex40-pattern".into(), "src/ids.py".into())]);

    let skip = bin()
        .args([
            "scan",
            "--json",
            "--skip",
            "hex40-pattern",
            "--exclude",
            "scripts/",
        ])
        .arg(d.path())
        .output()
        .unwrap();
    let got = findings(&parse(&skip));
    assert!(!got
        .iter()
        .any(|(r, p)| r == "hex40-pattern" || p.starts_with("scripts/")));

    write(d.path(), ".git3readyignore", "hooks/\n");
    let ignored = bin()
        .args(["scan", "--json"])
        .arg(d.path())
        .output()
        .unwrap();
    assert!(!findings(&parse(&ignored))
        .iter()
        .any(|(_, p)| p.starts_with("hooks/")));

    let bad = bin()
        .args(["scan", "--only", "no-such-rule"])
        .arg(d.path())
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn embedded_bare_repository_is_found() {
    if !have_git() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    fs::create_dir_all(d.path().join("fixtures")).unwrap();
    assert!(git(
        &d.path().join("fixtures"),
        &["init", "-q", "--bare", "remote.git"]
    )
    .status
    .success());
    // A worktree's .git directory is not reported: Git 3.0 still finds those.
    assert!(git(d.path(), &["init", "-q", "work"]).status.success());
    let out = bin()
        .args(["scan", "--json"])
        .arg(d.path())
        .output()
        .unwrap();
    let got = findings(&parse(&out));
    assert!(
        got.contains(&("embedded-bare-repo".into(), "fixtures/remote.git/".into())),
        "{got:?}"
    );
    assert_eq!(
        got.iter()
            .filter(|(r, _)| r == "embedded-bare-repo")
            .count(),
        1
    );
}

#[test]
fn not_a_directory_is_a_usage_error() {
    let out = bin()
        .args(["scan", "/definitely/not/here"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a directory"));
}

#[test]
fn rules_listing() {
    let out = bin().args(["rules", "--json"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v = parse(&out);
    assert_eq!(
        v.get("rules").and_then(Value::as_array).map(<[Value]>::len),
        Some(git3ready::RULES.len())
    );
    let text = stdout(&bin().arg("rules").output().unwrap());
    assert!(text.contains("safe-bare-repository"));
}

#[test]
fn rehearse_switches_on_the_new_defaults() {
    if !git_at_least(2, 47) {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let out = bin()
        .current_dir(d.path())
        .args(["rehearse", "-q", "--", "git", "init", "-q", "r"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_DEFAULT_HASH", "sha1")
        .env_remove("GIT_CONFIG_COUNT")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let r = d.path().join("r");
    assert_eq!(
        stdout(&git(&r, &["rev-parse", "--show-object-format"])).trim(),
        "sha256"
    );
    assert_eq!(
        stdout(&git(&r, &["rev-parse", "--show-ref-format"])).trim(),
        "reftable"
    );
    assert_eq!(
        stdout(&git(&r, &["symbolic-ref", "HEAD"])).trim(),
        "refs/heads/main"
    );
}

#[test]
fn rehearse_refuses_implicit_bare_discovery() {
    if !git_at_least(2, 47) {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    assert!(git(d.path(), &["init", "-q", "--bare", "b.git"])
        .status
        .success());
    let run = |extra: &[&str]| {
        bin()
            .current_dir(d.path())
            .arg("rehearse")
            .arg("-q")
            .args(extra)
            .args(["--", "sh", "-c", "cd b.git && git rev-parse --git-dir"])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove("GIT_CONFIG_COUNT")
            .output()
            .unwrap()
    };
    let refused = run(&[]);
    assert_ne!(refused.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("cannot use bare repository"));
    assert_eq!(
        run(&["--without", "safe-bare-repository"]).status.code(),
        Some(0)
    );
}

#[test]
fn rehearse_passes_exit_status_through() {
    if !git_at_least(2, 47) {
        return;
    }
    let three = bin()
        .args(["rehearse", "-q", "--", "sh", "-c", "exit 3"])
        .output()
        .unwrap();
    assert_eq!(three.status.code(), Some(3));
    let missing = bin()
        .args(["rehearse", "-q", "--", "git3ready-no-such-program"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(127));
    let nothing = bin().args(["rehearse"]).output().unwrap();
    assert_eq!(nothing.status.code(), Some(2));
}

#[test]
fn rehearse_print_formats() {
    if !git_at_least(2, 47) {
        return;
    }
    let sh = bin()
        .args(["rehearse", "--print", "sh"])
        .env_remove("GIT_CONFIG_COUNT")
        .env("GIT_DEFAULT_REF_FORMAT", "files")
        .output()
        .unwrap();
    let text = stdout(&sh);
    assert!(text.starts_with("unset GIT_DEFAULT_REF_FORMAT\n"), "{text}");
    assert!(text.contains("export GIT_CONFIG_COUNT='4'"));
    let env = bin()
        .args(["rehearse", "--print", "env", "--without", "default-branch"])
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_DEFAULT_REF_FORMAT")
        .env_remove("GIT_DEFAULT_HASH")
        .output()
        .unwrap();
    let text = stdout(&env);
    assert!(text.starts_with("GIT_CONFIG_COUNT=3\n"), "{text}");
    assert!(!text.contains("init.defaultBranch"));
}

#[test]
fn env_reports_removed_settings() {
    if !have_git() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let global = d.path().join("gitconfig");
    fs::write(
        &global,
        "[init]\n\tdefaultBranch = main\n[core]\n\tcommentChar = auto\n",
    )
    .unwrap();
    let out = bin()
        .current_dir(d.path())
        .args(["env", "--json"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", &global)
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_DIR")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let v = parse(&out);
    let checks = v.get("checks").and_then(Value::as_array).unwrap();
    let status = |subject: &str| {
        checks
            .iter()
            .find(|c| c.get("subject").and_then(Value::as_str) == Some(subject))
            .and_then(|c| c.get("status"))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    assert_eq!(status("core.commentChar").as_deref(), Some("break"));
    assert_eq!(status("init.defaultBranch").as_deref(), Some("ok"));
}

#[test]
fn env_reads_the_renamed_ref_format_key_only_where_git_does() {
    if !have_git() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let global = d.path().join("gitconfig");
    fs::write(&global, "[init]\n\tdefaultRefStorageFormat = files\n").unwrap();
    let out = bin()
        .current_dir(d.path())
        .args(["env", "--json"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", &global)
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_DEFAULT_REF_FORMAT")
        .env_remove("GIT_DEFAULT_REF_STORAGE_FORMAT")
        .env_remove("GIT_DIR")
        .output()
        .unwrap();
    let v = parse(&out);
    let check = v
        .get("checks")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|c| c.get("subject").and_then(Value::as_str) == Some("init.defaultRefFormat"))
        .unwrap();
    let status = check.get("status").and_then(Value::as_str).unwrap();
    let detail = check.get("detail").and_then(Value::as_str).unwrap();
    assert!(
        detail.starts_with("init.defaultRefStorageFormat "),
        "{detail}"
    );
    // No release up to 2.56 reads the new name (git/git setup.c at v2.56.1).
    if git_at_least(2, 57) {
        assert_eq!(status, "ok", "{detail}");
    } else {
        assert_eq!(status, "info", "{detail}");
        assert!(detail.contains("does not read that name"), "{detail}");
    }
}

fn git_at_least(major: u32, minor: u32) -> bool {
    let Ok(out) = Command::new("git").arg("version").output() else {
        return false;
    };
    git3ready::rehearse::parse_git_version(&String::from_utf8_lossy(&out.stdout))
        .is_some_and(|v| v >= (major, minor))
}

#[test]
fn env_ignores_repository_local_init_defaults_and_fails_on_bad_config() {
    if !git_at_least(2, 47) {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    assert!(git(d.path(), &["init", "-q", "p"]).status.success());
    let p = d.path().join("p");
    assert!(git(&p, &["config", "init.defaultBranch", "foo"])
        .status
        .success());
    let run = |extra_env: &[(&str, &str)]| {
        let mut c = bin();
        c.current_dir(&p)
            .args(["env", "--json"])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove("GIT_CONFIG_COUNT")
            .env_remove("GIT_CONFIG")
            .env_remove("GIT_DIR");
        for (k, v) in extra_env {
            c.env(k, v);
        }
        c.output().unwrap()
    };
    let ok = run(&[]);
    let v = parse(&ok);
    let branch = v
        .get("checks")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|c| c.get("subject").and_then(Value::as_str) == Some("init.defaultBranch"))
        .and_then(|c| c.get("status"))
        .and_then(Value::as_str)
        .map(str::to_string);
    assert_eq!(branch.as_deref(), Some("risk"), "{}", stdout(&ok));

    let bad = run(&[("GIT_CONFIG_COUNT", "not-a-count")]);
    assert_eq!(bad.status.code(), Some(2), "{}", stdout(&bad));
}

#[test]
fn scan_reads_non_utf8_scripts() {
    let d = tempfile::tempdir().unwrap();
    fs::write(
        d.path().join("latin1.sh"),
        b"# caf\xe9\ncat .git/HEAD\n".as_slice(),
    )
    .unwrap();
    let out = bin()
        .args(["scan", "--json"])
        .arg(d.path())
        .output()
        .unwrap();
    let v = parse(&out);
    assert!(findings(&v).contains(&("head-file-read".into(), "latin1.sh".into())));
    assert_eq!(
        v.get("summary").and_then(|s| s.get("lossy_utf8")),
        Some(&Value::Number(1.0))
    );
}

#[cfg(unix)]
#[test]
fn unreadable_files_make_the_scan_incomplete() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("secret.sh");
    fs::write(&p, "echo hi\n").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
    // Root reads anything; the check is meaningless there.
    if fs::read(&p).is_ok() {
        return;
    }
    let out = bin().arg("scan").arg(d.path()).output().unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
    assert!(stdout(&out).contains("secret.sh"));
}

#[test]
fn print_env_refuses_an_overriding_variable() {
    if !git_at_least(2, 47) {
        return;
    }
    let out = bin()
        .args(["rehearse", "--print", "env"])
        .env_remove("GIT_CONFIG_COUNT")
        .env("GIT_DEFAULT_HASH", "sha1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(stdout(&out).is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("GIT_DEFAULT_HASH"));
}

#[cfg(unix)]
#[test]
fn rehearse_passes_non_utf8_arguments() {
    use std::os::unix::ffi::OsStrExt;
    let arg = std::ffi::OsStr::from_bytes(b"x\xff");
    let out = bin()
        .args([
            "rehearse",
            "-q",
            "--without",
            "object-format",
            "--without",
            "ref-format",
            "--",
            "printf",
            "%s",
        ])
        .arg(arg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, b"x\xff");
}

#[test]
fn env_fails_when_config_or_git_dir_cannot_be_read() {
    if !have_git() {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let run = |envs: &[(&str, &std::ffi::OsStr)]| {
        let mut c = bin();
        c.current_dir(d.path())
            .arg("env")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_CONFIG_COUNT")
            .env_remove("GIT_DIR");
        for (k, v) in envs {
            c.env(k, v);
        }
        c.output().unwrap()
    };
    // A global config path that is a directory: Git warns and exits 1.
    let dir_as_config = run(&[("GIT_CONFIG_GLOBAL", d.path().as_os_str())]);
    assert_eq!(dir_as_config.status.code(), Some(2), "{dir_as_config:?}");
    // Same, when the key is found elsewhere and Git exits 0 with the warning.
    let mut c = bin();
    let found_anyway = c
        .current_dir(d.path())
        .arg("env")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", d.path())
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "init.defaultBranch")
        .env("GIT_CONFIG_VALUE_0", "main")
        .env_remove("GIT_DIR")
        .output()
        .unwrap();
    assert_eq!(found_anyway.status.code(), Some(2), "{found_anyway:?}");
    // GIT_DIR pointing nowhere is an error, not "no repository".
    let missing = d.path().join("nope");
    let bad_git_dir = run(&[
        ("GIT_CONFIG_GLOBAL", std::ffi::OsStr::new("/dev/null")),
        ("GIT_DIR", missing.as_os_str()),
    ]);
    assert_eq!(bad_git_dir.status.code(), Some(2), "{bad_git_dir:?}");
    assert!(String::from_utf8_lossy(&bad_git_dir.stderr).contains("GIT_DIR"));
}
