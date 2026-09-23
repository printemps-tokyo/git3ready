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
        Some("985b38ca6cdbd04432a7072c790f8ddf9dcc717c")
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
    if !have_git() {
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
    if !have_git() {
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
