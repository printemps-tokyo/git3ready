//! `git3ready env`: how the installed Git and the current repository will
//! behave once the Git 3.0 defaults apply.
//!
//! Gathering ([`gather`]) runs `git config` and `git rev-parse`; evaluating
//! ([`evaluate`]) is pure, so every verdict is testable from a hand-built
//! [`Facts`].

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::json::quote;
use crate::report::RenderOptions;
use crate::rules::Severity;

/// A config value together with the scope Git reports for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    pub scope: String,
    pub value: String,
}

/// What `git3ready env` knows about the current repository.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepoFacts {
    pub common_dir: PathBuf,
    pub object_format: Option<String>,
    pub ref_format: Option<String>,
    pub is_bare: bool,
    pub has_grafts: bool,
    pub legacy_remote_dirs: Vec<String>,
}

/// Everything [`evaluate`] looks at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    pub git_version: Option<String>,
    pub default_branch: Option<Setting>,
    pub default_object_format: Option<Setting>,
    pub default_ref_format: Option<Setting>,
    pub env_default_hash: Option<String>,
    pub env_default_ref_format: Option<String>,
    pub env_git_dir: bool,
    pub env_graft_file: Option<String>,
    pub safe_bare_repository: Option<Setting>,
    /// The effective comment setting: which of the two names set it last.
    pub comment: Option<(String, Setting)>,
    pub prefer_symlink_refs: Option<Setting>,
    pub repo: Option<RepoFacts>,
}

/// One verdict. `status: None` means "fine as it is".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub subject: &'static str,
    pub status: Option<Severity>,
    pub detail: String,
    pub fix: Option<String>,
}

/// The first Git with `git config --show-scope`.
const SHOW_SCOPE_SINCE: (u32, u32) = (2, 26);

/// `git <args>` in `cwd`, isolated from `GIT_CONFIG`, which would point
/// `git config` at one file instead of the configuration Git really uses.
fn git(cwd: &Path, args: &[&str]) -> Result<std::process::Output, String> {
    Command::new("git")
        .current_dir(cwd)
        .args(args)
        .env_remove("GIT_CONFIG")
        .output()
        .map_err(|e| format!("cannot run git: {e}"))
}

/// Stdout of a command that is allowed to fail (rev-parse outside a repo).
fn run_git(cwd: &Path, args: &[&str]) -> Option<String> {
    let out = git(cwd, args).ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

/// Every value of `key`, in the order Git reads them.
///
/// `git config --get-all` exits 1 when the key is unset, which is an empty
/// list here -- unless Git also printed something, which is how it reports a
/// config file it could not read ("warning: unable to access ...") while
/// still exiting 1. That, and any other failure -- a malformed file, a bad
/// `GIT_CONFIG_COUNT`, a value that is not a boolean -- is an error: the
/// check cannot be made, and saying "unset" would be wrong.
fn config_all(cwd: &Path, key: &str, as_bool: bool) -> Result<Vec<Setting>, String> {
    let mut args = vec!["config", "--show-scope"];
    if as_bool {
        args.push("--type=bool");
    }
    args.extend(["--get-all", key]);
    let out = git(cwd, &args)?;
    match out.status.code() {
        Some(0) => Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .map(|(scope, value)| Setting {
                scope: scope.to_string(),
                value: value.to_string(),
            })
            .collect()),
        Some(1) if out.stderr.is_empty() => Ok(Vec::new()),
        _ => Err(format!(
            "git config {key} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
    }
}

/// The value that applies to new repositories and to repository discovery.
///
/// `git init` and the `safe.*` checks ignore a repository's own config
/// (`repository_format_configure()` and the protected-config rule in git/git
/// `setup.c`), so local and worktree values are dropped and the last
/// remaining value wins.
fn user_config(cwd: &Path, key: &str) -> Result<Option<Setting>, String> {
    Ok(config_all(cwd, key, false)?
        .into_iter()
        .rfind(|s| !matches!(s.scope.as_str(), "local" | "worktree")))
}

/// The last value of `key` from any scope: what a command in `cwd` uses.
fn effective_config(cwd: &Path, key: &str, as_bool: bool) -> Result<Option<Setting>, String> {
    Ok(config_all(cwd, key, as_bool)?.pop())
}

/// core.commentChar and core.commentString are one setting under two names;
/// whichever Git reads last wins.
fn comment_config(cwd: &Path) -> Result<Option<(String, Setting)>, String> {
    let out = git(
        cwd,
        &[
            "config",
            "--show-scope",
            "--get-regexp",
            r"^core\.comment(char|string)$",
        ],
    )?;
    match out.status.code() {
        Some(0) => Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| {
                let (scope, rest) = l.split_once('\t')?;
                let (key, value) = rest.split_once(' ').unwrap_or((rest, ""));
                let name = if key.eq_ignore_ascii_case("core.commentstring") {
                    "core.commentString"
                } else {
                    "core.commentChar"
                };
                Some((
                    name.to_string(),
                    Setting {
                        scope: scope.to_string(),
                        value: value.to_string(),
                    },
                ))
            })
            .next_back()),
        Some(1) if out.stderr.is_empty() => Ok(None),
        _ => Err(format!(
            "git config core.commentChar failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
    }
}

/// Collect [`Facts`] by running Git in `cwd`.
///
/// Fails when Git is missing or its configuration cannot be read; a partial
/// answer would report settings as unset that are really unreadable.
pub fn gather(cwd: &Path) -> Result<Facts, String> {
    let git_version = run_git(cwd, &["version"])
        .ok_or_else(|| "git is not installed or not on PATH".to_string())?;
    // `git config --show-scope` arrived in Git 2.26 (its release notes: "git
    // config" learned to show in which "scope" each setting comes from).
    if let Some(v) = crate::rehearse::parse_git_version(&git_version) {
        if v < SHOW_SCOPE_SINCE {
            return Err(format!(
                "git3ready env needs Git {}.{} or later (git config --show-scope); this is {git_version}",
                SHOW_SCOPE_SINCE.0, SHOW_SCOPE_SINCE.1
            ));
        }
    }
    let explicit_git_dir = std::env::var_os("GIT_DIR").is_some_and(|v| !v.is_empty());
    let common = git(cwd, &["rev-parse", "--git-common-dir"])?;
    // Outside a repository rev-parse fails, and that is a normal answer. But
    // when GIT_DIR names the repository explicitly, a failure means it is
    // wrong, and reporting "no repository" would hide that.
    if !common.status.success() && explicit_git_dir {
        return Err(format!(
            "GIT_DIR does not point at a usable repository: {}",
            String::from_utf8_lossy(&common.stderr).trim()
        ));
    }
    let common = common.status.success().then(|| {
        String::from_utf8_lossy(&common.stdout)
            .trim_end()
            .to_string()
    });
    let repo = common.map(|common| {
        let common_dir = {
            let p = PathBuf::from(&common);
            if p.is_absolute() {
                p
            } else {
                cwd.join(p)
            }
        };
        let legacy_remote_dirs = ["branches", "remotes"]
            .into_iter()
            .filter(|d| {
                std::fs::read_dir(common_dir.join(d)).is_ok_and(|mut it| it.next().is_some())
            })
            .map(|d| format!("{d}/"))
            .collect();
        RepoFacts {
            object_format: run_git(cwd, &["rev-parse", "--show-object-format"]),
            ref_format: run_git(cwd, &["rev-parse", "--show-ref-format"]),
            is_bare: run_git(cwd, &["rev-parse", "--is-bare-repository"]).as_deref()
                == Some("true"),
            has_grafts: common_dir.join("info").join("grafts").is_file(),
            legacy_remote_dirs,
            common_dir,
        }
    });
    Ok(Facts {
        git_version: Some(git_version),
        default_branch: user_config(cwd, "init.defaultBranch")?,
        default_object_format: user_config(cwd, "init.defaultObjectFormat")?,
        default_ref_format: user_config(cwd, "init.defaultRefFormat")?,
        env_default_hash: std::env::var("GIT_DEFAULT_HASH").ok(),
        env_default_ref_format: std::env::var("GIT_DEFAULT_REF_FORMAT").ok(),
        env_git_dir: explicit_git_dir,
        env_graft_file: std::env::var("GIT_GRAFT_FILE")
            .ok()
            .filter(|v| !v.is_empty()),
        safe_bare_repository: user_config(cwd, "safe.bareRepository")?,
        comment: comment_config(cwd)?,
        prefer_symlink_refs: effective_config(cwd, "core.preferSymlinkRefs", true)?,
        repo,
    })
}

fn pinned(s: &Setting) -> String {
    format!("set to {} ({} config)", s.value, s.scope)
}

/// Turn [`Facts`] into verdicts, in a fixed order.
pub fn evaluate(f: &Facts) -> Vec<Check> {
    let mut out = Vec::new();

    out.push(match &f.default_branch {
        Some(s) => Check {
            subject: "init.defaultBranch",
            status: None,
            detail: format!("{}; new repositories keep this name", pinned(s)),
            fix: None,
        },
        None => Check {
            subject: "init.defaultBranch",
            status: Some(Severity::Risk),
            detail: "unset: git init names the first branch master today and main under Git 3.0"
                .into(),
            fix: Some(
                "git config --global init.defaultBranch <name>, or pass -b <name> to git init"
                    .into(),
            ),
        },
    });

    out.push(format_default(
        "init.defaultObjectFormat",
        f.env_default_hash
            .as_deref()
            .map(|v| ("GIT_DEFAULT_HASH", v)),
        f.default_object_format.as_ref(),
        "sha1",
        "sha256",
    ));
    out.push(format_default(
        "init.defaultRefFormat",
        f.env_default_ref_format
            .as_deref()
            .map(|v| ("GIT_DEFAULT_REF_FORMAT", v)),
        f.default_ref_format.as_ref(),
        "files",
        "reftable",
    ));

    out.push(match &f.safe_bare_repository {
        Some(s) if s.value == "explicit" => Check {
            subject: "safe.bareRepository",
            status: None,
            detail: format!("{}; already the Git 3.0 behavior", pinned(s)),
            fix: None,
        },
        Some(s) if s.value == "all" => Check {
            subject: "safe.bareRepository",
            status: None,
            detail: format!(
                "{}; implicit bare-repository discovery keeps working after Git 3.0",
                pinned(s)
            ),
            fix: None,
        },
        Some(s) => Check {
            subject: "safe.bareRepository",
            status: Some(Severity::Break),
            detail: format!(
                "{}; Git accepts only all or explicit and fails with \"unable to parse\" when it checks a bare repository",
                pinned(s)
            ),
            fix: Some("Set it to all or explicit".into()),
        },
        None => Check {
            subject: "safe.bareRepository",
            status: Some(Severity::Info),
            detail: "unset: defaults to all today and explicit under Git 3.0 (cd into a bare repository and run git stops working)".into(),
            fix: Some(
                "Use --git-dir / GIT_DIR for bare repositories, or pin the old behavior with git config --global safe.bareRepository all".into(),
            ),
        },
    });

    if let Some((key, s)) = &f.comment {
        // Git compares the value with strcasecmp (environment.c in git/git),
        // so AUTO is auto too.
        if s.value.eq_ignore_ascii_case("auto") {
            out.push(Check {
                subject: if key == "core.commentString" {
                    "core.commentString"
                } else {
                    "core.commentChar"
                },
                status: Some(Severity::Break),
                detail: format!("{}; the auto value is removed in Git 3.0", pinned(s)),
                fix: Some(unset_fix(
                    s,
                    key,
                    &format!("git config --{{scope}} {key} ';'"),
                )),
            });
        }
    }

    if let Some(s) = &f.prefer_symlink_refs {
        if s.value == "true" {
            out.push(Check {
                subject: "core.preferSymlinkRefs",
                status: Some(Severity::Break),
                detail: format!(
                    "{}; writing symrefs as symlinks is removed in Git 3.0",
                    pinned(s)
                ),
                fix: Some(unset_fix(
                    s,
                    "core.preferSymlinkRefs",
                    "git config --{scope} --unset core.preferSymlinkRefs",
                )),
            });
        }
    }

    if let Some(v) = &f.env_graft_file {
        out.push(Check {
            subject: "GIT_GRAFT_FILE",
            status: Some(Severity::Break),
            detail: format!("set to {v}; graft support is removed in Git 3.0"),
            fix: Some("git replace --convert-graft-file, then unset GIT_GRAFT_FILE".into()),
        });
    }

    if let Some(r) = &f.repo {
        out.push(Check {
            subject: "repository",
            status: None,
            detail: format!(
                "{} objects, {} refs{}",
                r.object_format.as_deref().unwrap_or("unknown"),
                r.ref_format.as_deref().unwrap_or("unknown"),
                if r.is_bare { ", bare" } else { "" }
            ),
            fix: None,
        });
        if r.is_bare && !f.env_git_dir {
            let pinned_all = f
                .safe_bare_repository
                .as_ref()
                .is_some_and(|s| s.value == "all");
            if !pinned_all {
                out.push(Check {
                    subject: "bare repository",
                    status: Some(Severity::Risk),
                    detail:
                        "this bare repository was found implicitly; Git 3.0 refuses that by default"
                            .into(),
                    fix: Some("Run Git with --git-dir=<path> or GIT_DIR=<path>".into()),
                });
            }
        }
        if r.has_grafts {
            out.push(Check {
                subject: "info/grafts",
                status: Some(Severity::Break),
                detail: format!(
                    "{} exists; graft support is removed in Git 3.0",
                    r.common_dir.join("info").join("grafts").display()
                ),
                fix: Some("git replace --convert-graft-file".into()),
            });
        }
        if !r.legacy_remote_dirs.is_empty() {
            out.push(Check {
                subject: "legacy remotes",
                status: Some(Severity::Break),
                detail: format!(
                    "{} in {} is not empty; these remote shorthands are removed in Git 3.0",
                    r.legacy_remote_dirs.join(" and "),
                    r.common_dir.display()
                ),
                fix: Some("Recreate each remote with git remote add <name> <url>".into()),
            });
        }
    }

    out
}

/// A fix for a setting, phrased for the scope it came from. `template` has
/// `{scope}` where the `git config` scope flag goes.
fn unset_fix(s: &Setting, key: &str, template: &str) -> String {
    match s.scope.as_str() {
        "global" | "system" | "local" | "worktree" => template.replace("{scope}", &s.scope),
        "command" => format!(
            "It comes from the command line: drop the -c {key}=... option or the GIT_CONFIG_KEY_<n> / GIT_CONFIG_VALUE_<n> pair"
        ),
        other => format!("Change {key} where it is set ({other} scope)"),
    }
}

fn format_default(
    subject: &'static str,
    env: Option<(&str, &str)>,
    setting: Option<&Setting>,
    today: &str,
    git3: &str,
) -> Check {
    // Git matches these names exactly: GIT_DEFAULT_HASH=SHA256 is "fatal:
    // unknown hash algorithm" (observed with Git 2.52.0), and so is empty.
    if let Some((var, v)) = env {
        if v != today && v != git3 {
            return Check {
                subject,
                status: Some(Severity::Break),
                detail: format!("{var}={v:?} is not {today} or {git3}; git init fails with it"),
                fix: Some(format!("unset {var}, or set it to {today} or {git3}")),
            };
        }
    }
    if let Some((var, v)) = env {
        return Check {
            subject,
            status: None,
            detail: format!("{var}={v} in the environment overrides the default"),
            fix: None,
        };
    }
    match setting {
        // An unknown value in config only draws a warning and the built-in
        // default applies (observed with Git 2.52.0), so it pins nothing.
        Some(s) if s.value != today && s.value != git3 => Check {
            subject,
            status: Some(Severity::Risk),
            detail: format!(
                "{}, which Git does not recognize: it warns and uses its default, {today} today and {git3} under Git 3.0",
                pinned(s)
            ),
            fix: Some(format!("git config --{} {subject} {today}", s.scope)),
        },
        Some(s) => Check {
            subject,
            status: None,
            detail: format!("{}; new repositories keep this format", pinned(s)),
            fix: None,
        },
        None => Check {
            subject,
            status: Some(Severity::Info),
            detail: format!("unset: new repositories use {today} today and {git3} under Git 3.0"),
            fix: Some(format!(
                "Rehearse with git3ready rehearse -- <test command>, or pin {today} with git config --global {subject} {today}"
            )),
        },
    }
}

/// Exit status for `env`: 1 when any check is at `fail_on` or worse.
pub fn exit_code(checks: &[Check], fail_on: Severity) -> i32 {
    i32::from(
        checks
            .iter()
            .any(|c| c.status.is_some_and(|s| s >= fail_on)),
    )
}

fn label(status: Option<Severity>, opts: RenderOptions) -> String {
    let (text, code) = match status {
        None => ("OK   ", "1;32"),
        Some(Severity::Break) => ("BREAK", "1;31"),
        Some(Severity::Risk) => ("RISK ", "1;33"),
        Some(Severity::Info) => ("INFO ", "1;36"),
    };
    if opts.color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Human-readable `env` output.
pub fn render_text(facts: &Facts, checks: &[Check], opts: RenderOptions) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "git3ready env  ({})",
        facts.git_version.as_deref().unwrap_or("git not found")
    );
    let _ = writeln!(out);
    let width = checks.iter().map(|c| c.subject.len()).max().unwrap_or(0);
    for c in checks {
        let _ = writeln!(
            out,
            "  {}  {:<width$}  {}",
            label(c.status, opts),
            c.subject,
            c.detail
        );
        if let Some(fix) = &c.fix {
            let _ = writeln!(out, "         {:<width$}  fix: {fix}", "");
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", crate::rules::NO_RELEASE_DATE);
    out
}

/// Machine-readable `env` output.
pub fn render_json(facts: &Facts, checks: &[Check]) -> String {
    let items: Vec<String> = checks
        .iter()
        .map(|c| {
            format!(
                "{{\"subject\":{},\"status\":{},\"detail\":{},\"fix\":{}}}",
                quote(c.subject),
                quote(c.status.map_or("ok", Severity::as_str)),
                quote(&c.detail),
                c.fix.as_deref().map_or("null".into(), quote)
            )
        })
        .collect();
    format!(
        "{{\"tool\":\"git3ready\",\"version\":{},\"git_version\":{},\"checks\":[{}]}}\n",
        quote(env!("CARGO_PKG_VERSION")),
        facts.git_version.as_deref().map_or("null".into(), quote),
        items.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(scope: &str, value: &str) -> Option<Setting> {
        Some(Setting {
            scope: scope.into(),
            value: value.into(),
        })
    }

    fn status_of(checks: &[Check], subject: &str) -> Option<Option<Severity>> {
        checks
            .iter()
            .find(|c| c.subject == subject)
            .map(|c| c.status)
    }

    #[test]
    fn unset_defaults_are_flagged() {
        let checks = evaluate(&Facts::default());
        assert_eq!(
            status_of(&checks, "init.defaultBranch"),
            Some(Some(Severity::Risk))
        );
        assert_eq!(
            status_of(&checks, "init.defaultObjectFormat"),
            Some(Some(Severity::Info))
        );
        assert_eq!(
            status_of(&checks, "init.defaultRefFormat"),
            Some(Some(Severity::Info))
        );
        assert_eq!(
            status_of(&checks, "safe.bareRepository"),
            Some(Some(Severity::Info))
        );
        assert_eq!(exit_code(&checks, Severity::Break), 0);
        assert_eq!(exit_code(&checks, Severity::Risk), 1);
    }

    #[test]
    fn pinned_settings_are_ok() {
        let f = Facts {
            default_branch: set("global", "main"),
            default_object_format: set("global", "sha1"),
            env_default_ref_format: Some("files".into()),
            safe_bare_repository: set("global", "all"),
            ..Default::default()
        };
        let checks = evaluate(&f);
        assert!(checks.iter().all(|c| c.status.is_none()));
        let rf = checks
            .iter()
            .find(|c| c.subject == "init.defaultRefFormat")
            .unwrap();
        assert!(rf.detail.contains("GIT_DEFAULT_REF_FORMAT=files"));
    }

    #[test]
    fn removed_settings_break() {
        let f = Facts {
            default_branch: set("global", "main"),
            comment: Some(("core.commentChar".into(), set("local", "auto").unwrap())),
            prefer_symlink_refs: set("global", "true"),
            env_graft_file: Some("/tmp/g".into()),
            ..Default::default()
        };
        let checks = evaluate(&f);
        assert_eq!(
            status_of(&checks, "core.commentChar"),
            Some(Some(Severity::Break))
        );
        assert_eq!(
            status_of(&checks, "core.preferSymlinkRefs"),
            Some(Some(Severity::Break))
        );
        assert_eq!(
            status_of(&checks, "GIT_GRAFT_FILE"),
            Some(Some(Severity::Break))
        );
        let fix = checks
            .iter()
            .find(|c| c.subject == "core.commentChar")
            .and_then(|c| c.fix.clone())
            .unwrap();
        assert!(fix.starts_with("git config --local"));
        assert_eq!(exit_code(&checks, Severity::Break), 1);
    }

    #[test]
    fn comment_value_is_case_insensitive_and_command_scope_fix_is_worded() {
        let upper = Facts {
            comment: Some(("core.commentChar".into(), set("global", "AUTO").unwrap())),
            ..Default::default()
        };
        assert_eq!(
            status_of(&evaluate(&upper), "core.commentChar"),
            Some(Some(Severity::Break))
        );
        let cmd = Facts {
            comment: Some(("core.commentString".into(), set("command", "auto").unwrap())),
            ..Default::default()
        };
        let checks = evaluate(&cmd);
        let c = checks
            .iter()
            .find(|c| c.subject == "core.commentString")
            .unwrap();
        assert_eq!(c.status, Some(Severity::Break));
        assert!(c.fix.as_deref().unwrap().contains("drop the -c"));
    }

    #[test]
    fn unknown_format_names() {
        let f = Facts {
            env_default_hash: Some("SHA256".into()),
            default_ref_format: set("global", "bogus"),
            ..Default::default()
        };
        let checks = evaluate(&f);
        assert_eq!(
            status_of(&checks, "init.defaultObjectFormat"),
            Some(Some(Severity::Break))
        );
        assert_eq!(
            status_of(&checks, "init.defaultRefFormat"),
            Some(Some(Severity::Risk))
        );
    }

    #[test]
    fn invalid_and_empty_values_break() {
        let f = Facts {
            safe_bare_repository: set("global", "ALL"),
            env_default_hash: Some(String::new()),
            ..Default::default()
        };
        let checks = evaluate(&f);
        assert_eq!(
            status_of(&checks, "safe.bareRepository"),
            Some(Some(Severity::Break))
        );
        assert_eq!(
            status_of(&checks, "init.defaultObjectFormat"),
            Some(Some(Severity::Break))
        );
    }

    #[test]
    fn repository_checks() {
        let f = Facts {
            repo: Some(RepoFacts {
                common_dir: PathBuf::from("/r"),
                object_format: Some("sha1".into()),
                ref_format: Some("files".into()),
                is_bare: true,
                has_grafts: true,
                legacy_remote_dirs: vec!["remotes/".into()],
            }),
            ..Default::default()
        };
        let checks = evaluate(&f);
        assert_eq!(status_of(&checks, "repository"), Some(None));
        assert_eq!(
            status_of(&checks, "bare repository"),
            Some(Some(Severity::Risk))
        );
        assert_eq!(
            status_of(&checks, "info/grafts"),
            Some(Some(Severity::Break))
        );
        assert_eq!(
            status_of(&checks, "legacy remotes"),
            Some(Some(Severity::Break))
        );

        let explicit = Facts {
            env_git_dir: true,
            ..f
        };
        assert_eq!(status_of(&evaluate(&explicit), "bare repository"), None);
    }

    #[test]
    fn json_parses() {
        let f = Facts::default();
        let json = render_json(&f, &evaluate(&f));
        assert!(crate::json::parse(&json).is_ok());
    }
}
