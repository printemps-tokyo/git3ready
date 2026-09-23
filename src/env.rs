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
    pub comment_char: Option<Setting>,
    pub comment_string: Option<Setting>,
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

fn run_git(cwd: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

fn config(cwd: &Path, key: &str, as_bool: bool) -> Option<Setting> {
    let mut args = vec!["config", "--show-scope"];
    if as_bool {
        args.push("--type=bool");
    }
    args.extend(["--get", key]);
    let line = run_git(cwd, &args)?;
    let (scope, value) = line.split_once('\t')?;
    Some(Setting {
        scope: scope.to_string(),
        value: value.to_string(),
    })
}

/// Only config Git treats as protected (system, global, command line) counts
/// for safe.bareRepository; a repository cannot vouch for itself. The last
/// protected value wins, so every value is read and local ones are dropped.
fn protected_config(cwd: &Path, key: &str) -> Option<Setting> {
    let all = run_git(cwd, &["config", "--show-scope", "--get-all", key])?;
    all.lines()
        .filter_map(|l| l.split_once('\t'))
        .rfind(|(scope, _)| !matches!(*scope, "local" | "worktree"))
        .map(|(scope, value)| Setting {
            scope: scope.to_string(),
            value: value.to_string(),
        })
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Collect [`Facts`] by running Git in `cwd`.
pub fn gather(cwd: &Path) -> Facts {
    let repo = run_git(cwd, &["rev-parse", "--git-common-dir"]).map(|common| {
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
    Facts {
        git_version: run_git(cwd, &["version"]),
        default_branch: config(cwd, "init.defaultBranch", false),
        default_object_format: config(cwd, "init.defaultObjectFormat", false),
        default_ref_format: config(cwd, "init.defaultRefFormat", false),
        env_default_hash: env_nonempty("GIT_DEFAULT_HASH"),
        env_default_ref_format: env_nonempty("GIT_DEFAULT_REF_FORMAT"),
        env_git_dir: env_nonempty("GIT_DIR").is_some(),
        env_graft_file: env_nonempty("GIT_GRAFT_FILE"),
        safe_bare_repository: protected_config(cwd, "safe.bareRepository"),
        comment_char: config(cwd, "core.commentChar", false),
        comment_string: config(cwd, "core.commentString", false),
        prefer_symlink_refs: config(cwd, "core.preferSymlinkRefs", true),
        repo,
    }
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
        Some(s) => Check {
            subject: "safe.bareRepository",
            status: None,
            detail: format!(
                "{}; implicit bare-repository discovery keeps working after Git 3.0",
                pinned(s)
            ),
            fix: None,
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

    for (subject, setting) in [
        ("core.commentChar", &f.comment_char),
        ("core.commentString", &f.comment_string),
    ] {
        if let Some(s) = setting {
            if s.value.eq_ignore_ascii_case("auto") {
                out.push(Check {
                    subject,
                    status: Some(Severity::Break),
                    detail: format!("{}; the auto value is removed in Git 3.0", pinned(s)),
                    fix: Some(format!("git config --{} {subject} ';'", scope_flag(s))),
                });
            }
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
                fix: Some(format!(
                    "git config --{} --unset core.preferSymlinkRefs",
                    scope_flag(s)
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

fn scope_flag(s: &Setting) -> &str {
    match s.scope.as_str() {
        "global" => "global",
        "system" => "system",
        "worktree" => "worktree",
        _ => "local",
    }
}

fn format_default(
    subject: &'static str,
    env: Option<(&str, &str)>,
    setting: Option<&Setting>,
    today: &str,
    git3: &str,
) -> Check {
    if let Some((var, v)) = env {
        return Check {
            subject,
            status: None,
            detail: format!("{var}={v} in the environment overrides the default"),
            fix: None,
        };
    }
    match setting {
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
            comment_char: set("local", "auto"),
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
