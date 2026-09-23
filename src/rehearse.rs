//! `git3ready rehearse`: run a command with the Git 3.0 defaults switched on.
//!
//! Git reads extra configuration from `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`
//! and `GIT_CONFIG_VALUE_<n>` (see git-config(1), ENVIRONMENT). Every Git the
//! command spawns -- test suites, build scripts, hooks -- inherits them, so a
//! `git init` deep inside a test creates a sha256, reftable repository on
//! `main`, and a bare repository reached by `cd` is refused, exactly as the new
//! defaults will do.
//!
//! What it cannot rehearse: removed commands still exist in the installed Git,
//! a clone keeps the format of its remote, and an explicit `git -c`, an
//! explicit option (`git init -b`, `--object-format`) or a test that clears
//! the environment opts out. Config files do not: `GIT_CONFIG_COUNT` pairs
//! override them. The README says so.

use std::fmt::Write as _;

/// One Git 3.0 default that can be switched on through configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aspect {
    /// Name accepted by `--without`.
    pub name: &'static str,
    pub key: &'static str,
    pub value: &'static str,
    /// Environment variables that would override `key` and must be cleared.
    pub overriding_env: &'static [&'static str],
    /// The first Git release that reads `key` from configuration, when that
    /// is recent enough to matter.
    pub since: Option<(u32, u32)>,
}

/// Git 2.47.0's release notes: "The default object hash and ref backend
/// format used to be settable only with explicit command line option to
/// \"git init\" and environment variables, but now they can be configured".
const CONFIG_DEFAULT_FORMATS: (u32, u32) = (2, 47);

/// The switchable Git 3.0 defaults, in the order they are appended.
pub const ASPECTS: &[Aspect] = &[
    Aspect {
        name: "object-format",
        key: "init.defaultObjectFormat",
        value: "sha256",
        overriding_env: &["GIT_DEFAULT_HASH"],
        since: Some(CONFIG_DEFAULT_FORMATS),
    },
    Aspect {
        name: "ref-format",
        key: "init.defaultRefFormat",
        value: "reftable",
        overriding_env: &["GIT_DEFAULT_REF_FORMAT"],
        since: Some(CONFIG_DEFAULT_FORMATS),
    },
    Aspect {
        name: "default-branch",
        key: "init.defaultBranch",
        value: "main",
        overriding_env: &[],
        since: None,
    },
    Aspect {
        name: "safe-bare-repository",
        key: "safe.bareRepository",
        value: "explicit",
        overriding_env: &[],
        since: None,
    },
];

/// The environment changes a rehearsal makes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Variables to set, in order.
    pub set: Vec<(String, String)>,
    /// Variables to remove from the child's environment.
    pub unset: Vec<String>,
    /// The aspects in effect, for the banner.
    pub aspects: Vec<&'static Aspect>,
}

/// Validate `--without` names.
pub fn select(without: &[String]) -> Result<Vec<&'static Aspect>, String> {
    for w in without {
        if !ASPECTS.iter().any(|a| a.name == w) {
            let names: Vec<&str> = ASPECTS.iter().map(|a| a.name).collect();
            return Err(format!(
                "unknown aspect '{w}' for --without (expected one of: {})",
                names.join(", ")
            ));
        }
    }
    let chosen: Vec<&'static Aspect> = ASPECTS
        .iter()
        .filter(|a| !without.iter().any(|w| w == a.name))
        .collect();
    if chosen.is_empty() {
        return Err("--without removed every aspect; nothing to rehearse".into());
    }
    Ok(chosen)
}

/// Build the plan on top of whatever `GIT_CONFIG_COUNT` pairs already exist.
///
/// Existing pairs are kept and ours are appended after them, so for these
/// single-valued keys ours win. `get` reads the current environment.
pub fn plan(
    aspects: Vec<&'static Aspect>,
    get: impl Fn(&str) -> Option<String>,
) -> Result<Plan, String> {
    // Git treats an empty count as zero and rejects anything that is not a
    // plain number ("bogus count in GIT_CONFIG_COUNT"), surrounding spaces
    // included, so this does not trim either.
    let existing = match get("GIT_CONFIG_COUNT") {
        None => 0,
        Some(v) if v.is_empty() => 0,
        Some(v) => v
            .parse::<u32>()
            .map_err(|_| format!("GIT_CONFIG_COUNT is set to '{v}', which is not a count"))?,
    };
    let total = u32::try_from(aspects.len())
        .ok()
        .and_then(|n| existing.checked_add(n))
        .ok_or_else(|| format!("GIT_CONFIG_COUNT={existing} leaves no room for more pairs"))?;
    let mut set = vec![("GIT_CONFIG_COUNT".to_string(), total.to_string())];
    for (i, a) in aspects.iter().enumerate() {
        let n = existing as usize + i;
        set.push((format!("GIT_CONFIG_KEY_{n}"), a.key.to_string()));
        set.push((format!("GIT_CONFIG_VALUE_{n}"), a.value.to_string()));
    }
    let unset = aspects
        .iter()
        .flat_map(|a| a.overriding_env.iter())
        .filter(|v| get(v).is_some())
        .map(|v| v.to_string())
        .collect();
    Ok(Plan {
        set,
        unset,
        aspects,
    })
}

/// `(major, minor)` from `git version` output such as "git version 2.52.0"
/// or "git version 2.39.5 (Apple Git-154)".
pub fn parse_git_version(s: &str) -> Option<(u32, u32)> {
    let v = s.trim().strip_prefix("git version ")?;
    let mut parts = v.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Why the installed Git cannot rehearse some of `aspects`, if it cannot.
pub fn version_problem(aspects: &[&'static Aspect], version: (u32, u32)) -> Option<String> {
    let too_new: Vec<&Aspect> = aspects
        .iter()
        .copied()
        .filter(|a| a.since.is_some_and(|since| version < since))
        .collect();
    let first = too_new.first()?;
    let (maj, min) = first.since.unwrap_or_default();
    let keys: Vec<&str> = too_new.iter().map(|a| a.key).collect();
    let names: Vec<String> = too_new
        .iter()
        .map(|a| format!("--without {}", a.name))
        .collect();
    Some(format!(
        "Git {}.{} does not read {} from configuration (added in Git {maj}.{min}), so the rehearsal would silently keep today's default; upgrade Git or pass {}",
        version.0,
        version.1,
        keys.join(" / "),
        names.join(" ")
    ))
}

/// Output formats for `--print`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintFormat {
    /// `export KEY='VALUE'` lines plus `unset`, for `eval` in a shell.
    Sh,
    /// `KEY=VALUE` lines, for `$GITHUB_ENV` and dotenv files.
    Env,
}

impl PrintFormat {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "sh" => Ok(PrintFormat::Sh),
            "env" => Ok(PrintFormat::Env),
            _ => Err(format!("unknown --print format '{s}' (expected sh or env)")),
        }
    }
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Render the plan for `--print`.
pub fn render(plan: &Plan, format: PrintFormat) -> String {
    let mut out = String::new();
    match format {
        PrintFormat::Sh => {
            if !plan.unset.is_empty() {
                let _ = writeln!(out, "unset {}", plan.unset.join(" "));
            }
            for (k, v) in &plan.set {
                let _ = writeln!(out, "export {k}={}", sh_quote(v));
            }
        }
        PrintFormat::Env => {
            for (k, v) in &plan.set {
                let _ = writeln!(out, "{k}={v}");
            }
        }
    }
    out
}

/// One line for stderr describing what is in effect.
pub fn banner(plan: &Plan) -> String {
    let pairs: Vec<String> = plan
        .aspects
        .iter()
        .map(|a| format!("{}={}", a.key, a.value))
        .collect();
    let mut s = format!(
        "git3ready: rehearsing Git 3.0 defaults: {}",
        pairs.join(" ")
    );
    if !plan.unset.is_empty() {
        let _ = write!(s, " (cleared {})", plan.unset.join(", "));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(pk, _)| *pk == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn plan_on_a_clean_environment() {
        let p = plan(select(&[]).unwrap(), env(&[])).unwrap();
        assert_eq!(p.set[0], ("GIT_CONFIG_COUNT".into(), "4".into()));
        assert_eq!(
            p.set[1],
            ("GIT_CONFIG_KEY_0".into(), "init.defaultObjectFormat".into())
        );
        assert_eq!(p.set[2], ("GIT_CONFIG_VALUE_0".into(), "sha256".into()));
        assert_eq!(p.set[8], ("GIT_CONFIG_VALUE_3".into(), "explicit".into()));
        assert!(p.unset.is_empty());
    }

    #[test]
    fn plan_appends_after_existing_pairs_and_clears_overrides() {
        let p = plan(
            select(&[]).unwrap(),
            env(&[("GIT_CONFIG_COUNT", "2"), ("GIT_DEFAULT_HASH", "sha1")]),
        )
        .unwrap();
        assert_eq!(p.set[0], ("GIT_CONFIG_COUNT".into(), "6".into()));
        assert_eq!(
            p.set[1],
            ("GIT_CONFIG_KEY_2".into(), "init.defaultObjectFormat".into())
        );
        assert_eq!(p.unset, vec!["GIT_DEFAULT_HASH".to_string()]);
        assert!(banner(&p).contains("cleared GIT_DEFAULT_HASH"));
    }

    #[test]
    fn empty_count_is_zero_and_garbage_is_an_error() {
        let p = plan(select(&[]).unwrap(), env(&[("GIT_CONFIG_COUNT", "")])).unwrap();
        assert_eq!(p.set[0].1, "4");
        assert!(plan(select(&[]).unwrap(), env(&[("GIT_CONFIG_COUNT", "x")])).is_err());
    }

    #[test]
    fn without_filters_and_validates() {
        let chosen = select(&["safe-bare-repository".into()]).unwrap();
        assert_eq!(chosen.len(), 3);
        assert!(select(&["nope".into()]).is_err());
        let all: Vec<String> = ASPECTS.iter().map(|a| a.name.to_string()).collect();
        assert!(select(&all).is_err());
    }

    #[test]
    fn count_is_parsed_like_git_does() {
        assert!(plan(select(&[]).unwrap(), env(&[("GIT_CONFIG_COUNT", " 2 ")])).is_err());
        assert!(plan(
            select(&[]).unwrap(),
            env(&[("GIT_CONFIG_COUNT", "18446744073709551615")])
        )
        .is_err());
        assert!(plan(
            select(&[]).unwrap(),
            env(&[("GIT_CONFIG_COUNT", "4294967294")])
        )
        .is_err());
    }

    #[test]
    fn versions() {
        assert_eq!(parse_git_version("git version 2.52.0"), Some((2, 52)));
        assert_eq!(
            parse_git_version("git version 2.39.5 (Apple Git-154)"),
            Some((2, 39))
        );
        assert_eq!(parse_git_version("nope"), None);
        let all = select(&[]).unwrap();
        assert!(version_problem(&all, (2, 47)).is_none());
        let msg = version_problem(&all, (2, 46)).unwrap();
        assert!(msg.contains("--without object-format --without ref-format"));
        let rest = select(&["object-format".into(), "ref-format".into()]).unwrap();
        assert!(version_problem(&rest, (2, 40)).is_none());
    }

    #[test]
    fn print_formats() {
        let p = plan(select(&[]).unwrap(), env(&[("GIT_DEFAULT_HASH", "sha1")])).unwrap();
        let sh = render(&p, PrintFormat::Sh);
        assert!(sh.starts_with("unset GIT_DEFAULT_HASH\n"));
        assert!(sh.contains("export GIT_CONFIG_KEY_0='init.defaultObjectFormat'\n"));
        let envf = render(&p, PrintFormat::Env);
        assert!(envf.starts_with("GIT_CONFIG_COUNT=4\n"));
        assert!(!envf.contains("unset"));
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
    }
}
