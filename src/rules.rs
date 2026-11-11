//! The rule table: what each check looks for, why it matters under Git 3.0,
//! and what to do instead.
//!
//! Every rule traces back to one item of Git's own list of breaking changes,
//! `Documentation/BreakingChanges.adoc` in git/git, pinned by [`SOURCE_COMMIT`].
//! Behavior claims that go beyond that document (what `.git/HEAD` contains in a
//! reftable repository, which environment variables Git reads) were checked
//! against a real Git 2.52 and are stated in the rule text as observed facts.
//!
//! The matching itself lives in [`crate::matcher`]; this module is data only.

/// The document every rule is derived from.
pub const SOURCE_URL: &str =
    "https://github.com/git/git/blob/53d995c53fb100920464c0709389f4fa55c6f215/Documentation/BreakingChanges.adoc";

/// The git/git commit of [`SOURCE_URL`]: the latest change to that file when
/// the rule table was last reviewed.
pub const SOURCE_COMMIT: &str = "53d995c53fb100920464c0709389f4fa55c6f215";

/// The day the document was read and the rule table reviewed against it.
pub const SOURCE_READ_ON: &str = "2026-11-11";

/// The source document's own words on timing, printed with every report.
pub const NO_RELEASE_DATE: &str = "Git 3.0 has no planned release date.";

/// Printed under every scan report.
pub const CAVEAT: &str = "Git 3.0 has no planned release date. Matching is textual, not semantic.";

/// How sure a finding is to break once the Git 3.0 behavior is in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Needs a human look: breaks for some inputs, or only in some setups.
    Info,
    /// Likely to break, but depends on context the scan cannot see.
    Risk,
    /// Breaks under the new default or because the feature is removed.
    Break,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Break => "break",
            Severity::Risk => "risk",
            Severity::Info => "info",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "break" => Ok(Severity::Break),
            "risk" => Ok(Severity::Risk),
            "info" => Ok(Severity::Info),
            _ => Err(format!(
                "unknown severity '{s}' (expected break, risk or info)"
            )),
        }
    }
}

/// Which Git 3.0 change a rule belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    ObjectFormat,
    RefFormat,
    DefaultBranch,
    SafeBareRepository,
    Removal,
    Build,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::ObjectFormat => "object-format",
            Category::RefFormat => "ref-format",
            Category::DefaultBranch => "default-branch",
            Category::SafeBareRepository => "safe-bare-repository",
            Category::Removal => "removal",
            Category::Build => "build",
        }
    }

    /// The Git 3.0 change, in one line, as the source document states it.
    pub fn change(self) -> &'static str {
        match self {
            Category::ObjectFormat => {
                "New repositories default to the sha256 object format (64-hex object ids)."
            }
            Category::RefFormat => "New repositories default to the reftable ref storage format.",
            Category::DefaultBranch => "New repositories default to a branch named main.",
            Category::SafeBareRepository => {
                "safe.bareRepository defaults to explicit: implicitly discovered bare repositories are refused."
            }
            Category::Removal => "Removed in Git 3.0.",
            Category::Build => {
                "Rust is planned to become a required part of building Git (the document allows deferring this)."
            }
        }
    }
}

/// One check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub id: &'static str,
    pub severity: Severity,
    pub category: Category,
    /// What the matched text assumes, in one line.
    pub title: &'static str,
    /// Why that assumption fails under Git 3.0.
    pub why: &'static str,
    /// What to write instead.
    pub fix: &'static str,
}

/// All rules, in report order within a severity.
pub const RULES: &[Rule] = &[
    // -- object format ------------------------------------------------------
    Rule {
        id: "hex40-pattern",
        severity: Severity::Break,
        category: Category::ObjectFormat,
        title: "Pattern accepts exactly 40 hex digits (a SHA-1 object id)",
        why: "A full object id in a sha256 repository is 64 hex digits, so this pattern rejects every one of them.",
        fix: "Accept both lengths, e.g. [0-9a-f]{40}([0-9a-f]{24})?, or ask Git with git rev-parse --show-object-format.",
    },
    Rule {
        id: "hex40-upper-bound",
        severity: Severity::Risk,
        category: Category::ObjectFormat,
        title: "Pattern caps an object id at 40 hex digits",
        why: "Abbreviated ids still match, but a full 64-digit sha256 id is rejected or cut off.",
        fix: "Raise the upper bound to 64, e.g. {7,64}, or drop it.",
    },
    Rule {
        id: "oid-fixed-width",
        severity: Severity::Risk,
        category: Category::ObjectFormat,
        title: "Object id handled as fixed 40 characters or 20 bytes",
        why: "sha256 object ids are 64 hex characters (32 bytes); length checks, truncation and column widths sized for SHA-1 reject or corrupt them.",
        fix: "Size for 64 hex characters / 32 bytes, or derive the length from git rev-parse --show-object-format.",
    },
    Rule {
        id: "sha1-constant-oid",
        severity: Severity::Break,
        category: Category::ObjectFormat,
        title: "Hard-coded SHA-1 object id constant",
        why: "The null id, the empty tree and the empty blob have different, 64-digit ids in a sha256 repository.",
        fix: "Compute them: git hash-object -t tree /dev/null (empty tree), git hash-object --stdin </dev/null (empty blob), and for the null id: git hash-object --stdin </dev/null | tr '[0-9a-f]' '0' (what Git's own sample hooks do).",
    },
    Rule {
        id: "sha1-object-hashing",
        severity: Severity::Risk,
        category: Category::ObjectFormat,
        title: "Object ids computed by hand with SHA-1",
        why: "Hashing a \"blob <size>\\0\" header with SHA-1 reproduces Git's ids only in sha1 repositories.",
        fix: "Let Git compute ids (git hash-object), or pick the algorithm from git rev-parse --show-object-format.",
    },
    // -- ref format ---------------------------------------------------------
    Rule {
        id: "ref-files-access",
        severity: Severity::Break,
        category: Category::RefFormat,
        title: "Reads or writes ref storage files directly",
        why: "A reftable repository keeps refs and reflogs in .git/reftable/: there is no packed-refs, no .git/logs/, and .git/refs/heads is a placeholder file, not a directory.",
        fix: "Go through Git: git for-each-ref, git rev-parse, git update-ref, git show-ref, git reflog / git log -g.",
    },
    Rule {
        id: "head-file-read",
        severity: Severity::Break,
        category: Category::RefFormat,
        title: "Reads .git/HEAD as a file",
        why: "In a reftable repository .git/HEAD is a compatibility stub that always reads \"ref: refs/heads/.invalid\".",
        fix: "git symbolic-ref --short -q HEAD, git branch --show-current, or git rev-parse HEAD.",
    },
    // -- default branch -----------------------------------------------------
    Rule {
        id: "master-after-init",
        severity: Severity::Break,
        category: Category::DefaultBranch,
        title: "Assumes a freshly initialized repository is on master",
        why: "The file runs git init without choosing a branch, then refers to master; under Git 3.0 the new repository is on main.",
        fix: "Pin the name at creation: git init -b <name> (or --initial-branch), or -c init.defaultBranch=<name>.",
    },
    // -- safe.bareRepository ------------------------------------------------
    Rule {
        id: "embedded-bare-repo",
        severity: Severity::Risk,
        category: Category::SafeBareRepository,
        title: "Bare repository checked into the tree",
        why: "Running Git from inside this directory (cd, git -C) relies on implicit bare-repository discovery, which Git 3.0 refuses by default. Using it as a clone, fetch or push URL keeps working.",
        fix: "Point Git at it explicitly (--git-dir or GIT_DIR) wherever a command runs inside it, or create the fixture at test time.",
    },
    Rule {
        id: "bare-repo-implicit",
        severity: Severity::Risk,
        category: Category::SafeBareRepository,
        title: "Runs Git from inside what looks like a bare repository",
        why: "cd / git -C into a bare repository relies on implicit discovery; with safe.bareRepository=explicit Git exits with \"cannot use bare repository\".",
        fix: "Use git --git-dir=<path> or set GIT_DIR instead of changing into the directory.",
    },
    // -- removals -----------------------------------------------------------
    Rule {
        id: "git-whatchanged",
        severity: Severity::Break,
        category: Category::Removal,
        title: "Uses git whatchanged",
        why: "git whatchanged is removed in Git 3.0; it already refuses to run without --i-still-use-this.",
        fix: "git log --raw (the rough equivalent the Git project names).",
    },
    Rule {
        id: "git-pack-redundant",
        severity: Severity::Break,
        category: Category::Removal,
        title: "Uses git pack-redundant",
        why: "git pack-redundant is removed in Git 3.0; it already refuses to run without --i-still-use-this.",
        fix: "Let git gc / git repack -a -d consolidate packs.",
    },
    Rule {
        id: "name-rev-stdin",
        severity: Severity::Break,
        category: Category::Removal,
        title: "Uses git name-rev --stdin",
        why: "The --stdin option of git name-rev is removed in Git 3.0.",
        fix: "git name-rev --annotate-stdin (the documented synonym).",
    },
    Rule {
        id: "grafts-file",
        severity: Severity::Break,
        category: Category::Removal,
        title: "Relies on info/grafts",
        why: "Graft support is removed in Git 3.0.",
        fix: "git replace --graft <commit> <parent>..., or convert an existing file with git replace --convert-graft-file.",
    },
    Rule {
        id: "legacy-remote-dirs",
        severity: Severity::Break,
        category: Category::Removal,
        title: "Uses .git/branches/ or .git/remotes/ remote shorthands",
        why: "Remote shorthands stored in $GIT_COMMON_DIR/branches/ and $GIT_COMMON_DIR/remotes/ are removed in Git 3.0.",
        fix: "Configure remotes in the repository config: git remote add <name> <url>.",
    },
    Rule {
        id: "comment-char-auto",
        severity: Severity::Break,
        category: Category::Removal,
        title: "Sets core.commentChar / core.commentString to auto",
        why: "The auto value is removed in Git 3.0.",
        fix: "Set an explicit comment character or string, e.g. core.commentChar=';'.",
    },
    Rule {
        id: "prefer-symlink-refs",
        severity: Severity::Break,
        category: Category::Removal,
        title: "Sets core.preferSymlinkRefs to true",
        why: "Writing symbolic refs as symbolic links is removed in Git 3.0; symrefs are written as plain files.",
        fix: "Drop the setting and read symrefs with git symbolic-ref.",
    },
    // -- build --------------------------------------------------------------
    Rule {
        id: "git-source-build",
        severity: Severity::Info,
        category: Category::Build,
        title: "Builds Git from source",
        why: "Git plans to make Rust mandatory in 3.0 and drop the build switch that turns it off; the document says this may be deferred if distributions are hurt.",
        fix: "Make sure the build image has a Rust toolchain before it builds Git 3.0.",
    },
];

/// Look a rule up by id.
pub fn find(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_kebab_case() {
        let mut seen = std::collections::HashSet::new();
        for r in RULES {
            assert!(seen.insert(r.id), "duplicate rule id {}", r.id);
            assert!(
                r.id.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{} is not kebab-case",
                r.id
            );
        }
    }

    #[test]
    fn every_rule_has_text() {
        for r in RULES {
            assert!(!r.title.is_empty() && !r.why.is_empty() && !r.fix.is_empty());
        }
    }

    #[test]
    fn severity_round_trips() {
        for s in [Severity::Break, Severity::Risk, Severity::Info] {
            assert_eq!(Severity::parse(s.as_str()), Ok(s));
        }
        assert!(Severity::parse("fatal").is_err());
        assert!(Severity::Break > Severity::Risk && Severity::Risk > Severity::Info);
    }
}
