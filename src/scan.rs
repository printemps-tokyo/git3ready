//! Walking a directory tree and feeding files to the [`Matcher`].
//!
//! This is the only scanning code that touches the filesystem. The walk is
//! gitignore-aware (`.gitignore`, `.ignore`, `.git/info/exclude`, the global
//! gitignore), the same behavior sunsetscan and repotome have, plus a
//! `.git3readyignore` file for paths that legitimately quote the patterns.
//!
//! Besides text files, the walk looks at every directory to find bare
//! repositories checked into the tree (`embedded-bare-repo`), using the same
//! three signatures Git's own `is_git_directory()` in `setup.c` checks: a valid
//! `HEAD`, an `objects/` directory and a `refs` entry.

use std::path::Path;

use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;

use crate::matcher::{Finding, Matcher};

/// Files larger than this are skipped: scripts and CI files are not this big.
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// How much of a file is inspected before deciding it is binary.
const BINARY_SNIFF_BYTES: usize = 8192;

/// The per-directory ignore file git3ready honors in addition to .gitignore.
pub const IGNORE_FILE: &str = ".git3readyignore";

/// Extensions scanned by default. Anything else needs `--all-files`, except
/// extensionless files that start with a `#!` line, which are always scanned:
/// Git hooks and `bin/` scripts are where object ids and `.git/` paths live.
pub const SOURCE_EXTENSIONS: &[&str] = &[
    "bash", "bat", "c", "cc", "cfg", "cjs", "cmd", "conf", "cpp", "cs", "cts", "dart", "ex", "exs",
    "fish", "go", "gradle", "groovy", "h", "hcl", "hpp", "ini", "java", "js", "json", "jsonc",
    "jsx", "ksh", "kt", "kts", "lua", "md", "mdx", "mjs", "mk", "mts", "nix", "php", "pl", "pm",
    "ps1", "psm1", "py", "rake", "rb", "rs", "scala", "sh", "sql", "swift", "tf", "toml", "ts",
    "tsx", "txt", "vue", "xml", "yaml", "yml", "zsh",
];

/// Extensionless (or dot-) files scanned by default.
pub const SOURCE_FILENAMES: &[&str] = &[
    ".bash_profile",
    ".bashrc",
    ".gitconfig",
    ".gitlab-ci.yml",
    ".profile",
    ".zshrc",
    "Brewfile",
    "Containerfile",
    "GNUmakefile",
    "Jenkinsfile",
    "Justfile",
    "Makefile",
    "Rakefile",
    "gitconfig",
    "justfile",
    "makefile",
];

/// Traversal settings.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Scan every text file, not just the default source kinds.
    pub all_files: bool,
    /// gitignore-syntax globs whose matches are skipped.
    pub exclude: Vec<String>,
}

/// Counts of what the walk saw and skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanStats {
    pub scanned: usize,
    /// Scanned files that were not valid UTF-8 and were read lossily.
    pub lossy: usize,
    /// Paths that could not be read; the scan is incomplete when non-empty.
    pub unreadable: Vec<String>,
    pub skipped_kind: usize,
    pub skipped_large: usize,
    pub skipped_binary: usize,
    pub suppressed: usize,
}

/// Findings keyed by repository-relative path (forward slashes).
pub type PathFindings = Vec<(String, Vec<Finding>)>;

/// True when a path is one of the default source kinds by name alone.
/// Names and extensions compare case-insensitively (`build.dockerfile`,
/// `RUN.SH` on a case-insensitive filesystem).
pub fn looks_like_source(rel_path: &str) -> bool {
    let name = rel_path
        .rsplit('/')
        .next()
        .unwrap_or(rel_path)
        .to_ascii_lowercase();
    if SOURCE_FILENAMES
        .iter()
        .any(|f| f.eq_ignore_ascii_case(&name))
    {
        return true;
    }
    if name.starts_with("dockerfile") || name.ends_with(".dockerfile") {
        return true;
    }
    match name.rsplit_once('.') {
        // A leading dot is the whole name (".gitignore"), not an extension.
        Some((stem, ext)) if !stem.is_empty() => SOURCE_EXTENSIONS.contains(&ext),
        _ => false,
    }
}

/// A `#!` line, allowing for a UTF-8 byte order mark in front of it.
fn starts_with_shebang(bytes: &[u8]) -> bool {
    bytes
        .strip_prefix(b"\xef\xbb\xbf")
        .unwrap_or(bytes)
        .starts_with(b"#!")
}

fn has_extension(rel_path: &str) -> bool {
    let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
    matches!(name.rsplit_once('.'), Some((stem, _)) if !stem.is_empty())
}

/// True when `bytes` look like a binary file.
fn looks_binary(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(BINARY_SNIFF_BYTES)].contains(&0)
}

/// Whether `dir` is a bare repository by Git's own discovery test.
///
/// Mirrors `is_git_directory()` in git/git `setup.c`: `HEAD` must be a valid
/// head reference (a `ref: refs/...` symref or a bare hex object id), and both
/// `objects` and `refs` must exist.
pub fn is_bare_repository(dir: &Path) -> bool {
    if !dir.join("objects").is_dir() || !dir.join("refs").exists() {
        return false;
    }
    let Ok(head) = std::fs::read(dir.join("HEAD")) else {
        return false;
    };
    if head.len() > 4096 {
        return false;
    }
    let head = String::from_utf8_lossy(&head);
    let head = head.trim_end();
    head.starts_with("ref: refs/")
        || ((head.len() == 40 || head.len() == 64) && head.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Whether ignore files above `root` apply. See sunsetscan's notes: a
/// `.gitignore` above a repository does not apply to it.
fn wants_parent_ignores(root: &Path) -> bool {
    !root.join(".git").exists()
}

/// Walk `root` and run `matcher` over every file that survives the filters.
pub fn scan_tree(
    root: &Path,
    opts: &ScanOptions,
    matcher: &Matcher,
) -> Result<(PathFindings, ScanStats), String> {
    let mut overrides = OverrideBuilder::new(root);
    for glob in &opts.exclude {
        // A bare override glob is an allowlist, so an exclusion is the negated
        // form; this gives --exclude full gitignore syntax and prunes whole
        // directories.
        overrides
            .add(&format!("!{glob}"))
            .map_err(|e| format!("invalid --exclude glob '{glob}': {e}"))?;
    }
    let overrides = overrides
        .build()
        .map_err(|e| format!("invalid --exclude globs: {e}"))?;

    let mut walker = WalkBuilder::new(root);
    walker
        // Dotfiles are scanned: .github workflows, .husky hooks, .gitconfig.
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .ignore(true)
        .parents(wants_parent_ignores(root))
        .require_git(false)
        .add_custom_ignore_filename(IGNORE_FILE)
        .overrides(overrides)
        .filter_entry(|e| e.file_name() != ".git");

    let mut out: PathFindings = Vec::new();
    let mut stats = ScanStats::default();
    let check_bare = matcher.is_enabled("embedded-bare-repo");

    for result in walker.build() {
        let dent = match result {
            Ok(d) => d,
            // An unreadable directory does not stop the walk, but it is
            // reported by path and makes the scan incomplete.
            Err(e) => {
                stats.unreadable.push(e.to_string());
                continue;
            }
        };
        let path = dent.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        let Some(ft) = dent.file_type() else {
            continue;
        };
        if ft.is_dir() {
            if check_bare && dent.depth() > 0 && is_bare_repository(path) {
                out.push((
                    format!("{rel}/"),
                    vec![Finding {
                        rule: "embedded-bare-repo",
                        line: 0,
                        column: 0,
                        text: "HEAD, objects/ and refs present".into(),
                        note: None,
                    }],
                ));
            }
            continue;
        }
        if !ft.is_file() {
            continue;
        }

        let by_name = opts.all_files || looks_like_source(&rel);
        // Files with an unknown extension are never scripts worth reading by
        // default; extensionless ones might be (hooks, bin/ scripts).
        if !by_name && has_extension(&rel) {
            stats.skipped_kind += 1;
            continue;
        }
        match dent.metadata() {
            Ok(md) if md.len() > MAX_FILE_BYTES => {
                stats.skipped_large += 1;
                continue;
            }
            Ok(_) => {}
            Err(e) => {
                stats.unreadable.push(format!("{rel}: {e}"));
                continue;
            }
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                stats.unreadable.push(format!("{rel}: {e}"));
                continue;
            }
        };
        if !by_name && !starts_with_shebang(&bytes) {
            stats.skipped_kind += 1;
            continue;
        }
        if looks_binary(&bytes) {
            stats.skipped_binary += 1;
            continue;
        }
        // Every pattern is ASCII, so a script with a Latin-1 or CP932 comment
        // is still worth reading; the odd bytes become U+FFFD.
        let text = match String::from_utf8(bytes) {
            Ok(t) => t,
            Err(e) => {
                stats.lossy += 1;
                String::from_utf8_lossy(e.as_bytes()).into_owned()
            }
        };
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);

        stats.scanned += 1;
        let scan = matcher.scan(text);
        stats.suppressed += scan.suppressed;
        if !scan.findings.is_empty() {
            out.push((rel, scan.findings));
        }
    }

    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((out, stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_detection() {
        for yes in [
            "a.sh",
            ".github/workflows/ci.yml",
            "Dockerfile",
            "docker/Dockerfile.ci",
            "Makefile",
            ".gitconfig",
            "src/lib.rs",
            "build.Dockerfile",
            "build.dockerfile",
            "RUN.SH",
            "x.ksh",
        ] {
            assert!(looks_like_source(yes), "{yes} should be scanned");
        }
        for no in [
            "a.png",
            ".gitignore",
            "LICENSE",
            "hooks/pre-push",
            "x.tar.gz",
        ] {
            assert!(!looks_like_source(no), "{no} should not match by name");
        }
    }

    #[test]
    fn extension_detection() {
        assert!(has_extension("a/b.txt"));
        assert!(!has_extension("hooks/pre-push"));
        assert!(!has_extension(".profile"));
    }

    #[test]
    fn shebang_detection_allows_a_bom() {
        assert!(starts_with_shebang(b"#!/bin/sh\n"));
        assert!(starts_with_shebang(b"\xef\xbb\xbf#!/bin/sh\n"));
        assert!(!starts_with_shebang(b"echo\n"));
    }

    #[test]
    fn binary_sniffing() {
        assert!(!looks_binary(b"echo hi\n"));
        assert!(looks_binary(b"\x7fELF\x00"));
    }

    #[test]
    fn extension_list_is_sorted_and_unique() {
        let mut sorted = SOURCE_EXTENSIONS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.as_slice(), SOURCE_EXTENSIONS);
    }
}
