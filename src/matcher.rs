//! Pure text matching: file contents in, findings out.
//!
//! Most rules are one regular expression applied line by line. Three need a
//! little more context, and that context is the reason this is not a grep
//! wrapper:
//!
//! - `hex40-pattern` / `hex40-upper-bound` look inside the matched character
//!   class, so `[0-9]{40}` (not an object id) is left alone.
//! - `sha1-object-hashing` only fires when a SHA-1 call sits within a few
//!   lines of a Git object header literal such as `"blob "`.
//! - `master-after-init` is file-level: a reference to `master` only counts
//!   when the same file runs `git init` without choosing a branch.
//!
//! Nothing here touches the filesystem; [`crate::scan`] does that.

use std::collections::BTreeSet;

use regex::Regex;

use crate::rules::{self, RULES};

/// The inline suppression marker. `git3ready:ignore` on a line suppresses
/// every finding on it; `git3ready:ignore hex40-pattern, head-file-read`
/// suppresses only those rules.
pub const IGNORE_MARKER: &str = "git3ready:ignore";

/// Longest snippet kept per finding, in characters.
const SNIPPET_CHARS: usize = 160;

/// How many lines around a SHA-1 call may hold the object header literal.
const HASHING_WINDOW: usize = 3;

/// How far below a `git init` a `master` reference is still tied to it.
const MASTER_WINDOW: usize = 30;

/// One finding in one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: &'static str,
    /// 1-based line number.
    pub line: usize,
    /// 1-based column of the match, in characters.
    pub column: usize,
    /// The trimmed source line, shortened to [`SNIPPET_CHARS`].
    pub text: String,
    /// Extra context for this particular hit, when the rule text is not enough.
    pub note: Option<String>,
}

/// Findings for one file plus how many were suppressed inline.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileScan {
    pub findings: Vec<Finding>,
    pub suppressed: usize,
}

/// Compiled patterns plus the set of enabled rule ids.
#[derive(Debug)]
pub struct Matcher {
    enabled: BTreeSet<&'static str>,
    simple: Vec<(&'static str, Regex)>,
    hex_class: Regex,
    hex64: Regex,
    width: Regex,
    hash_context: Regex,
    hash_context_camel: Regex,
    constant_oid: Regex,
    null_oid_context: Regex,
    sha1_call: Regex,
    object_header: Regex,
    shell_init: Regex,
    quoted_init: Regex,
    quoted_git: Regex,
    branch_pinned_line: Regex,
    branch_pinned_file: Regex,
    master: Regex,
    master_context: Regex,
    bare_cd: Regex,
}

/// `.git`, `$GIT_DIR` or `$GIT_COMMON_DIR` followed by a path separator.
const GIT_DIR_PREFIX: &str = r"(?:\.git|\$\{?GIT_DIR\}?|\$\{?GIT_COMMON_DIR\}?)[/\\]";

fn re(pattern: &str) -> Regex {
    // Patterns are compile-time constants covered by tests; a failure here is
    // a programming error, not user input.
    Regex::new(pattern).unwrap_or_else(|e| panic!("bad built-in pattern {pattern}: {e}"))
}

impl Default for Matcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Matcher {
    /// A matcher with every rule enabled.
    pub fn new() -> Self {
        let simple = vec![
            (
                "ref-files-access",
                re(&format!(
                    r#"{GIT_DIR_PREFIX}(?:refs\b|packed-refs\b|logs[/\\])|\bpacked-refs\b|["']\.git["']\s*,\s*["'](?:refs|packed-refs|logs)["']"#
                )),
            ),
            (
                "head-file-read",
                re(&format!(
                    r#"{GIT_DIR_PREFIX}HEAD\b|["']\.git["']\s*,\s*["']HEAD["']"#
                )),
            ),
            (
                "git-whatchanged",
                re(r#"\bgit[\s-]+whatchanged\b|["']whatchanged["']"#),
            ),
            (
                "git-pack-redundant",
                re(r#"\bgit[\s-]+pack-redundant\b|["']pack-redundant["']"#),
            ),
            // The option must be preceded by whitespace or a quote, which is
            // what keeps --annotate-stdin out.
            ("name-rev-stdin", re(r#"\bname-rev\b.*[\s"']--stdin\b"#)),
            ("grafts-file", re(r"\binfo[/\\]grafts\b|\bGIT_GRAFT_FILE\b")),
            (
                "legacy-remote-dirs",
                re(&format!(r"{GIT_DIR_PREFIX}(?:branches|remotes)\b")),
            ),
            (
                "comment-char-auto",
                re(
                    r#"(?i)\bcore\.comment(?:char|string)["']?\s*(?:=|\s|,)\s*["']?auto\b|^\s*comment(?:char|string)\s*=\s*["']?auto\b"#,
                ),
            ),
            (
                "prefer-symlink-refs",
                re(
                    r#"(?i)\bcore\.prefersymlinkrefs["']?\s*(?:=|\s|,)\s*["']?(?:true|yes|on|1)\b|^\s*prefersymlinkrefs\s*=\s*["']?(?:true|yes|on|1)\b"#,
                ),
            ),
            (
                "git-source-build",
                re(
                    r"\bgit-\d+\.\d+(?:\.\d+)?(?:\.rc\d+|-rc\d+)?\.tar\.(?:gz|xz|bz2)\b|\b(?:NO_RUST|WITH_RUST)\b|-Drust=|\bclone\b.*\bgithub\.com/git/git(?:\.git)?\b|\bgit\.kernel\.org/pub/scm/git/git\.git\b",
                ),
            ),
        ];

        Matcher {
            enabled: RULES.iter().map(|r| r.id).collect(),
            simple,
            // A hex digit class (or \h, \p{XDigit}, [[:xdigit:]]) repeated
            // {40} or {n,40}; BRE escapes \{ \} are accepted too.
            hex_class: re(
                r"(?:\[\[:xdigit:\]\]|\[((?:\\d|[0-9a-zA-Z-])+)\]|\\h|\\p\{(?:XDigit|AHex|Hex_Digit|ASCII_Hex_Digit)\})\\?\{(?:(\d+),)?40\\?\}",
            ),
            // The same class sized for SHA-256: {64}, {n,64}, or the {24}
            // suffix of a 40-or-64 pattern. A line that has one already
            // handles both lengths.
            hex64: re(
                r"(?:\[\[:xdigit:\]\]|\[(?:\\d|[0-9a-zA-Z-])+\]|\\h|\\p\{(?:XDigit|AHex|Hex_Digit|ASCII_Hex_Digit)\})\\?\{(?:\d+,)?(?:64|24)\\?\}",
            ),
            width: re(
                r#"(?i)(?:\blen\([^()]*\)|\.length\b|\.len\(\)|\.size\(\)|\b(?:mb_)?strlen\([^()]*\)|\$\{#\w+\}["']?|\bcount\([^()]*\))\s*(?:={2,3}|!==?|<=?|>=?|-(?:eq|ne|lt|le|gt|ge)\b)\s*40\b|\[\s*(?:0\s*)?:\s*40\s*\]|\[\s*\.\.\s*40\s*\]|\.(?:slice|substring|substr)\(\s*0\s*,\s*40\s*\)|\bsubstr\([^,()]+,\s*0\s*,\s*40\s*\)|\bcut\s+-c\s*1?-40\b|\bhead\s+-c\s*40\b|\b(?:var)?char\s*\(\s*40\s*\)|\b(?:var)?binary\s*\(\s*20\s*\)|\[u8;\s*20\]"#,
            ),
            hash_context: re(
                r"(?i)(?:\b|_)(?:sha1?|hexsha|oids?|objectid|object_id|commit\w*|revs?|revision)(?:\b|_)",
            ),
            hash_context_camel: re(r"[a-z](?:Sha1?|Oid|ObjectId|Commit)\b"),
            constant_oid: re(
                r"\b(?:4b825dc642cb6eb9a060e54bf8d69288fbee4904|e69de29bb2d1d6434b8b29ae775ad8c2e48c5391|0{40})\b",
            ),
            // Forty zeros are also a common placeholder (key ids, addresses),
            // so the null id only counts next to a Git-flavored word.
            null_oid_context: re(
                r"(?i)zero|null|z40|empty|\bold|\bnew|\bref|\bgit|sha|\boid|\brev|commit|\bhash|\bobject|\bparent|\bbase|\bhead",
            ),
            sha1_call: re(
                r#"(?i)hashlib\.sha1\b|createHash\(\s*['"]sha-?1['"]|\bsha1\s*\(|\bsha1::|\bsha1sum\b|\bdigest::sha1\b|\bopenssl\s+(?:dgst\s+-)?sha1\b|getInstance\(\s*"sha-?1"|\bsha1\.new\b|\bcrypto/sha1\b|\bsha1\.sum\b"#,
            ),
            object_header: re(r#"(?:\bb)?["'`](?:blob|tree|commit|tag) "#),
            shell_init: re(r"\bgit(?:\s+(?:-[Cc]\s+\S+|--?[\w-]+(?:=\S+)?))*\s+init\b"),
            quoted_init: re(r#"["']init["']"#),
            quoted_git: re(r#"["']git["']|\bgit\b"#),
            branch_pinned_line: re(r#"(?:\s|["'])(?:-b|--initial-branch)\b"#),
            branch_pinned_file: re(r"(?i)\binit\.defaultBranch\b|--initial-branch\b"),
            master: re(r"\bmaster\b"),
            master_context: re(r#"\bgit\b|refs/heads/master\b|["']master["']"#),
            bare_cd: re(
                r#"(?:\bcd|\bpushd|\bgit\s+-C|\bcwd\s*[:=]|\bcurrent_dir\(|\bchdir\()\s*["'`]?([^\s"'`;|&)]+)"#,
            ),
        }
    }

    /// Keep only the named rules (`only`, when non-empty) minus `skip`.
    pub fn retain(&mut self, only: &[String], skip: &[String]) -> Result<(), String> {
        for id in only.iter().chain(skip) {
            if rules::find(id).is_none() {
                return Err(format!("unknown rule id '{id}' (see git3ready rules)"));
            }
        }
        if !only.is_empty() {
            self.enabled.retain(|id| only.iter().any(|o| o == id));
        }
        self.enabled.retain(|id| !skip.iter().any(|s| s == id));
        if self.enabled.is_empty() {
            return Err("--only / --skip left no rules enabled".into());
        }
        Ok(())
    }

    /// Whether a rule is enabled.
    pub fn is_enabled(&self, id: &str) -> bool {
        self.enabled.contains(id)
    }

    /// Run every enabled rule over one file's text.
    pub fn scan(&self, text: &str) -> FileScan {
        let lines: Vec<&str> = text.lines().collect();
        let mut raw: Vec<Finding> = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let lineno = idx + 1;
            for (id, pattern) in &self.simple {
                if let Some(m) = pattern.find(line) {
                    raw.push(finding(id, lineno, line, m.start(), None));
                }
            }
            self.hex_patterns(lineno, line, &mut raw);
            self.fixed_width(lineno, line, &mut raw);
            if let Some(m) = self.constant_oid.find(line) {
                let note = match m.as_str() {
                    "4b825dc642cb6eb9a060e54bf8d69288fbee4904" => {
                        Some("SHA-1 id of the empty tree")
                    }
                    "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" => {
                        Some("SHA-1 id of the empty blob")
                    }
                    _ if self.null_oid_context.is_match(line) => {
                        Some("SHA-1-length null object id")
                    }
                    _ => None,
                };
                if let Some(note) = note {
                    raw.push(finding(
                        "sha1-constant-oid",
                        lineno,
                        line,
                        m.start(),
                        Some(note.into()),
                    ));
                }
            }
            if let Some(m) = self.sha1_call.find(line) {
                let lo = idx.saturating_sub(HASHING_WINDOW);
                let hi = (idx + HASHING_WINDOW).min(lines.len() - 1);
                if lines[lo..=hi]
                    .iter()
                    .any(|l| self.object_header.is_match(l))
                {
                    raw.push(finding(
                        "sha1-object-hashing",
                        lineno,
                        line,
                        m.start(),
                        None,
                    ));
                }
            }
            if let Some(start) = self.bare_repo_cd(line) {
                raw.push(finding("bare-repo-implicit", lineno, line, start, None));
            }
        }
        self.master_after_init(&lines, &mut raw);

        let mut out = FileScan::default();
        for f in raw {
            if !self.enabled.contains(f.rule) {
                continue;
            }
            if suppressed(lines[f.line - 1], f.rule) {
                out.suppressed += 1;
            } else {
                out.findings.push(f);
            }
        }
        out.findings
            .sort_by(|a, b| (a.line, a.column, a.rule).cmp(&(b.line, b.column, b.rule)));
        out.findings
            .dedup_by(|a, b| a.line == b.line && a.rule == b.rule);
        out
    }

    fn hex_patterns(&self, lineno: usize, line: &str, out: &mut Vec<Finding>) {
        if self.hex64.is_match(line) {
            return;
        }
        for caps in self.hex_class.captures_iter(line) {
            if let Some(class) = caps.get(1) {
                let c = class.as_str();
                if !(c.contains("a-f") || c.contains("A-F")) {
                    continue;
                }
            }
            let whole = caps.get(0).map_or(0, |m| m.start());
            let id = if caps.get(2).is_some() {
                "hex40-upper-bound"
            } else {
                "hex40-pattern"
            };
            out.push(finding(id, lineno, line, whole, None));
            return;
        }
    }

    fn fixed_width(&self, lineno: usize, line: &str, out: &mut Vec<Finding>) {
        let Some(m) = self.width.find(line) else {
            return;
        };
        if self.hash_context.is_match(line) || self.hash_context_camel.is_match(line) {
            out.push(finding("oid-fixed-width", lineno, line, m.start(), None));
        }
    }

    /// The byte offset of a `cd x.git` / `git -C x.git` style hit, if any.
    fn bare_repo_cd(&self, line: &str) -> Option<usize> {
        for caps in self.bare_cd.captures_iter(line) {
            let path = caps.get(1)?.as_str().trim_end_matches('/');
            let looks_bare = path.ends_with(".git")
                && path != ".git"
                && !path.ends_with("/.git")
                && !path.ends_with("\\.git")
                // A URL is a clone source, not a directory Git runs in.
                && !path.contains("://");
            if looks_bare {
                return caps.get(0).map(|m| m.start());
            }
        }
        None
    }

    fn is_init_line(&self, lines: &[&str], idx: usize) -> bool {
        let line = lines[idx];
        self.shell_init.is_match(line)
            || (self.quoted_init.is_match(line)
                && lines[idx.saturating_sub(2)..=idx]
                    .iter()
                    .any(|l| self.quoted_git.is_match(l)))
    }

    /// Report `master` references that follow an unpinned `git init` closely.
    ///
    /// Each reference is tied to the nearest `git init` above it (or on the
    /// same line), within [`MASTER_WINDOW`] lines. A branch chosen on that
    /// init line (`-b`, `--initial-branch`, `-c init.defaultBranch=`) pins it;
    /// `init.defaultBranch` set anywhere else in the file pins every init.
    /// `origin/master` and other `<remote>/master` names are skipped: the
    /// remote's branch was named wherever the remote was created.
    fn master_after_init(&self, lines: &[&str], out: &mut Vec<Finding>) {
        let inits: Vec<(usize, bool)> = (0..lines.len())
            .filter(|&i| self.is_init_line(lines, i))
            .map(|i| {
                let l = lines[i];
                (
                    i,
                    self.branch_pinned_line.is_match(l) || self.branch_pinned_file.is_match(l),
                )
            })
            .collect();
        if inits.is_empty() {
            return;
        }
        let pinned_elsewhere = lines.iter().enumerate().any(|(i, l)| {
            self.branch_pinned_file.is_match(l) && !inits.iter().any(|(j, _)| *j == i)
        });
        if pinned_elsewhere {
            return;
        }
        for (idx, line) in lines.iter().enumerate() {
            let Some(m) = self
                .master
                .find_iter(line)
                .find(|m| !line[..m.start()].ends_with('/'))
            else {
                continue;
            };
            if !self.master_context.is_match(line) {
                continue;
            }
            let nearest = inits
                .iter()
                .rev()
                .find(|(i, _)| *i <= idx && idx - *i <= MASTER_WINDOW);
            if let Some((init_idx, false)) = nearest {
                out.push(finding(
                    "master-after-init",
                    idx + 1,
                    line,
                    m.start(),
                    Some(format!(
                        "git init at line {} does not choose a branch",
                        init_idx + 1
                    )),
                ));
            }
        }
    }
}

fn finding(
    rule: &'static str,
    line: usize,
    text: &str,
    byte_start: usize,
    note: Option<String>,
) -> Finding {
    let column = text[..byte_start].chars().count() + 1;
    Finding {
        rule,
        line,
        column,
        text: snippet(text),
        note,
    }
}

/// Trim and shorten a line for display.
fn snippet(line: &str) -> String {
    let t = line.trim();
    if t.chars().count() <= SNIPPET_CHARS {
        return t.to_string();
    }
    let mut s: String = t.chars().take(SNIPPET_CHARS - 3).collect();
    s.push_str("...");
    s
}

/// Whether `line` carries a marker that suppresses `rule`.
///
/// Tokens after the marker that are rule ids narrow it to those rules. A token
/// made only of punctuation (`*/`, `-->`, `--`) is ignored so comment closers
/// do not widen the marker. Anything else -- a word of explanation -- makes
/// the marker suppress the whole line, which is the safe reading of
/// `git3ready:ignore fixture data`.
pub fn suppressed(line: &str, rule: &str) -> bool {
    let Some(pos) = line.find(IGNORE_MARKER) else {
        return false;
    };
    let rest = &line[pos + IGNORE_MARKER.len()..];
    let tokens: Vec<&str> = rest
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty() && t.chars().any(|c| c.is_alphanumeric()))
        .collect();
    if tokens.is_empty() || tokens.iter().any(|t| rules::find(t).is_none()) {
        return true;
    }
    tokens.contains(&rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(text: &str) -> Vec<&'static str> {
        Matcher::new()
            .scan(text)
            .findings
            .iter()
            .map(|f| f.rule)
            .collect()
    }

    fn has(text: &str, id: &str) -> bool {
        ids(text).contains(&id)
    }

    #[test]
    fn hex40_exact_and_bounded() {
        assert!(has(r"grep -E '^[0-9a-f]{40}$'", "hex40-pattern"));
        assert!(has(r"/^[a-fA-F0-9]{40}$/", "hex40-pattern"));
        assert!(has(
            r"sed -n 's/^\([0-9a-f]\{40\}\).*/\1/p'",
            "hex40-pattern"
        ));
        assert!(has(r"grep -E '[[:xdigit:]]{40}'", "hex40-pattern"));
        assert!(has(r"/\h{40}/", "hex40-pattern"));
        assert!(has(r"r'[\da-f]{40}'", "hex40-pattern"));
        assert!(has(r"/^[0-9a-f]{7,40}$/", "hex40-upper-bound"));
        assert!(!has(r"/^[0-9a-f]{7,40}$/", "hex40-pattern"));
    }

    #[test]
    fn hex40_leaves_non_hex_and_sha256_ready_patterns_alone() {
        assert!(ids(r"/^[0-9]{40}$/").is_empty());
        assert!(ids(r"/^[0-9a-f]{40,}$/").is_empty());
        assert!(ids(r"/^[0-9a-f]{40}([0-9a-f]{24})?$/").is_empty());
        assert!(ids(r"/^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/").is_empty());
        assert!(ids(r"rb'(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40})'").is_empty());
        assert!(ids(r"/^[0-9a-f]{64}$/").is_empty());
        assert!(ids(r"/^[0-9a-f]{7,64}$/").is_empty());
    }

    #[test]
    fn fixed_width_needs_hash_context() {
        assert!(has("if len(sha) != 40:", "oid-fixed-width"));
        assert!(has("if (commitId.length === 40) {", "oid-fixed-width"));
        assert!(has(r#"[ "${#rev}" -eq 40 ]"#, "oid-fixed-width"));
        assert!(has("commit_sha CHAR(40) NOT NULL,", "oid-fixed-width"));
        assert!(has("oid BINARY(20)", "oid-fixed-width"));
        assert!(has("let oid: [u8; 20] = ...;", "oid-fixed-width"));
        assert!(has("short = headSha.slice(0, 40)", "oid-fixed-width"));
        assert!(!has("if len(name) != 40:", "oid-fixed-width"));
        assert!(!has("title VARCHAR(40)", "oid-fixed-width"));
        assert!(!has("if (password.length === 40) {", "oid-fixed-width"));
    }

    #[test]
    fn constant_oids() {
        let f = Matcher::new().scan("zero=0000000000000000000000000000000000000000\n");
        assert_eq!(f.findings[0].rule, "sha1-constant-oid");
        assert_eq!(
            f.findings[0].note.as_deref(),
            Some("SHA-1-length null object id")
        );
        assert!(has(
            "git diff 4b825dc642cb6eb9a060e54bf8d69288fbee4904 HEAD",
            "sha1-constant-oid"
        ));
        assert!(has(
            "EMPTY_BLOB = 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391'",
            "sha1-constant-oid"
        ));
        // 64 zeros is the sha256 null id; 0x-prefixed runs are not object ids.
        assert!(ids(&"0".repeat(64)).is_empty());
        // Forty zeros without a Git-flavored word nearby are a placeholder.
        assert!(ids(r#""private_key_id": "0000000000000000000000000000000000000000","#).is_empty());
        assert!(has(
            r#"if [ "$oldrev" = 0000000000000000000000000000000000000000 ]; then"#,
            "sha1-constant-oid"
        ));
        assert!(ids("addr = 0x0000000000000000000000000000000000000000").is_empty());
    }

    #[test]
    fn sha1_hashing_needs_object_header_nearby() {
        let yes = "data = f.read()\nhdr = b\"blob %d\\0\" % len(data)\noid = hashlib.sha1(hdr + data).hexdigest()\n";
        assert!(has(yes, "sha1-object-hashing"));
        assert!(!has(
            "digest = hashlib.sha1(payload).hexdigest()\n",
            "sha1-object-hashing"
        ));
    }

    #[test]
    fn ref_storage_and_head() {
        assert!(has("cat .git/refs/heads/main", "ref-files-access"));
        assert!(has(
            r#"open(os.path.join(".git", "packed-refs"))"#,
            "ref-files-access"
        ));
        assert!(has("tail -1 $GIT_DIR/logs/HEAD", "ref-files-access"));
        assert!(has(
            r#"p = path.join('.git', 'refs', 'heads')"#,
            "ref-files-access"
        ));
        assert!(has(
            "branch=$(sed 's#ref: refs/heads/##' .git/HEAD)",
            "head-file-read"
        ));
        assert!(has(
            r#"fs.readFileSync(path.join(".git", "HEAD"))"#,
            "head-file-read"
        ));
        assert!(!has("git rev-parse --abbrev-ref HEAD", "head-file-read"));
        assert!(!has(
            "uses: actions/checkout@v7 # .github/workflows",
            "ref-files-access"
        ));
        assert!(!has("cat .git/FETCH_HEAD", "head-file-read"));
    }

    #[test]
    fn master_after_unpinned_init() {
        let text =
            "git init repo\ncd repo\ngit commit --allow-empty -m x\ngit push origin master\n";
        let scan = Matcher::new().scan(text);
        let f = scan
            .findings
            .iter()
            .find(|f| f.rule == "master-after-init")
            .unwrap();
        assert_eq!(f.line, 4);
        assert_eq!(
            f.note.as_deref(),
            Some("git init at line 1 does not choose a branch")
        );
    }

    #[test]
    fn master_after_init_respects_pinning() {
        assert!(!has(
            "git init -b master repo\ngit checkout master\n",
            "master-after-init"
        ));
        assert!(!has(
            "git init --initial-branch=master r\ngit checkout master\n",
            "master-after-init"
        ));
        assert!(!has(
            "git config --global init.defaultBranch master\ngit init r\ngit checkout master\n",
            "master-after-init"
        ));
        // No init at all: an existing repository on master is fine.
        assert!(!has("git checkout master\n", "master-after-init"));
    }

    #[test]
    fn master_after_init_is_local_to_its_init() {
        // Far below the init: tied to some other repository.
        let far = format!("git init r\n{}git checkout master\n", "echo\n".repeat(40));
        assert!(!has(&far, "master-after-init"));
        // A remote-tracking name is not the new repository's branch.
        assert!(!has(
            "git init r\ngit checkout origin/master -b x\n",
            "master-after-init"
        ));
        // Pinning one init does not pin a later, unpinned one.
        let text = "git -c init.defaultBranch=master init a\ngit -C a checkout master\ngit init b\ngit -C b checkout master\n";
        let lines: Vec<usize> = Matcher::new()
            .scan(text)
            .findings
            .iter()
            .filter(|f| f.rule == "master-after-init")
            .map(|f| f.line)
            .collect();
        assert_eq!(lines, vec![4]);
        // A reference above every init is not "after" one.
        assert!(!has(
            "git checkout master\ngit init r\n",
            "master-after-init"
        ));
    }

    #[test]
    fn master_after_init_in_code() {
        let text = "execFileSync('git', ['init'], { cwd })\nexpect(branch).toBe('master')\n";
        assert!(has(text, "master-after-init"));
        let rust = "Command::new(\"git\")\n    .arg(\"init\")\n    .status()?;\nassert_eq!(head, \"master\");\n";
        assert!(has(rust, "master-after-init"));
    }

    #[test]
    fn bare_repo_cd() {
        assert!(has(
            "cd /srv/repos/app.git && git log",
            "bare-repo-implicit"
        ));
        assert!(has(
            "git -C fixtures/remote.git rev-parse HEAD",
            "bare-repo-implicit"
        ));
        assert!(has(
            r#"subprocess.run(cmd, cwd="origin.git")"#,
            "bare-repo-implicit"
        ));
        assert!(!has("cd repo/.git && git status", "bare-repo-implicit"));
        assert!(!has("cd .git", "bare-repo-implicit"));
        assert!(!has("git --git-dir=app.git log", "bare-repo-implicit"));
        assert!(!has("cd https://x/app.git", "bare-repo-implicit"));
    }

    #[test]
    fn removals() {
        assert!(has("git whatchanged --since=1.week", "git-whatchanged"));
        assert!(has(
            "git pack-redundant --all | xargs rm",
            "git-pack-redundant"
        ));
        assert!(has(
            "git rev-list HEAD | git name-rev --stdin",
            "name-rev-stdin"
        ));
        assert!(!has("git name-rev --annotate-stdin", "name-rev-stdin"));
        assert!(has("echo \"$c $p\" >> .git/info/grafts", "grafts-file"));
        assert!(has("export GIT_GRAFT_FILE=/tmp/g", "grafts-file"));
        assert!(has("cp origin .git/remotes/", "legacy-remote-dirs"));
        assert!(has("ls $GIT_DIR/branches", "legacy-remote-dirs"));
        assert!(!has(
            "git branch -r # refs/remotes/origin",
            "legacy-remote-dirs"
        ));
        assert!(has("git config core.commentChar auto", "comment-char-auto"));
        assert!(has("  commentString = auto", "comment-char-auto"));
        assert!(has(
            "git -c core.commentString=auto commit",
            "comment-char-auto"
        ));
        assert!(!has("git config core.commentChar ';'", "comment-char-auto"));
        assert!(has(
            "git config core.preferSymlinkRefs true",
            "prefer-symlink-refs"
        ));
        assert!(has("\tpreferSymlinkRefs = yes", "prefer-symlink-refs"));
        assert!(!has(
            "git config core.preferSymlinkRefs false",
            "prefer-symlink-refs"
        ));
    }

    #[test]
    fn source_build() {
        assert!(has(
            "curl -LO https://www.kernel.org/pub/software/scm/git/git-2.51.0.tar.xz",
            "git-source-build"
        ));
        assert!(has("make NO_RUST=YesPlease", "git-source-build"));
        assert!(has(
            "git clone https://github.com/git/git",
            "git-source-build"
        ));
        assert!(!has(
            "git clone https://github.com/git/gitk",
            "git-source-build"
        ));
    }

    #[test]
    fn suppression_marker() {
        assert!(suppressed("x # git3ready:ignore", "hex40-pattern"));
        assert!(suppressed(
            "x # git3ready:ignore hex40-pattern",
            "hex40-pattern"
        ));
        assert!(!suppressed(
            "x # git3ready:ignore hex40-pattern",
            "head-file-read"
        ));
        assert!(suppressed(
            "/* git3ready:ignore hex40-pattern, head-file-read */",
            "head-file-read"
        ));
        assert!(suppressed(
            "x # git3ready:ignore fixture data",
            "head-file-read"
        ));
        assert!(!suppressed("x", "hex40-pattern"));

        let scan = Matcher::new().scan("cat .git/HEAD # git3ready:ignore\n");
        assert!(scan.findings.is_empty());
        assert_eq!(scan.suppressed, 1);
    }

    #[test]
    fn retain_filters_and_validates() {
        let mut m = Matcher::new();
        m.retain(&["head-file-read".into()], &[]).unwrap();
        assert!(m.is_enabled("head-file-read"));
        assert!(!m.is_enabled("hex40-pattern"));
        assert_eq!(
            m.scan("cat .git/HEAD .git/refs/x\n")
                .findings
                .iter()
                .map(|f| f.rule)
                .collect::<Vec<_>>(),
            vec!["head-file-read"]
        );
        assert!(Matcher::new().retain(&["nope".into()], &[]).is_err());
        assert!(Matcher::new()
            .retain(&["head-file-read".into()], &["head-file-read".into()])
            .is_err());
    }

    #[test]
    fn columns_count_characters_not_bytes() {
        let f = Matcher::new().scan("# \u{65e5}\u{672c} cat .git/HEAD\n");
        assert_eq!(f.findings[0].column, 10);
    }

    #[test]
    fn every_rule_but_the_tree_rule_is_reachable_from_text() {
        let corpus = [
            "grep '[0-9a-f]{40}'",
            "grep '[0-9a-f]{7,40}'",
            "len(sha) == 40",
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "h = b'blob 3\\0'\nhashlib.sha1(h)",
            "cat .git/packed-refs",
            "cat .git/HEAD",
            "git init r\ngit checkout master",
            "cd a.git",
            "git whatchanged",
            "git pack-redundant",
            "git name-rev --stdin",
            ".git/info/grafts",
            ".git/remotes/origin",
            "core.commentChar=auto",
            "core.preferSymlinkRefs=true",
            "make WITH_RUST=YesPlease",
        ]
        .join("\n");
        let found: BTreeSet<&str> = ids(&corpus).into_iter().collect();
        for r in RULES {
            if r.id == "embedded-bare-repo" {
                continue;
            }
            assert!(found.contains(r.id), "{} not reachable", r.id);
        }
    }
}
