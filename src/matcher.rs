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
    message_context: Regex,
    constant_oid: Regex,
    null_oid_context: Regex,
    sha1_call: Regex,
    object_header: Regex,
    shell_init: Regex,
    quoted_init: Regex,
    arg_init: Regex,
    helper_init: Regex,
    quoted_git: Regex,
    branch_pinned_line: Regex,
    branch_pinned_file: Regex,
    branch_reset: Regex,
    branch_rename: Regex,
    branch_rename_list: Regex,
    command_separator: Regex,
    message_subcommand: Regex,
    message_arg: Regex,
    master: Regex,
    master_context: Regex,
    bare_cd: Regex,
}

/// `.git`, `$GIT_DIR` or `$GIT_COMMON_DIR` followed by a path separator.
///
/// Also `${GIT_DIR:-.git}` and `$(git rev-parse --git-dir)` (and the
/// `--git-common-dir` / `--absolute-git-dir` forms), which hooks use to find
/// the repository.
const GIT_DIR_PREFIX: &str = r#"(?:\.git|\$\{?GIT_DIR\}?|\$\{?GIT_COMMON_DIR\}?|\$\{GIT_(?:COMMON_)?DIR:-[^}]*\}|\$\(git\s+rev-parse\s+--(?:absolute-)?git-(?:common-)?dir\))["']?[/\\]"#;

/// `git` plus any global options before the subcommand (`-C dir`, `-c k=v`,
/// `--git-dir=...`, `--no-pager`), then whitespace.
const GIT_OPTIONS: &str = r"\bgit(?:\s+(?:-[Cc]\s+\S+|--?[\w-]+(?:=\S+)?))*\s+";

/// A variable holding the Git directory, joined with a path component in
/// code: `path.join(gitDir, "refs")`, `os.path.join(git_dir, "HEAD")`.
const GIT_DIR_JOIN: &str = r#"(?:["']\.git["']|(?i:\bgit_?dir)\w*)\s*,\s*"#;

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
                    r#"{GIT_DIR_PREFIX}(?:refs\b|packed-refs\b|logs[/\\])|\bpacked-refs\b|{GIT_DIR_JOIN}["'](?:refs|packed-refs|logs)["']"#
                )),
            ),
            (
                "head-file-read",
                re(&format!(
                    // `HEAD.lock` is Git's lock file, not the HEAD file.
                    r#"{GIT_DIR_PREFIX}HEAD(?:[^\w.]|$)|{GIT_DIR_JOIN}["']HEAD["']"#
                )),
            ),
            (
                "git-whatchanged",
                re(&format!(
                    r#"{GIT_OPTIONS}whatchanged\b|\bgit-whatchanged\b|["']whatchanged["']"#
                )),
            ),
            (
                "git-pack-redundant",
                re(&format!(
                    r#"{GIT_OPTIONS}pack-redundant\b|\bgit-pack-redundant\b|["']pack-redundant["']"#
                )),
            ),
            // The option must be preceded by whitespace or a quote, which keeps
            // --annotate-stdin out, and belong to the same command, which
            // keeps `git name-rev ... | git hash-object --stdin` out.
            (
                "name-rev-stdin",
                re(r#"\bname-rev\b[^|;&\n]*[\s"']--stdin\b"#),
            ),
            ("grafts-file", re(r"\binfo[/\\]grafts\b|\bGIT_GRAFT_FILE\b")),
            (
                "legacy-remote-dirs",
                re(&format!(r"{GIT_DIR_PREFIX}(?:branches|remotes)\b")),
            ),
            (
                "comment-char-auto",
                // Git compares the value with strcasecmp (environment.c), so
                // AUTO and Auto are auto too.
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
                r"(?:\[\[:xdigit:\]\]|\[((?:\\d|[0-9a-zA-Z-])+)\]|\\h|\\p\{(?:XDigit|AHex|Hex_Digit|ASCII_Hex_Digit)\})\\?\{(?:\d+,)?(?:64|24)\\?\}",
            ),
            width: re(
                r#"(?i)(?:\blen\([^()]*\)|\.length\b|\.len\(\)|\.size\b(?:\(\))?|\b(?:mb_)?strlen\([^()]*\)|\$\{#\w+\}["']?|\bcount\([^()]*\))\s*(?:={2,3}|!==?|<=?|>=?|-(?:eq|ne|lt|le|gt|ge)\b)\s*40\b|\[\s*(?:0\s*)?:\s*40\s*\]|\[\s*\.\.\s*40\s*\]|\.(?:slice|substring|substr)\(\s*0\s*,\s*40\s*\)|\bsubstr\([^,()]+,\s*0\s*,\s*40\s*\)|\bcut\s+-c\s*1?-40\b|\bhead\s+-c\s*40\b|\b(?:var)?char\s*\(\s*40\s*\)|\b(?:var)?binary\s*\(\s*20\s*\)|\[u8;\s*20\]|\[20\]byte\b|\.length\(\s*40\s*\)"#,
            ),
            hash_context: re(
                r"(?i)(?:\b|_)(?:sha1?|hexsha|oids?|objectid|object_id|commit\w*|revs?|revision)(?:\b|_)",
            ),
            hash_context_camel: re(r"[a-z](?:Sha1?|Oid|ObjectId|Commit)\b"),
            // Commit messages are cut to 40 characters for display all the
            // time; that is not an object id.
            message_context: re(
                r"(?i)(?:\b|_)(?:message|msg|subject|summary|title|description|body)(?:\b|_)",
            ),
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
            shell_init: re(&format!(r"{GIT_OPTIONS}init\b")),
            // "init" as a list element (["git", "init"], .arg("init")), not
            // as a value (message="init", -m 'init').
            // ["git", "init"] or ("git", ["init"]) with only Git global
            // options in between, so ["git", "commit", "-m", "init"] is not
            // an init.
            quoted_init: re(
                r#"["']git["']\s*,\s*\[?\s*(?:["'](?:-[Cc]|--git-dir|--work-tree)["']\s*,\s*(?:["'][^"']*["']|[\w.$]+)\s*,\s*|["']--?[\w-]+(?:=[^"']*)?["']\s*,\s*)*["']init["']"#,
            ),
            // Builder style, Command::new("git") on this or a nearby line.
            arg_init: re(r#"\.args?\(\s*(?:&?\[\s*)?["']init["']"#),
            // Test helpers whose name says git, called with init first:
            // git('init'), git(['init']), run_git("init", ...).
            helper_init: re(r#"\b\w*git\w*\(\s*\[?\s*["']init["']"#),
            quoted_git: re(r#"["']git["']|\bgit\b"#),
            branch_pinned_line: re(
                r#"(?:\s|["'])(?:-b|--initial-branch)\b|(?i:init\.defaultBranch)="#,
            ),
            // Setting the default for the whole file: git config ...
            // init.defaultBranch <value>, a GIT_CONFIG_KEY_<n> pair, an
            // [init] section line, or --initial-branch=<name> used anywhere
            // (the file already names its branches; a bare fallback init
            // next to it is for Git versions without the option). Reading
            // the setting (--get) or mentioning it in a comment does not.
            branch_pinned_file: re(
                r#"(?i)\bconfig(?:\s+(?:set|--?[\w-]+(?:[= ]\S+)?))*\s+init\.defaultBranch\s+["']?[\w.$-]|["']init\.defaultBranch["']\s*,\s*["'][\w.-]+["']|GIT_CONFIG_KEY_\d+\S*\binit\.defaultBranch\b|^\s*defaultBranch\s*=|--initial-branch[= ]["']?[\w.-]"#,
            ),
            // Renaming or creating master after init: from here on master is
            // a branch the file chose, not the default.
            branch_reset: re(
                r#"(?:\bcheckout\s+-[bB]|\bswitch\s+(?:-[cC]|--create|--force-create)|\bsymbolic-ref\s+HEAD)\s+(?:refs/heads/)?master(?:\s|$)|["']-[bBcC]["']\s*,\s*["']master["']|\bsymbolic[-_]ref\b.*["']refs/heads/master["']"#,
            ),
            // git branch -m/-M [<old>] <new>: only a rename *to* master makes
            // it, and `branch -m master main` needs master to exist.
            // Flags may sit around -m/-M (-f, --force, --move is -m); names
            // may be quoted and the command may be followed by a quote,
            // bracket or comment. Captures: first name, optional second.
            branch_rename: re(
                r#"\bbranch(?:\s+(?:-f|--force))*\s+(?:-[mM]|--move|-f[mM]|-[mM]f)(?:\s+(?:-f|--force))*\s+["']?([\w./][\w./-]*)["']?(?:\s+["']?([\w./][\w./-]*)["']?)?(?:[\s"')\]#;]|$)"#,
            ),
            // The same in an argument list: ["branch", "-M", "master"] or
            // ["branch", "-m", "old", "master"].
            branch_rename_list: re(
                r#"["'](?:-[mM]|--move)["']\s*,\s*["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?"#,
            ),
            command_separator: re(r"&&|\|\||;|\|"),
            message_subcommand: re(
                r"\b(?:commit|merge|tag|stash|notes|revert|cherry-pick|am|branch)\b",
            ),
            // -m, -am, --message, -F, then a quoted value (escapes allowed).
            message_arg: re(
                r#"(?:-[a-zA-Z]*m|--message|-F)(?:\s+|=|["']\s*,\s*)(?:"(?:[^"\\]|\\.)*"|'[^']*')"#,
            ),
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
        // Only a hex class sized 64 (or the {24} tail of 40+24) counts as
        // handling sha256; `[0-9]{24}` next to a 40 does not.
        let handles_64 = self.hex64.captures_iter(line).any(|c| {
            c.get(1).is_none_or(|class| {
                class.as_str().contains("a-f") || class.as_str().contains("A-F")
            })
        });
        if handles_64 {
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
        if (self.hash_context.is_match(line) || self.hash_context_camel.is_match(line))
            && !self.message_context.is_match(line)
        {
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

    /// Whether a line is a comment in the usual languages. A leading `*` is
    /// a comment only as a doc-comment continuation (`* text`, `*/`), not a
    /// shell `case` arm (`*) git checkout master ;;`).
    ///
    /// `--` counts only as `-- text` (SQL, Lua), so an option on a shell
    /// continuation line (`  --initial-branch=main \\`) is code, and so is
    /// any line that continues a previous one ending in a backslash.
    fn is_comment(lines: &[&str], idx: usize) -> bool {
        if idx > 0 && lines[idx - 1].trim_end().ends_with('\\') {
            return false;
        }
        let t = lines[idx].trim_start();
        ["#", "//", "/*", "-- ", ";"]
            .iter()
            .any(|c| t.starts_with(c))
            || t == "--"
            || t == "*"
            || t.starts_with("* ")
            || t.starts_with("*/")
    }

    /// `cmd` with every message argument replaced by spaces of equal byte
    /// length.
    ///
    /// Only where the nearest Git subcommand before the option takes a
    /// message (commit, merge, tag, ...): `branch -m` renames, and its
    /// argument is a branch name. Done on the whole line before it is split
    /// into commands, so a `;` inside a message does not split it.
    fn blank_messages(&self, line: &str) -> String {
        let mut out = line.to_string();
        for m in self.message_arg.find_iter(line) {
            let takes_message = self
                .message_subcommand
                .find_iter(&line[..m.start()])
                .last()
                .is_some_and(|sub| sub.as_str() != "branch");
            if takes_message {
                out.replace_range(m.range(), &" ".repeat(m.len()));
            }
        }
        out
    }

    /// The commands on a line, split at `&&`, `||`, `;` and `|`, with the
    /// byte offset each starts at.
    fn commands<'l>(&self, line: &'l str) -> Vec<(usize, &'l str)> {
        let mut out = Vec::new();
        let mut start = 0;
        for sep in self.command_separator.find_iter(line) {
            out.push((start, &line[start..sep.start()]));
            start = sep.end();
        }
        out.push((start, &line[start..]));
        out
    }

    /// `Some(pinned)` when `cmd` runs `git init`; `pinned` says whether that
    /// command chooses the branch. `lines[idx]` is the line `cmd` is on.
    fn init_in(&self, cmd: &str, lines: &[&str], idx: usize) -> Option<bool> {
        if let Some(m) = self.shell_init.find(cmd) {
            return Some(self.branch_pinned_line.is_match(&cmd[m.start()..]));
        }
        if self.quoted_init.is_match(cmd) || self.helper_init.is_match(cmd) {
            return Some(self.branch_pinned_line.is_match(cmd));
        }
        // An argument list broken after "git",: join the next line.
        let t = lines[idx].trim_end();
        if (t.ends_with(',') || t.ends_with('[')) && idx + 1 < lines.len() {
            let joined = format!("{t} {}", lines[idx + 1].trim());
            if self.quoted_init.is_match(&joined) && !self.quoted_init.is_match(lines[idx + 1]) {
                return Some(self.branch_pinned_line.is_match(&joined));
            }
        }
        let builder = self.arg_init.is_match(cmd)
            && !cmd.contains("\"-m\"")
            && lines[idx.saturating_sub(2)..=idx]
                .iter()
                .any(|l| self.quoted_git.is_match(l));
        builder.then(|| self.branch_pinned_line.is_match(cmd))
    }

    /// Whether `cmd` makes `master` explicitly: checkout -b / switch -c /
    /// symbolic-ref HEAD to master, or branch -m/-M renaming something else
    /// to master.
    fn creates_master(&self, cmd: &str) -> bool {
        if self.branch_reset.is_match(cmd) {
            return true;
        }
        let renames_to_master = |c: regex::Captures| {
            let first = c.get(1).map_or("", |m| m.as_str());
            match c.get(2) {
                Some(target) => target.as_str() == "master" && first != "master",
                None => first == "master",
            }
        };
        self.branch_rename
            .captures(cmd)
            .is_some_and(renames_to_master)
            || self
                .branch_rename_list
                .captures(cmd)
                .is_some_and(renames_to_master)
    }

    /// Report `master` references that follow an unpinned `git init` closely.
    ///
    /// Commands are ordered by position (line, then offset), so in
    /// `git rev-parse master && git branch -M master` the reference comes
    /// before the rename. Each reference is tied to the nearest earlier event
    /// within [`MASTER_WINDOW`] lines: a `git init` (pinned when that command
    /// chooses a branch) or a command that creates `master` explicitly
    /// (pinned). Setting `init.defaultBranch` in the file (git config, a
    /// GIT_CONFIG_KEY pair, an `[init]` line) or using `--initial-branch=`
    /// anywhere pins everything; `-c init.defaultBranch=` only pins its own
    /// command. Comment lines are ignored for events and references alike.
    /// `origin/master` and other `<remote>/master` names, and names such as
    /// `master-backup`, are not the default branch; `refs/heads/master` is.
    fn master_after_init(&self, lines: &[&str], out: &mut Vec<Finding>) {
        // (line index, byte offset, pinned)
        let mut events: Vec<(usize, usize, bool)> = Vec::new();
        let mut any_init = false;
        for (idx, line) in lines.iter().enumerate() {
            if Self::is_comment(lines, idx) {
                continue;
            }
            if self.branch_pinned_file.is_match(line) {
                return;
            }
            let blanked = self.blank_messages(line);
            for (off, cmd) in self.commands(&blanked) {
                if let Some(pinned) = self.init_in(cmd, lines, idx) {
                    any_init = true;
                    events.push((idx, off, pinned));
                } else if self.creates_master(cmd) {
                    events.push((idx, off, true));
                }
            }
        }
        if !any_init {
            return;
        }
        for (idx, line) in lines.iter().enumerate() {
            if Self::is_comment(lines, idx) {
                continue;
            }
            // Blank out message arguments (-m "merge master into dev",
            // ["-m", "master docs"]) so their words are not references; same
            // length, so offsets stay valid.
            let blanked = self.blank_messages(line);
            for (off, cmd) in self.commands(&blanked) {
                let Some(m) = self.master.find_iter(cmd).find(|m| {
                    let before = &cmd[..m.start()];
                    let after = &cmd[m.end()..];
                    (!before.ends_with('/') || before.ends_with("refs/heads/"))
                        && !after.starts_with('-')
                }) else {
                    continue;
                };
                // A commit message that says "master" checks nothing out.
                if !self.master_context.is_match(line) || self.message_context.is_match(cmd) {
                    continue;
                }
                let pos = (idx, off + m.start());
                let nearest = events
                    .iter()
                    .rev()
                    .find(|(i, o, _)| (*i, *o) <= pos && idx - *i <= MASTER_WINDOW);
                if let Some((init_idx, _, false)) = nearest {
                    out.push(finding(
                        "master-after-init",
                        idx + 1,
                        line,
                        off + m.start(),
                        Some(format!(
                            "git init at line {} does not choose a branch",
                            init_idx + 1
                        )),
                    ));
                    break;
                }
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
    fn master_after_init_resets_and_full_names() {
        // Renaming or creating master makes it an explicit choice.
        assert!(!has(
            "git init\ngit add .\ngit commit -m x\ngit branch -M master\ngit push -u origin master\n",
            "master-after-init"
        ));
        assert!(!has(
            "git init repo\ngit -C repo checkout -b master\ngit -C repo log master\n",
            "master-after-init"
        ));
        assert!(!has(
            "git init repo\ngit -C repo symbolic-ref HEAD refs/heads/master\ngit -C repo log master\n",
            "master-after-init"
        ));
        // The full local name is still the default branch.
        assert!(has(
            "git init repo\ngit -C repo rev-parse --verify refs/heads/master\n",
            "master-after-init"
        ));
        // A -b for another command after && does not pin the init.
        assert!(has(
            "git init -q r && git -C r checkout -b topic\ngit -C r merge master\n",
            "master-after-init"
        ));
        // A fallback init next to one that uses --initial-branch, and doc
        // comments that mention master, are not reported.
        assert!(!has(
            "const args = [\"--initial-branch=master\"];\nexeca(\"git\", [\"init\", ...args]).catch(() => execa(\"git\", [\"init\"]));\nfunction repo(branch = \"master\") {}\n",
            "master-after-init"
        ));
        assert!(!has(
            "git init r\n# then git checkout master\n",
            "master-after-init"
        ));
        // message="init" is a commit message, not an init.
        assert!(!has(
            "r.git.commit(message=\"init\")\nr.git.checkout(\"master\")\n",
            "master-after-init"
        ));
        // Library calls (GitPython Repo.init and friends) are not treated
        // as git init: their master references are too often remote
        // branches or explicit create_head calls. The README says so.
        assert!(!has(
            "r = Repo.init(rw_dir)\nr.git.cherry_pick(\"master\")\n",
            "master-after-init"
        ));
        assert!(!has(
            "r = Repo.init(d)\nr.git.commit(message=\"change on master\")\n",
            "master-after-init"
        ));
        // Reading the setting, or naming it in a comment, pins nothing.
        assert!(has(
            "# see git config --get init.defaultBranch\ngit init r\ngit -C r checkout master\n",
            "master-after-init"
        ));
    }

    #[test]
    fn precision_fixes_from_review() {
        assert!(!has("print(commit.message[:40])", "oid-fixed-width"));
        assert!(!has("if len(commit_message) > 40:", "oid-fixed-width"));
        assert!(has("type ObjectID [20]byte", "oid-fixed-width"));
        assert!(has("raise unless sha.size == 40", "oid-fixed-width"));
        assert!(has(
            r#"ls "$(git rev-parse --git-dir)/refs/heads""#,
            "ref-files-access"
        ));
        assert!(has(r#"cat "${GIT_DIR:-.git}/HEAD""#, "head-file-read"));
        assert!(has(
            r#"open(os.path.join(git_dir, "HEAD"))"#,
            "head-file-read"
        ));
        assert!(!has("rm -f .git/HEAD.lock", "head-file-read"));
        assert!(!has(
            "git name-rev --name-only HEAD | git hash-object --stdin",
            "name-rev-stdin"
        ));
        assert!(has(
            "git -C repo whatchanged --i-still-use-this",
            "git-whatchanged"
        ));
        assert!(has(
            "git -C repo pack-redundant --i-still-use-this --all",
            "git-pack-redundant"
        ));
        assert!(has("git config core.commentChar AUTO", "comment-char-auto"));
        assert!(has("git config CORE.COMMENTCHAR auto", "comment-char-auto"));
        assert!(has(r"/^[0-9a-f]{40}-[0-9]{24}$/", "hex40-pattern"));
    }

    #[test]
    fn master_after_init_round_two() {
        // Renaming master away needs master to exist: still reported.
        assert!(has(
            "git init r\ngit -C r branch -m master main\n",
            "master-after-init"
        ));
        // master-backup is another branch; creating it does not create master.
        assert!(has(
            "git init r\ngit -C r checkout -b master-backup\ngit -C r log master\n",
            "master-after-init"
        ));
        // Order within a line: the reference runs before the rename.
        assert!(has(
            "git init r\ncd r && git rev-parse master && git branch -M master\n",
            "master-after-init"
        ));
        // Commented-out commands neither pin nor report.
        assert!(has(
            "git init r\n# git branch -M master\ngit -C r log master\n",
            "master-after-init"
        ));
        assert!(has(
            "# git config --global init.defaultBranch master\ngit init r\ngit -C r log master\n",
            "master-after-init"
        ));
        // -c on another command pins only that command.
        assert!(has(
            "git -c init.defaultBranch=main status\ngit init r\ngit -C r log master\n",
            "master-after-init"
        ));
        // A shell case arm is code, not a comment.
        assert!(has(
            "git init r\ncase $x in\n  *) git -C r checkout master ;;\nesac\n",
            "master-after-init"
        ));
        // A commit message "init" is not an init.
        assert!(!has(
            "subprocess.run([\"git\", \"commit\", \"-m\", \"init\"])\nsubprocess.run([\"git\", \"checkout\", \"master\"])\n",
            "master-after-init"
        ));
        assert!(has(
            "subprocess.run([\"git\", \"-C\", d, \"init\"])\nsubprocess.run([\"git\", \"checkout\", \"master\"])\n",
            "master-after-init"
        ));
        // Code that sets the default pins the file.
        assert!(!has(
            "run([\"git\", \"config\", \"--global\", \"init.defaultBranch\", \"master\"])\nrun([\"git\", \"init\"])\nrun([\"git\", \"checkout\", \"master\"])\n",
            "master-after-init"
        ));
    }

    #[test]
    fn master_after_init_round_two_claude() {
        // init.defaultBranch set on the init's own line pins it.
        assert!(!has(
            "git config --global init.defaultBranch master && git init repo\ncd repo && git checkout master\n",
            "master-after-init"
        ));
        assert!(!has(
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=init.defaultBranch GIT_CONFIG_VALUE_0=master git init repo\ngit -C repo checkout master\n",
            "master-after-init"
        ));
        // Message arguments are not references.
        assert!(!has(
            "git init repo\ngit -C repo commit -m \"merge master into dev\"\n",
            "master-after-init"
        ));
        assert!(!has(
            "subprocess.run([\"git\", \"init\"])\nsubprocess.run([\"git\", \"commit\", \"-m\", \"master docs\"])\n",
            "master-after-init"
        ));
        // But a reference next to a message still counts.
        assert!(has(
            "git init repo\ngit -C repo commit -m \"x\" && git -C repo log master\n",
            "master-after-init"
        ));
    }

    #[test]
    fn master_after_init_round_three() {
        // Renames to master in the forms scripts and CI files use.
        for text in [
            "execSync('git init', { cwd })\nexecSync('git branch -M master', { cwd })\nexecSync('git checkout master', { cwd })\n",
            "subprocess.run([\"git\", \"init\"])\nsubprocess.run([\"git\", \"branch\", \"-M\", \"master\"])\nsubprocess.run([\"git\", \"checkout\", \"master\"])\n",
            "  - run: \"git init r && git -C r branch -M master\"\n  - run: git -C r log master\n",
            "git init r\ngit -C r branch -M master # rename\ngit -C r log master\n",
            "git init r\ngit -C r branch -M \"master\"\ngit -C r log master\n",
            "git init r\ngit -C r branch --move master\ngit -C r log master\n",
            "git init r\ngit -C r branch -f -M master\ngit -C r log master\n",
        ] {
            assert!(!has(text, "master-after-init"), "{text}");
        }
        assert!(has(
            "subprocess.run([\"git\", \"init\"])\nsubprocess.run([\"git\", \"branch\", \"-m\", \"master\", \"trunk\"])\n",
            "master-after-init"
        ));
        // Helper-style inits.
        assert!(has(
            "await git('init')\nawait git('checkout', 'master')\n",
            "master-after-init"
        ));
        assert!(has(
            "await git(['init'])\nawait git(['checkout', 'master'])\n",
            "master-after-init"
        ));
        assert!(has(
            "run_git(\"init\", cwd=d)\nrun_git(\"checkout\", \"master\", cwd=d)\n",
            "master-after-init"
        ));
        // git config set and other option spellings pin the file.
        for text in [
            "git config set --global init.defaultBranch master\ngit init r\ngit -C r log master\n",
            "git config --global --replace-all init.defaultBranch master\ngit init r\ngit -C r log master\n",
            "git config -f ~/.gitconfig init.defaultBranch master\ngit init r\ngit -C r log master\n",
            "git config --global init.defaultBranch \"$BRANCH\"\ngit init r\ngit -C r log master\n",
        ] {
            assert!(!has(text, "master-after-init"), "{text}");
        }
        assert!(has(
            "git config --get init.defaultBranch\ngit init r\ngit -C r log master\n",
            "master-after-init"
        ));
        // A continuation line starting with -- is code.
        assert!(!has(
            "git init \\\n  --initial-branch=main \\\n  repo\ngit -C repo log master\n",
            "master-after-init"
        ));
        // -am and escaped quotes in messages.
        assert!(!has(
            "git init r\ngit -C r commit -am \"merge master into dev\"\n",
            "master-after-init"
        ));
        assert!(!has(
            "git init r\ngit -C r commit -m \"say \\\"hi\\\" to master\"\n",
            "master-after-init"
        ));
    }

    #[test]
    fn master_after_init_round_three_codex() {
        // branch -m takes branch names, not messages.
        assert!(has(
            "git init r\ngit -C r branch -m \"master\" main\n",
            "master-after-init"
        ));
        // A separator inside a message does not split the command.
        assert!(!has(
            "git init r\ngit -C r commit -m \"merge master; cleanup\"\n",
            "master-after-init"
        ));
        // A trailing flag is not the new name.
        assert!(!has(
            "git init r\ngit -C r branch -M master --force\ngit -C r log master\n",
            "master-after-init"
        ));
        // An argument list broken across lines.
        assert!(has(
            "subprocess.run([\"git\",\n                \"init\"])\nsubprocess.run([\"git\", \"checkout\", \"master\"])\n",
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
