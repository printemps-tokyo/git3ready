//! Rolling findings up into a report and rendering it as text or JSON.
//!
//! Everything here is pure: inputs are in-memory findings, output is a
//! `String`. Output is deterministic -- rules in severity-then-table order,
//! locations sorted by path and line, no terminal-width dependence.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::json::quote;
use crate::matcher::Finding;
use crate::rules::{Rule, Severity, CAVEAT, RULES, SOURCE_COMMIT, SOURCE_READ_ON, SOURCE_URL};
use crate::scan::{PathFindings, ScanStats};

/// Rendering switches.
#[derive(Debug, Clone, Copy, Default)]
pub struct RenderOptions {
    pub color: bool,
}

/// A finding with the file it was found in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    pub path: String,
    pub finding: Finding,
}

/// The whole scan result.
#[derive(Debug, Clone)]
pub struct Report {
    pub root_name: String,
    pub stats: ScanStats,
    /// Findings grouped by rule, in report order.
    pub groups: Vec<(&'static Rule, Vec<Located>)>,
}

impl Report {
    pub fn build(root_name: String, files: PathFindings, stats: ScanStats) -> Self {
        let mut by_rule: BTreeMap<&'static str, Vec<Located>> = BTreeMap::new();
        for (path, findings) in files {
            for f in findings {
                by_rule.entry(f.rule).or_default().push(Located {
                    path: path.clone(),
                    finding: f,
                });
            }
        }
        let mut groups: Vec<(&'static Rule, Vec<Located>)> = Vec::new();
        for sev in [Severity::Break, Severity::Risk, Severity::Info] {
            for rule in RULES.iter().filter(|r| r.severity == sev) {
                if let Some(mut locs) = by_rule.remove(rule.id) {
                    locs.sort_by(|a, b| {
                        (&a.path, a.finding.line, a.finding.column).cmp(&(
                            &b.path,
                            b.finding.line,
                            b.finding.column,
                        ))
                    });
                    groups.push((rule, locs));
                }
            }
        }
        Report {
            root_name,
            stats,
            groups,
        }
    }

    /// Number of findings at a severity.
    pub fn count(&self, sev: Severity) -> usize {
        self.groups
            .iter()
            .filter(|(r, _)| r.severity == sev)
            .map(|(_, l)| l.len())
            .sum()
    }

    pub fn total(&self) -> usize {
        self.groups.iter().map(|(_, l)| l.len()).sum()
    }

    /// Distinct files (or directories) with at least one finding.
    pub fn files_with_findings(&self) -> usize {
        let mut paths: Vec<&str> = self
            .groups
            .iter()
            .flat_map(|(_, l)| l.iter().map(|x| x.path.as_str()))
            .collect();
        paths.sort_unstable();
        paths.dedup();
        paths.len()
    }

    /// 1 when any finding is at `fail_on` or worse, otherwise 0.
    pub fn exit_code(&self, fail_on: Severity) -> i32 {
        let failing = self
            .groups
            .iter()
            .any(|(r, l)| r.severity >= fail_on && !l.is_empty());
        i32::from(failing)
    }
}

fn paint(s: &str, code: &str, opts: RenderOptions) -> String {
    if opts.color {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

fn severity_label(sev: Severity, opts: RenderOptions) -> String {
    let (text, code) = match sev {
        Severity::Break => ("BREAK", "1;31"),
        Severity::Risk => ("RISK ", "1;33"),
        Severity::Info => ("INFO ", "1;36"),
    };
    paint(text, code, opts)
}

fn location(l: &Located) -> String {
    if l.finding.line == 0 {
        l.path.clone()
    } else {
        format!("{}:{}:{}", l.path, l.finding.line, l.finding.column)
    }
}

/// The one-line count summary.
pub fn summary_line(report: &Report) -> String {
    format!(
        "{} break, {} risk, {} info in {} {} ({} scanned, {} suppressed)",
        report.count(Severity::Break),
        report.count(Severity::Risk),
        report.count(Severity::Info),
        report.files_with_findings(),
        if report.files_with_findings() == 1 {
            "path"
        } else {
            "paths"
        },
        report.stats.scanned,
        report.stats.suppressed,
    )
}

/// The provenance line printed under every text report.
pub fn source_line() -> String {
    format!(
        "Rules follow git/git Documentation/BreakingChanges.adoc @ {} (read {}).",
        &SOURCE_COMMIT[..7],
        SOURCE_READ_ON
    )
}

/// The human-readable report.
pub fn render_text(report: &Report, opts: RenderOptions) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "git3ready  {}", report.root_name);
    let _ = writeln!(out);

    if report.groups.is_empty() {
        let _ = writeln!(out, "No Git 3.0 assumptions found.");
        let _ = writeln!(out);
    }

    for (rule, locs) in &report.groups {
        let _ = writeln!(
            out,
            "{}  {}  {}",
            severity_label(rule.severity, opts),
            paint(rule.id, "1", opts),
            rule.title
        );
        let _ = writeln!(out, "       change: {}", rule.category.change());
        let _ = writeln!(out, "       why:    {}", rule.why);
        let _ = writeln!(out, "       fix:    {}", rule.fix);
        let width = locs.iter().map(|l| location(l).len()).max().unwrap_or(0);
        for l in locs {
            let loc = location(l);
            let _ = writeln!(out, "  {loc:<width$}  {}", l.finding.text);
            if let Some(note) = &l.finding.note {
                let _ = writeln!(out, "  {:<width$}  ({note})", "");
            }
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "Summary: {}", summary_line(report));
    let _ = writeln!(out, "{}", source_line());
    let _ = writeln!(out, "{CAVEAT}");
    out
}

fn rule_json(r: &Rule) -> String {
    format!(
        "{{\"id\":{},\"severity\":{},\"category\":{},\"title\":{},\"change\":{},\"why\":{},\"fix\":{}}}",
        quote(r.id),
        quote(r.severity.as_str()),
        quote(r.category.as_str()),
        quote(r.title),
        quote(r.category.change()),
        quote(r.why),
        quote(r.fix)
    )
}

fn source_json() -> String {
    format!(
        "{{\"url\":{},\"commit\":{},\"read_on\":{}}}",
        quote(SOURCE_URL),
        quote(SOURCE_COMMIT),
        quote(SOURCE_READ_ON)
    )
}

/// The machine-readable report.
pub fn render_json(report: &Report) -> String {
    let mut findings = Vec::new();
    for (rule, locs) in &report.groups {
        for l in locs {
            let (line, column) = if l.finding.line == 0 {
                ("null".to_string(), "null".to_string())
            } else {
                (l.finding.line.to_string(), l.finding.column.to_string())
            };
            findings.push(format!(
                "{{\"rule\":{},\"severity\":{},\"category\":{},\"path\":{},\"line\":{line},\"column\":{column},\"text\":{},\"note\":{}}}",
                quote(rule.id),
                quote(rule.severity.as_str()),
                quote(rule.category.as_str()),
                quote(&l.path),
                quote(&l.finding.text),
                l.finding.note.as_deref().map_or("null".into(), quote),
            ));
        }
    }
    let rules_hit: Vec<String> = report.groups.iter().map(|(r, _)| rule_json(r)).collect();
    let s = &report.stats;
    format!(
        "{{\"tool\":\"git3ready\",\"version\":{},\"root\":{},\"source\":{},\"caveat\":{},\"summary\":{{\"break\":{},\"risk\":{},\"info\":{},\"paths\":{},\"files_scanned\":{},\"suppressed\":{},\"skipped\":{{\"kind\":{},\"large\":{},\"binary\":{},\"unreadable\":{}}}}},\"findings\":[{}],\"rules\":[{}]}}\n",
        quote(env!("CARGO_PKG_VERSION")),
        quote(&report.root_name),
        source_json(),
        quote(CAVEAT),
        report.count(Severity::Break),
        report.count(Severity::Risk),
        report.count(Severity::Info),
        report.files_with_findings(),
        s.scanned,
        s.suppressed,
        s.skipped_kind,
        s.skipped_large,
        s.skipped_binary,
        s.skipped_unreadable,
        findings.join(","),
        rules_hit.join(",")
    )
}

/// `git3ready rules` as text.
pub fn render_rules_text(opts: RenderOptions) -> String {
    let mut out = String::new();
    let width = RULES.iter().map(|r| r.id.len()).max().unwrap_or(0);
    let mut last = None;
    for r in RULES {
        if last != Some(r.category) {
            if last.is_some() {
                let _ = writeln!(out);
            }
            let _ = writeln!(
                out,
                "{}  {}",
                paint(r.category.as_str(), "1", opts),
                r.category.change()
            );
            last = Some(r.category);
        }
        let _ = writeln!(
            out,
            "  {}  {:<width$}  {}",
            severity_label(r.severity, opts),
            r.id,
            r.title
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", source_line());
    let _ = writeln!(out, "{SOURCE_URL}");
    out
}

/// `git3ready rules --json`.
pub fn render_rules_json() -> String {
    let rules: Vec<String> = RULES.iter().map(rule_json).collect();
    format!(
        "{{\"tool\":\"git3ready\",\"version\":{},\"source\":{},\"rules\":[{}]}}\n",
        quote(env!("CARGO_PKG_VERSION")),
        source_json(),
        rules.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(rule: &'static str, line: usize) -> Finding {
        Finding {
            rule,
            line,
            column: 1,
            text: "x".into(),
            note: None,
        }
    }

    fn sample() -> Report {
        Report::build(
            "repo".into(),
            vec![
                (
                    "b.sh".into(),
                    vec![f("git-source-build", 3), f("hex40-pattern", 9)],
                ),
                (
                    "a.sh".into(),
                    vec![f("hex40-pattern", 2), f("oid-fixed-width", 4)],
                ),
                ("fx/remote.git/".into(), vec![f("embedded-bare-repo", 0)]),
            ],
            ScanStats {
                scanned: 5,
                ..Default::default()
            },
        )
    }

    #[test]
    fn groups_are_ordered_by_severity_then_table() {
        let r = sample();
        let ids: Vec<&str> = r.groups.iter().map(|(r, _)| r.id).collect();
        assert_eq!(
            ids,
            vec![
                "hex40-pattern",
                "embedded-bare-repo",
                "oid-fixed-width",
                "git-source-build"
            ]
        );
        let paths: Vec<&str> = r.groups[0].1.iter().map(|l| l.path.as_str()).collect();
        assert_eq!(paths, vec!["a.sh", "b.sh"]);
    }

    #[test]
    fn counts_and_exit_codes() {
        let r = sample();
        assert_eq!(r.count(Severity::Break), 3);
        assert_eq!(r.count(Severity::Risk), 1);
        assert_eq!(r.count(Severity::Info), 1);
        assert_eq!(r.total(), 5);
        assert_eq!(r.files_with_findings(), 3);
        assert_eq!(r.exit_code(Severity::Break), 1);

        let only_info = Report::build(
            "r".into(),
            vec![("a".into(), vec![f("git-source-build", 1)])],
            ScanStats::default(),
        );
        assert_eq!(only_info.exit_code(Severity::Break), 0);
        assert_eq!(only_info.exit_code(Severity::Risk), 0);
        assert_eq!(only_info.exit_code(Severity::Info), 1);
    }

    #[test]
    fn text_report_shows_locations_and_provenance() {
        let text = render_text(&sample(), RenderOptions::default());
        assert!(text.contains("BREAK  hex40-pattern"));
        assert!(text.contains("a.sh:2:1"));
        assert!(text.contains("fx/remote.git/"));
        assert!(!text.contains("fx/remote.git/:0"));
        assert!(text.contains("@ 985b38c"));
        assert!(text.contains("no planned release date"));
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn empty_report_says_so() {
        let r = Report::build("r".into(), vec![], ScanStats::default());
        assert!(render_text(&r, RenderOptions::default()).contains("No Git 3.0 assumptions found."));
        assert_eq!(r.exit_code(Severity::Info), 0);
    }

    #[test]
    fn json_has_null_lines_for_directories() {
        let json = render_json(&sample());
        assert!(json.contains("\"path\":\"fx/remote.git/\",\"line\":null,\"column\":null"));
        assert!(json.contains("\"break\":3"));
        let parsed = crate::json::parse(&json).expect("valid json");
        assert!(parsed.get("findings").is_some());
    }

    #[test]
    fn rules_listing_mentions_every_rule() {
        let text = render_rules_text(RenderOptions::default());
        for r in RULES {
            assert!(text.contains(r.id));
        }
        assert!(crate::json::parse(&render_rules_json()).is_ok());
    }
}
