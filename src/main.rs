//! Command-line entry point for git3ready.

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use git3ready::env;
use git3ready::matcher::Matcher;
use git3ready::rehearse::{self, PrintFormat};
use git3ready::report::{self, RenderOptions, Report};
use git3ready::rules::{Severity, CAVEAT};
use git3ready::scan::{scan_tree, ScanOptions};

const AFTER_HELP: &str = "\
EXIT CODES:
  0  nothing at or above the --fail-on severity
  1  at least one finding (scan) or check (env) at or above it
  2  usage or I/O error
  rehearse exits with the command's own status (127 if it cannot start).

Git 3.0 has no planned release date. Every rule cites
git/git Documentation/BreakingChanges.adoc; see `git3ready rules`.";

/// Find what assumes Git 2.x defaults before Git 3.0 changes them.
#[derive(Parser, Debug)]
#[command(name = "git3ready", version, about, long_about = None, after_help = AFTER_HELP)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Scan a tree for code, scripts and CI steps that break under Git 3.0.
    Scan(ScanArgs),
    /// Check the installed Git's config and the current repository.
    Env(EnvArgs),
    /// Run a command with the Git 3.0 defaults switched on.
    Rehearse(RehearseArgs),
    /// List the rules, their severity and the change each one tracks.
    Rules(RulesArgs),
}

#[derive(clap::Args, Debug)]
#[command(after_help = "\
SUPPRESSION:
  A line containing `git3ready:ignore` is skipped. Name rule ids after the
  marker (`git3ready:ignore hex40-pattern`) to skip only those; any other word
  after the marker makes it skip the whole line. Paths can be listed in a
  .git3readyignore file (gitignore syntax) or passed with --exclude.

Matching is textual, not semantic: hits in comments and docs are reported
like any other.")]
struct ScanArgs {
    /// Directory to scan.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Exit 1 when a finding is at this severity or worse.
    #[arg(long, value_name = "SEVERITY", default_value = "break", value_parser = Severity::parse)]
    fail_on: Severity,

    /// Run only this rule (repeatable).
    #[arg(long, value_name = "RULE")]
    only: Vec<String>,

    /// Skip this rule (repeatable).
    #[arg(long, value_name = "RULE")]
    skip: Vec<String>,

    /// Skip paths matching this gitignore-syntax glob (repeatable).
    #[arg(long, value_name = "GLOB")]
    exclude: Vec<String>,

    /// Scan every text file, not just known script, source and config kinds.
    #[arg(long)]
    all_files: bool,

    /// Emit JSON instead of the human report.
    #[arg(long)]
    json: bool,

    /// Never emit ANSI color codes.
    #[arg(long)]
    no_color: bool,

    /// Print only the one-line summary.
    #[arg(short, long)]
    quiet: bool,
}

#[derive(clap::Args, Debug)]
struct EnvArgs {
    /// Repository (or any directory) to evaluate Git in.
    #[arg(long, value_name = "DIR", default_value = ".")]
    dir: PathBuf,

    /// Exit 1 when a check is at this severity or worse.
    #[arg(long, value_name = "SEVERITY", default_value = "break", value_parser = Severity::parse)]
    fail_on: Severity,

    /// Emit JSON instead of the human report.
    #[arg(long)]
    json: bool,

    /// Never emit ANSI color codes.
    #[arg(long)]
    no_color: bool,
}

#[derive(clap::Args, Debug)]
#[command(after_help = "\
EXAMPLES:
  git3ready rehearse -- cargo test
  git3ready rehearse --without safe-bare-repository -- npm test
  eval \"$(git3ready rehearse --print sh)\"
  git3ready rehearse --print env >> \"$GITHUB_ENV\"

Aspects: object-format (init.defaultObjectFormat=sha256), ref-format
(init.defaultRefFormat=reftable), default-branch (init.defaultBranch=main),
safe-bare-repository (safe.bareRepository=explicit). They are passed through
GIT_CONFIG_COUNT, after any pairs already set, and GIT_DEFAULT_HASH /
GIT_DEFAULT_REF_FORMAT / GIT_DEFAULT_REF_STORAGE_FORMAT are cleared because
they would override them. init.defaultRefFormat is the name released Git
reads; Git's development branch renamed it to init.defaultRefStorageFormat
and keeps the old name as an alias.

Not rehearsed: removed commands still exist in the installed Git, clones keep
their remote's format, and an explicit `git -c` wins over the environment.")]
struct RehearseArgs {
    /// Leave this aspect at today's default (repeatable).
    #[arg(long, value_name = "ASPECT")]
    without: Vec<String>,

    /// Print the environment instead of running a command: sh or env.
    #[arg(long, value_name = "FORMAT", value_parser = PrintFormat::parse, conflicts_with = "command")]
    print: Option<PrintFormat>,

    /// Do not print the banner to stderr.
    #[arg(short, long)]
    quiet: bool,

    /// The command to run, after `--`.
    #[arg(last = true, value_name = "COMMAND", value_parser = clap::value_parser!(OsString))]
    command: Vec<OsString>,
}

#[derive(clap::Args, Debug)]
struct RulesArgs {
    /// Emit JSON.
    #[arg(long)]
    json: bool,

    /// Never emit ANSI color codes.
    #[arg(long)]
    no_color: bool,
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("git3ready: {err:#}");
            std::process::exit(2);
        }
    }
}

fn render_opts(no_color: bool, json: bool) -> RenderOptions {
    // Color is opt-out via the flag, the NO_COLOR convention, or a non-tty.
    RenderOptions {
        color: !no_color
            && !json
            && std::env::var_os("NO_COLOR").is_none()
            && std::io::stdout().is_terminal(),
    }
}

fn run() -> Result<i32> {
    match Cli::parse().command {
        Cmd::Scan(a) => scan(a),
        Cmd::Env(a) => env_cmd(a),
        Cmd::Rehearse(a) => rehearse_cmd(a),
        Cmd::Rules(a) => {
            let out = if a.json {
                report::render_rules_json()
            } else {
                report::render_rules_text(render_opts(a.no_color, false))
            };
            print_flush(&out)?;
            Ok(0)
        }
    }
}

fn print_flush(s: &str) -> Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(s.as_bytes())?;
    out.flush()?;
    Ok(())
}

fn scan(a: ScanArgs) -> Result<i32> {
    if !a.path.is_dir() {
        anyhow::bail!("not a directory: {}", a.path.display());
    }
    let mut matcher = Matcher::new();
    matcher
        .retain(&a.only, &a.skip)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let root_name = a
        .path
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| a.path.display().to_string());

    let opts = ScanOptions {
        all_files: a.all_files,
        exclude: a.exclude.clone(),
    };
    let (files, stats) = scan_tree(&a.path, &opts, &matcher)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("failed to walk {}", a.path.display()))?;
    let report = Report::build(root_name, files, stats);
    let ropts = render_opts(a.no_color, a.json);

    if a.json {
        print_flush(&report::render_json(&report))?;
    } else if a.quiet {
        print_flush(&format!(
            "git3ready: {}  {}\n",
            report.root_name,
            report::summary_line(&report)
        ))?;
        if !report.stats.unreadable.is_empty() {
            eprintln!(
                "git3ready: could not read {} path(s); the scan is incomplete (run without -q to list them)",
                report.stats.unreadable.len()
            );
        }
        eprintln!("{CAVEAT}");
    } else {
        print_flush(&report::render_text(&report, ropts))?;
    }
    Ok(report.exit_code(a.fail_on))
}

fn env_cmd(a: EnvArgs) -> Result<i32> {
    if !a.dir.is_dir() {
        anyhow::bail!("not a directory: {}", a.dir.display());
    }
    let facts = env::gather(&a.dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    let checks = env::evaluate(&facts);
    if a.json {
        print_flush(&env::render_json(&facts, &checks))?;
    } else {
        print_flush(&env::render_text(
            &facts,
            &checks,
            render_opts(a.no_color, false),
        ))?;
    }
    Ok(env::exit_code(&checks, a.fail_on))
}

fn rehearse_cmd(a: RehearseArgs) -> Result<i32> {
    let aspects = rehearse::select(&a.without).map_err(|e| anyhow::anyhow!("{e}"))?;
    // Ask the Git on PATH whether it reads the keys being injected. When there
    // is no Git here (a --print for another machine), say so and go on.
    match Command::new("git").arg("version").output() {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            match rehearse::parse_git_version(&text).filter(|_| out.status.success()) {
                Some(v) => {
                    if let Some(problem) = rehearse::version_problem(&aspects, v) {
                        anyhow::bail!("{problem}");
                    }
                }
                None => eprintln!(
                    "git3ready: could not read the version from `git version`; not checking which settings it supports"
                ),
            }
        }
        Err(_) => eprintln!("git3ready: git not found on PATH; cannot check its version"),
    }

    let plan =
        rehearse::plan(aspects, |k| std::env::var(k).ok()).map_err(|e| anyhow::anyhow!("{e}"))?;

    if let Some(format) = a.print {
        if format == PrintFormat::Env && !plan.unset.is_empty() {
            // KEY=VALUE lines cannot unset anything, so the rehearsal would
            // be silently overridden. Refuse rather than print a half plan.
            anyhow::bail!(
                "{} is set and would override the rehearsal; unset it in that environment, or use --print sh",
                plan.unset.join(", ")
            );
        }
        for w in &plan.warnings {
            eprintln!("git3ready: {w}");
        }
        print_flush(&rehearse::render(&plan, format))?;
        return Ok(0);
    }

    let Some((program, args)) = a.command.split_first() else {
        anyhow::bail!("nothing to run: pass a command after --, or use --print sh|env");
    };
    if !a.quiet {
        eprintln!("{}", rehearse::banner(&plan));
    }
    for w in &plan.warnings {
        eprintln!("git3ready: {w}");
    }
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in &plan.set {
        cmd.env(k, v);
    }
    for k in &plan.unset {
        cmd.env_remove(k);
    }
    let status = match cmd.status() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("git3ready: cannot run {}: {e}", program.to_string_lossy());
            return Ok(127);
        }
    };
    Ok(exit_status_code(status))
}

#[cfg(unix)]
fn exit_status_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

#[cfg(not(unix))]
fn exit_status_code(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}
