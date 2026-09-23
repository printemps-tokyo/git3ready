//! git3ready -- find what assumes Git 2.x defaults before Git 3.0 changes
//! them, and rehearse the new defaults today.
//!
//! # The problem
//!
//! Git's `Documentation/BreakingChanges.adoc` lists what the next breaking
//! release, Git 3.0, changes: new repositories default to SHA-256 object ids
//! (64 hex digits, not 40), to the reftable ref backend (no `.git/refs/` files,
//! no `packed-refs`), and to a branch named `main`; `safe.bareRepository`
//! defaults to `explicit`; and a handful of commands, options and files are
//! removed. The document also says there is no planned release date.
//!
//! None of that breaks Git itself. It breaks the code around Git: the regex
//! that validates a 40-digit commit id, the deploy script that reads
//! `.git/HEAD`, the test helper that runs `git init` and then checks out
//! `master`, the hook that compares against forty zeros.
//!
//! # What it does
//!
//! - [`matcher`] + [`scan`]: a textual scan of a tree for those assumptions,
//!   each hit tied to one rule in [`rules`] and one item of the source document.
//! - [`env`]: what the installed Git and the current repository will do.
//! - [`rehearse`]: run any command with the new defaults switched on through
//!   `GIT_CONFIG_COUNT`, so the test suite shows what actually breaks.
//!
//! # Shape
//!
//! [`matcher::Matcher`], [`report::Report::build`], [`env::evaluate`] and
//! [`rehearse::plan`] are pure. [`scan::scan_tree`] and [`env::gather`] are the
//! only code that reads the filesystem or runs Git. No network access happens
//! at any point.

pub mod env;
pub mod json;
pub mod matcher;
pub mod rehearse;
pub mod report;
pub mod rules;
pub mod scan;

pub use matcher::{FileScan, Finding, Matcher, IGNORE_MARKER};
pub use report::{render_json, render_text, RenderOptions, Report};
pub use rules::{Category, Rule, Severity, RULES};
pub use scan::{scan_tree, ScanOptions, ScanStats};
