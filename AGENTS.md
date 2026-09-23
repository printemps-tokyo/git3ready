# AGENTS.md

Project instructions for AI coding agents working in this repository.

## What this is

git3ready is an offline Rust CLI with four subcommands: `scan` (textual scan
for code that assumes Git 2.x defaults Git 3.0 changes), `env` (the installed
Git's config and the current repository), `rehearse` (run a command with the
Git 3.0 defaults switched on through `GIT_CONFIG_COUNT`) and `rules`. No
network access at runtime, ever.

## Layout

| Path | Role |
| --- | --- |
| `src/rules.rs` | The rule table and the pinned source document (URL, commit, read date). Data only. |
| `src/matcher.rs` | Pure matching: text in, findings out. Context heuristics live here. |
| `src/scan.rs` | Directory walk, file selection, bare-repository detection. |
| `src/report.rs` | Pure rollup and rendering (text, JSON, rule list). |
| `src/env.rs` | `gather` runs Git; `evaluate` is pure. |
| `src/rehearse.rs` | Pure environment planning for `rehearse`. |
| `src/json.rs` | Local JSON writer/reader, deliberately not serde. |
| `src/main.rs` | Argument parsing and wiring only. |

## Non-negotiables

- Every rule traces to an item of git/git `Documentation/BreakingChanges.adoc`
  at the pinned commit. Never add a rule for a change that is not in it.
- Never state Git behavior that was not checked against a real Git, Git's
  documentation or Git's source. Git 3.0 has no release date; never invent one.
- Matching stays textual. Do not add language parsers.
- Do not add dependencies beyond `anyhow`, `clap`, `ignore` and `regex`
  without justifying why local code is worse.
- No emoji anywhere: code, comments, docs, commit messages.
- All deliverables in English.

## Conventions

- Output is deterministic: sorted everywhere, no terminal-width wrapping.
- Tests that run Git isolate it from the developer's config
  (`GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL`, cleared `GIT_CONFIG_COUNT`).
- Conventional Commits, English, no `Co-Authored-By` trailer.

## Before you finish

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
cargo build --release
./target/release/git3ready scan . --fail-on info
./target/release/git3ready rehearse -- cargo test --all
```

CI runs a newer stable toolchain than the local one, with stricter clippy
lints. Write modern idiomatic Rust (inline format args, `let ... else`,
`is_some_and`) so it stays clean there.
