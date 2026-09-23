# Contributing

Thanks for your interest in contributing to git3ready.

## Development

1. Fork / clone the repository
2. Install a stable Rust toolchain (https://rustup.rs) and a Git with the
   reftable backend (Git 2.45 or later); the tests run Git
3. Create a branch: `git switch -c feat/your-change`
4. Make your change and verify locally:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo test --all
   cargo build --release
   ./target/release/git3ready scan . --fail-on info
   ./target/release/git3ready rehearse -- cargo test --all
   ```
5. Commit and open a pull request

## Adding or changing a rule

git3ready tells people their code will break under a Git release that does
not exist yet. That is only defensible with a citation, so:

- Every rule must trace back to an item of git/git
  `Documentation/BreakingChanges.adoc`. Quote the item in the pull request.
  A change that is only proposed on the mailing list, or that a blog post
  predicts, is not a rule.
- Any claim about how Git behaves (what a file contains, what an environment
  variable does, what error Git prints) must be checked against a real Git or
  Git's own documentation or source, and the test should repeat the check
  against the Git on the machine running it, as `tests/cli.rs` does for
  reftable and `safe.bareRepository`.
- Add the rule to `RULES` in `src/rules.rs`, the matching to
  `src/matcher.rs`, a row to the rules table in `README.md`, and tests for a
  hit and for a near-miss that must not match. Measure precision on a few real
  repositories before proposing a new pattern; say which ones in the pull
  request.
- Pick the severity honestly. `break` means the code fails under the new
  default; if that depends on context the scan cannot see, it is `risk`.

## Updating the source pin

When `BreakingChanges.adoc` changes, re-read it, update `SOURCE_URL`,
`SOURCE_COMMIT` and `SOURCE_READ_ON` in `src/rules.rs` together, and adjust
or remove any rule whose item changed. Say in the pull request what changed in
the document.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/), in English.
