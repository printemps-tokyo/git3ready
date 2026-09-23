# git3ready

Find the scripts, hooks, tests and CI steps that assume Git 2.x defaults
before Git 3.0 changes them, and rehearse the new defaults today.

```console
$ git3ready scan .
BREAK  head-file-read  Reads .git/HEAD as a file
       change: New repositories default to the reftable ref storage format.
       why:    In a reftable repository .git/HEAD is a compatibility stub that always reads "ref: refs/heads/.invalid".
       fix:    git symbolic-ref --short -q HEAD, git branch --show-current, or git rev-parse HEAD.
  scripts/release.sh:3:37  branch=$(sed 's#ref: refs/heads/##' .git/HEAD)
...
Summary: 5 break, 1 risk, 0 info in 4 paths (4 scanned, 0 suppressed)
```

```console
$ sh scripts/release.sh            # today: works
$ git3ready rehearse -- sh -c 'git init -q r && cd r && git commit -q --allow-empty -m x && sh ../scripts/release.sh'
git3ready: rehearsing Git 3.0 defaults: init.defaultObjectFormat=sha256 init.defaultRefFormat=reftable init.defaultBranch=main safe.bareRepository=explicit
cat: .git/refs/heads/.invalid: Not a directory
```

## Why

Git keeps a list of the changes its next breaking release will make:
[`Documentation/BreakingChanges.adoc`](https://github.com/git/git/blob/985b38ca6cdbd04432a7072c790f8ddf9dcc717c/Documentation/BreakingChanges.adoc).
For Git 3.0 it says, among other things:

- new repositories default to the `sha256` object format, so a full object id
  is 64 hex digits instead of 40;
- new repositories default to the `reftable` ref backend, so there are no
  loose ref files, no `packed-refs` and no `.git/logs/`;
- new repositories default to a branch named `main`;
- `safe.bareRepository` defaults to `explicit`, so Git refuses a bare
  repository it only finds by walking up from the current directory;
- `git whatchanged`, `git pack-redundant`, `git name-rev --stdin`, grafts,
  `.git/branches/` and `.git/remotes/`, `core.commentChar=auto` and
  `core.preferSymlinkRefs=true` are removed;
- Rust becomes a required part of building Git.

It also says: "There is no planned release date for this breaking version
yet." git3ready does not guess one.

None of this breaks Git itself. It breaks the code around Git: the regex that
validates a 40-digit commit id, the deploy script that reads `.git/HEAD`, the
test helper that runs `git init` and checks out `master`, the pre-push hook
that compares against forty zeros, the fixture that is a bare repository
committed into the tree.

## Install

Download a binary from the
[releases page](https://github.com/printemps-tokyo/git3ready/releases) (each
archive has a `.sha256` next to it), or build from source:

```sh
cargo install --git https://github.com/printemps-tokyo/git3ready
```

## Usage

### `git3ready scan [PATH]`

Walks the tree (honoring `.gitignore`) and reports every line that assumes a
Git 2.x default. Scripts, CI files, Dockerfiles, Makefiles, source in the
common languages, `.gitconfig` files and extensionless files that start with
`#!` (hooks, `bin/` scripts) are read; `--all-files` reads every text file.

```sh
git3ready scan                     # current directory
git3ready scan --fail-on risk      # also fail CI on risk findings
git3ready scan --only head-file-read --only ref-files-access
git3ready scan --skip git-source-build --exclude 'vendor/'
git3ready scan --json | jq '.findings[] | select(.severity == "break")'
```

Severities:

| Severity | Meaning |
| --- | --- |
| `break` | Fails under the new default, or uses something Git 3.0 removes. |
| `risk` | Likely to fail, but depends on context a text scan cannot see. |
| `info` | Worth a look: works today, needs a change when you upgrade. |

To silence a line, add `git3ready:ignore` to it; name rule ids after the
marker (`git3ready:ignore hex40-pattern`) to silence only those. Paths can go
in a `.git3readyignore` file (gitignore syntax) or `--exclude`.

### `git3ready rehearse -- COMMAND...`

Runs a command with the Git 3.0 defaults switched on for every Git it
spawns, so your own test suite tells you what actually breaks:

```sh
git3ready rehearse -- cargo test
git3ready rehearse -- npm test
git3ready rehearse --without safe-bare-repository -- ./ci/integration.sh
```

It appends four pairs through `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_<n>` /
`GIT_CONFIG_VALUE_<n>` (documented in git-config(1)), after any pairs already
set:

| Aspect (`--without` name) | Setting |
| --- | --- |
| `object-format` | `init.defaultObjectFormat=sha256` |
| `ref-format` | `init.defaultRefFormat=reftable` |
| `default-branch` | `init.defaultBranch=main` |
| `safe-bare-repository` | `safe.bareRepository=explicit` |

`GIT_DEFAULT_HASH` and `GIT_DEFAULT_REF_FORMAT` override the config keys, so
they are removed from the command's environment. The exit status is the
command's own (127 if it cannot be started).

To apply the same environment in CI without wrapping each command:

```yaml
- run: git3ready rehearse --print env >> "$GITHUB_ENV"
- run: cargo test
```

Or in a shell: `eval "$(git3ready rehearse --print sh)"`.

What a rehearsal cannot show:

- Removed commands still exist in the Git you have installed.
- A clone takes its object format from the remote, not from the default.
- An explicit `git -c key=value` wins over the environment, and a test that
  writes its own config file or clears the environment opts out.
- Rehearsing the ref format needs a Git with the reftable backend, which
  Git 2.45 introduced (`git init --ref-format=reftable`, per its release
  notes). The tests were run against Git 2.52.0.

### `git3ready env`

Reports how the installed Git and the current repository will behave:
which of the defaults above are unset (and will change), which are pinned,
and whether anything Git 3.0 removes is in use (`core.commentChar=auto`,
`core.preferSymlinkRefs`, `GIT_GRAFT_FILE`, an `info/grafts` file, a
non-empty `branches/` or `remotes/` directory). For `safe.bareRepository`
only system, global and command-line values count, because Git ignores a
repository's own setting for it.

```console
$ git3ready env
git3ready env  (git version 2.52.0)

  OK     init.defaultBranch        set to master (global config); new repositories keep this name
  INFO   init.defaultObjectFormat  unset: new repositories use sha1 today and sha256 under Git 3.0
                                   fix: Rehearse with git3ready rehearse -- <test command>, or pin sha1 with git config --global init.defaultObjectFormat sha1
  ...
```

### `git3ready rules`

Lists every rule with its severity and the change it tracks. `--json` for
tooling.

## Rules

| Rule | Severity | Looks for |
| --- | --- | --- |
| `hex40-pattern` | break | A hex class repeated exactly `{40}` (also `[[:xdigit:]]`, `\h`, BRE `\{40\}`), unless the same line also accepts 64 |
| `hex40-upper-bound` | risk | `{n,40}`: abbreviations pass, full sha256 ids do not |
| `oid-fixed-width` | risk | Length checks, slices and column widths of 40 chars / 20 bytes, on a line that names a sha, oid, commit or rev |
| `sha1-constant-oid` | break | The SHA-1 empty tree and empty blob ids, and forty zeros next to a Git-flavored word |
| `sha1-object-hashing` | risk | A SHA-1 call within three lines of a `"blob "` / `"tree "` / `"commit "` header |
| `ref-files-access` | break | `.git/refs/`, `packed-refs`, `.git/logs/`, also via `$GIT_DIR` and `path.join(".git", "refs")` |
| `head-file-read` | break | `.git/HEAD` read as a file |
| `master-after-init` | break | `master`, within 30 lines after a `git init` that does not choose a branch |
| `embedded-bare-repo` | break | A directory in the tree that Git would treat as a bare repository |
| `bare-repo-implicit` | risk | `cd x.git`, `git -C x.git`, `cwd: "x.git"` |
| `git-whatchanged` | break | `git whatchanged` |
| `git-pack-redundant` | break | `git pack-redundant` |
| `name-rev-stdin` | break | `git name-rev --stdin` (not `--annotate-stdin`) |
| `grafts-file` | break | `info/grafts`, `GIT_GRAFT_FILE` |
| `legacy-remote-dirs` | break | `.git/branches/`, `.git/remotes/` |
| `comment-char-auto` | break | `core.commentChar` / `core.commentString` set to `auto` |
| `prefer-symlink-refs` | break | `core.preferSymlinkRefs` set to true |
| `git-source-build` | info | Git source tarballs, a clone of git/git, `NO_RUST` / `WITH_RUST` / `-Drust=` |

## Where the facts come from

- Every rule maps to one item of `BreakingChanges.adoc` at git/git commit
  [`985b38c`](https://github.com/git/git/blob/985b38ca6cdbd04432a7072c790f8ddf9dcc717c/Documentation/BreakingChanges.adoc),
  the latest change to that file when it was read on 2026-09-23. `git3ready
  rules` and every report print that commit and date.
- What a reftable repository looks like on disk (`.git/HEAD` reading
  `ref: refs/heads/.invalid`, `.git/refs/heads` being a file, no `.git/logs/`)
  and that `git -C` into a bare repository fails with
  `safe.bareRepository=explicit` were observed with Git 2.52.0 while writing
  the rules; the tests repeat both against the Git on the machine running them.
- The bare-repository test mirrors `is_git_directory()` in git/git `setup.c`:
  a valid `HEAD`, an `objects` directory and a `refs` entry.
- The null-id recipe in the `sha1-constant-oid` fix is the one Git's own
  sample `pre-push` and `update` hooks use.

## Limits

- Matching is textual. git3ready does not parse your code, so hits in
  comments, documentation and vendored or generated files are reported like
  any other; that is what `--exclude`, `.git3readyignore` and the inline
  marker are for. In exchange it works on shell, YAML, SQL and every language
  at once.
- `master-after-init` only sees a `git init` in the same file. A helper that
  creates repositories in one file and a test that checks out `master` in
  another are not connected; `git3ready rehearse` is how you catch those.
- A repository that already exists keeps its format and branch. The scan is
  about code that creates repositories or handles ids generically; a script
  that only ever runs in one existing SHA-1 repository may be fine.
- This is a readiness aid, not a statement about when Git 3.0 ships or what
  it will finally contain. The source document can change; check it before
  acting on a finding.

## Exit codes

| Code | `scan` / `env` | `rehearse` |
| --- | --- | --- |
| 0 | Nothing at or above `--fail-on` (default `break`) | The command's own status |
| 1 | At least one finding / check at or above it | |
| 2 | Usage or I/O error | Usage error |
| 127 | | The command could not be started |

## License

MIT
