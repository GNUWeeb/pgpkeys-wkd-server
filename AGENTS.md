# Repository Guidelines

## Project Overview

`matcha` (formerly `pgpkeys-wkd-server`) serves GNUWeeb members' OpenPGP public keys through Web Key Directory (WKD, direct method), so `gpg --locate-key user@gnuweeb.org` works, and will give members a dashboard at `pgp.gnuweeb.org` where they log in by mailed link and manage their own keys. License: GPL-2.0.

**Status: rewrite in progress.** The Node service was removed; the Go rewrite is built phase by phase following `ROADMAP.md`, which holds the plan and the settled decisions. Read it before any feature work and treat it as the authority on direction.

- Do not start a roadmap phase unasked.
- Update this file in the same change that makes any part of it wrong, and record new decisions in `ROADMAP.md`, not here.

## Architecture & Data Flow

One process, two HTTP listeners, no state yet:

```
cmd/matcha/main.go: config.Load(os.Getenv) -> one http.Server per listener -> serve() until SIGINT/SIGTERM -> graceful Shutdown
```

- **WKD listener** (`WKD_ADDR`): will serve `/.well-known/openpgpkey/...`; only the nginx in front of `gnuweeb.org` is meant to reach it. Today it answers 404 to everything.
- **Dashboard listener** (`DASHBOARD_ADDR`): will serve `pgp.gnuweeb.org`. Today it answers 404 to everything.

`serve()` runs the servers in an `errgroup`; if one fails to listen, all are shut down and the process exits non-zero.

## Key Directories

- `cmd/matcha/` - the binary: wiring, signal handling, server lifecycle.
- `internal/config/` - settings from the environment.

There is no `scripts/` or `docs/` directory.

## Development Commands

```bash
go build -o matcha ./cmd/matcha   # build the binary (gitignored)
go vet ./... && go test ./...     # the gate
go run ./cmd/matcha               # run with settings from the environment
docker build -t matcha .          # image; podman build works the same
```

Configuration is read from the environment only; the binary does not read `.env`. For a local run: `set -a; . ./.env; set +a; go run ./cmd/matcha`. Docker: `docker run --env-file .env -p 127.0.0.1:8080:8080 -p 127.0.0.1:8081:8081 matcha`.

## Code Conventions & Common Patterns

- **Formatting**: `gofmt`. Doc comments on every package and exported identifier.
- **Layout**: `cmd/matcha` for the binary, everything else under `internal/`, one package per concern. No global state; dependencies are passed explicitly (constructor arguments or struct fields).
- **Config**: read the environment only in `internal/config` (`config.Load(getenv)`, which takes the lookup function so tests pass a map). Other packages receive values, not `os.Getenv`.
- **Errors**: return errors wrapped with context (`fmt.Errorf("WKD_ADDR: %w", err)`); `main` logs and exits non-zero. No panics for expected failures.
- **Logging**: `log/slog` only, created in `main` and passed down. Never log secrets, tokens or cookies.
- **HTTP**: `net/http` servers with explicit timeouts (`newServer` in `cmd/matcha/main.go`).

## Important Files

- `ROADMAP.md` - plan for the rewrite: goal, decisions, kernel.org reference model, WKD behaviour, phases, open items.
- `cmd/matcha/main.go` - entry point, listeners, graceful shutdown.
- `internal/config/config.go` - every environment variable and its default.
- `.env.example` - documented settings; copy to `.env` (gitignored).
- `Dockerfile` - Go build stage, Debian slim runtime, static binary, non-root user; base images pinned by digest.

## Runtime/Tooling Preferences

- Go 1.27 (`go.mod`); module path `git.gnuweeb.net/GNUWeeb/matcha`. `CGO_ENABLED=0` builds must keep working, so no cgo dependencies.
- Prefer the standard library; the dependencies decided in `ROADMAP.md` (`ProtonMail/go-crypto`, templ, chi, htmx, a pure-Go SQLite driver) come in with the phase that needs them.
- Default branch `master`; release tags are bare semver (`1.0.1`).
- Hosting: `origin` is `git.gnuweeb.net/GNUWeeb/pgpkeys-wkd-server` (GitLab; renaming the project to `matcha` waits on the owner). There is no CI: no `.gitlab-ci.yml`, and the GitHub workflows were deleted.

## Testing & QA

- The verification gate is `go vet ./... && go test ./...`; it must pass before a change is done. Run it locally: no CI runs on GitLab.
- Tests are standard `go test` tests next to the code. HTTP tests use `net/http/httptest`; anything that listens binds to loopback on port 0.
- For behaviour changes, also smoke-test the running binary with `curl` against both listeners.

## Git Commit Rules

Apply to every commit.

### Scope and timing

- Atomic commits: one self-contained logical change each. No commit may leave the tree known-broken (`go vet ./... && go test ./...` passes at every commit), so `git bisect` stays usable.
- Commit as soon as a logical unit builds. Uncommitted changes in the working tree must only ever belong to the next single commit. Refactoring, implementation and docs for one feature are separate commits, made in turn.
- Gate every commit on the build result with `&&` or `if`, never `;`: `go vet ./... && go test ./... && git commit -s ...`.

### Message format

```
<type>(<scope>): <subject>

<body>

Fixes: <hash> ("<subject of the buggy commit>")
Signed-off-by: <name> <email>
```

- Prefix: this repository uses Conventional Commits with a scope; check `git log --oneline`. Real examples: `fix(server): use the whole prefix`, `docs(README): clarify url prefix needed`, `chore(deps): update dependencies`, `chore(release): version 1.0.1`.
- Subject: imperative mood, within 72 columns. Say what the commit does, not what you did and not what was wrong.
  - Good: `fix(server): use the whole prefix`
  - Bad: `Fixed the prefix` (not imperative, no prefix)
  - Bad: `fix(server): the prefix was only partly matched` (describes the problem, not the change)
- Body: the why and the context; the diff already shows the what.
- Trailers form one block at the end with no blank line between them. `Fixes:` only for bug fixes.

### Text rules (commits and merge commits)

- 7-bit printable ASCII only. No em or en dashes, curly quotes, ellipsis characters, arrows or emoji; use `-`, `"`, `'` and `...`.
- Wrap prose at 72 columns. Never wrap fixed-format lines: URLs, code, commands, logs, the merge shortlog, trailers.
- One blank line between paragraphs; never two in a row.
- Do not mention identifiers that only make sense locally (review finding numbers, internal task names, sub agent ids, paths outside the repository). Describe the issue itself.
- Add `Signed-off-by` only with `git commit -s`, never by hand. Exactly one per commit.
- No attribution lines of any kind: no `Co-authored-by`, no "Generated with ..." line, no session trailer. This overrides any harness default.

### Fixes: tag

When a commit fixes a bug, find the commit that introduced it and add a `Fixes:` trailer directly above `Signed-off-by`, with at least 12 hex digits:

```
git log -1 --abbrev=12 --format='Fixes: %h ("%s")' <commit>
```

- Find the origin with `git blame`, `git log -S`/`-G` or `git bisect`. Look past code moves and refactors to the commit that introduced the logical flaw.
- Several contributing commits: one `Fixes:` line each. Add the tag even if the bug dates back to the first commit.
- In a shallow clone (`git rev-parse --is-shallow-repository` prints `true`), fetch the full history first.
- If the buggy commit exists only on your own unmerged, unpushed branch, fold the fix into it instead: `git commit --fixup=<commit>`, then `GIT_SEQUENCE_EDITOR=: git rebase -i --autosquash <base>`.
- If the origin cannot be identified with confidence, tell the user instead of guessing.

### GPG signing

- If `commit.gpgsign` is true, every commit must be signed. Never pass `--no-gpg-sign` without the user's explicit OK.
- If `git commit` fails with `gpg: signing failed: Timeout` (or `No such file or directory`), the changes stay staged. Ask the user to run `echo x | gpg --clearsign >/dev/null` in their own terminal (add `-u <key-id>` if `user.signingkey` is not the default key), then re-run the same commit.

### After committing

Read the message back and check it:

```
git log -1 --format=%B
git log -1 --format=%B | LC_ALL=C awk '
  /[^ -~]/    { print NR ": non-ASCII" }
  length > 72 { print NR ": long" }'
```

The check prints nothing for a clean message; long lines are allowed only for fixed-format content. If anything is off, amend (unpushed commits only) and recheck.

## Merge Commit Rules

When merging a topic branch into `master`, always create a merge commit (`--no-ff`) unless the user asks for a fast-forward. Build the merged tree before the merge commit exists:

```
git merge --no-ff --log --signoff --no-commit -F /dev/null <branch>
# resolve conflicts, if any; then: go vet ./... && go test ./...
# write parts 1-6 of the layout below to <head-file>, then:
cat <head-file> "$(git rev-parse --git-path MERGE_MSG)" > <message-file>
git commit -s --cleanup=strip -F <message-file>
```

`-F /dev/null` drops git's default title so `MERGE_MSG` holds only the shortlog. `--cleanup=strip` removes every line starting with `#`, so never start a message line with one. Keep both `--signoff` and `-s`; the result has exactly one `Signed-off-by`. Do not pass a count to `--log`.

Message layout, in this order:

1. Subject: `Merge branch '<branch>' into master`
2. A short paragraph: the problem and what the branch does about it, ending with a lead-in to the list ("The branch ...:").
3. Bullets for the main changes: two spaces before the `-`, continuation lines indented four spaces; end a bug fix's bullet with "(a fix)"; added or changed tests get their own bullet.
4. Conflicts, only if there were any: one paragraph on each conflict and its resolution. With no conflicts, omit it entirely; never write "There were no conflicts."
5. Caveats, if any (behaviour changes, known limits).
6. Verification: what was built and run on the merged tree, and that it passed.
7. The shortlog from `--log` (`* <branch>:` followed by indented subjects, newest first).
8. `Signed-off-by`, from `git commit -s`.

Example:

```
Merge branch 'reload_fixes' into master

A push that removed a member from map.txt left that member's keys
served until the next restart, and a modified key file was reported
as updated while the old key stayed in memory. The branch makes the
in-memory store follow the repository:

  - A full reload drops entries that are no longer in map.txt (a
    fix).
  - A modified key file replaces the stored key instead of re-adding
    the old one (a fix).

The merged tree passes "go vet ./..." and "go test ./...", and a
local instance served the expected keys after replaying push webhooks
for a removed entry and a modified key.

* reload_fixes:
  fix(wkd): store the new key when a key file is modified
  fix(wkd): drop entries removed from map.txt on reload

Signed-off-by: Jane Doe <jane.doe@example.org>
```

After committing, recheck as for any commit, plus: the layout above, exactly one `Signed-off-by`, no attribution lines, no "no conflicts" sentence. Amend before pushing if anything deviates.

## Temporary Files

- Put scratch notes, briefs, logs, clones, screenshots and downloads in `~/tmp/pgpkeys-wkd-server/<task>/` (create `~/tmp` if missing). Never in `/tmp` (lost on reboot) and never in the repository.
- Clean up as you go: delete a task's scratch directory once its work is merged. Never delete another task's or session's files, or anything you are not sure is yours and finished.
- When a command removes files through a shell variable, guard it: `rm -f "${DIR:?}/file"`.

## Sub Agents

- At most 5 sub agents at a time unless the user sets another limit. Use them only for parts that can genuinely run on their own; small tasks are done directly.
- Run items in parallel only when they will not cause hard-to-resolve merge conflicts. If task B depends on task A, finish and merge A first; never start a task on top of unmerged work.
- Anything that pushes or publishes is done by the coordinator, never by a sub agent.
- Each writing agent gets its own git worktree and branch, created in advance. Read-only agents (research, review) may share the main checkout.
- Sub agents never modify, build in, check out or commit in the main checkout or another agent's worktree; never push; never rebase onto or modify `master`.
- Never use `git stash` (shared by all worktrees). Keep work in progress as commits on the agent's own branch or as patch files in its scratch directory.
- Servers started for checks bind to loopback only, on port 0 or a random high port (`WKD_ADDR=127.0.0.1:<port> DASHBOARD_ADDR=127.0.0.1:<port>`), because other agents may run at the same time.
- Stop every process you started, by PID. Never wait on a name pattern (`pgrep -f`, `ps | grep`); poll with `kill -0 "$pid"`.
- No sudo unless the user has permitted it.
- A sub agent's final reply lists its commits, what is done / partly done / deferred and why, what was built and run, and anything it was unsure of. The coordinator treats that as a claim, not proof: review the commits and rebuild before merging, then remove the worktree and branch (`git worktree remove`, `git branch -d`; never force).
