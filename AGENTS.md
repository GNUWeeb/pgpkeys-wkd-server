# Repository Guidelines

## Project Overview

`pgpkeys-wkd-server` is a small HTTP server that serves GNUWeeb members' OpenPGP public keys via Web Key Directory (WKD, direct method), so `gpg --locate-key user@gnuweeb.org` works. Keys are not stored locally: they are pulled from the GitHub repo `GNUWeeb/pgpkeys` (`map.txt` + `keys/<FINGERPRINT>.asc`) into memory and refreshed by a GitHub push webhook. License: GPL-2.0.

**Status: legacy code, rewrite planned.** The Node implementation described below is to be replaced by a Go rewrite named `matcha`. `ROADMAP.md` holds the plan and the settled decisions; read it before any feature work and treat it as the authority on direction. Until the rewrite lands, the sections below describe the code as it is today:

- Do not add features to the Node code or migrate its tooling; changes to `src/` are limited to what the user explicitly asks for.
- Do not start a roadmap phase unasked.
- Update this file in the same change that makes any part of it wrong, and record new decisions in `ROADMAP.md`, not here.

## Architecture & Data Flow

Single process, no database, no disk state. All state is one in-memory map.

```
index.ts -> Server.start() -> WKDEntryManager.loadKeys(true) -> register @fastify/compress -> registerRoutes() -> listen
```

**Key load** (`WKDEntryManager.loadKeys(force, commitHash?)`):

1. Resolve the commit SHA: `api.github.com/repos/<REPOSITORY>/branches/<BRANCH>` (unauthenticated), unless the webhook passed one.
2. Fetch `raw.githubusercontent.com/<REPOSITORY>/<sha>/map.txt`, parse with `mapItemRegex` (`U: <uid>` / `W: <wkdHash>` / `P: <file>` lines), keep only UIDs matching `emailRegex` (`@<EMAIL_DOMAIN>`).
3. Fetch each `keys/<file>` (sends `If-None-Match` with the stored ETag unless `force`), parse with `openpgp.readKey`.
4. Store as `Map<wkdHash, PubKeySet>`; `PubKeySet` is a `Set<{ data: PublicKey, etag }>`.

The server never computes WKD hashes; it trusts the `W:` values in `map.txt`.

**Routes** (all in `src/server.ts`, all under `/.well-known/openpgpkey`):

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/policy` | Empty body (WKD Update Protocol is not implemented) |
| HEAD | `/hu/:wkdHash` | 200 or 404 |
| GET | `/hu/:wkdHash` | `application/octet-stream`, all keys of the entry concatenated newest-first, `X-Fingerprints` header; 404 on miss |
| POST | `/internal/updateHook` | GitHub push webhook (`src/lib/util/updateHook.ts`) |

**Webhook flow**: validate headers (`content-type` exactly `application/json`, `x-github-event: push`, delivery ID, `x-hub-signature-256`) -> HMAC-SHA256 over `JSON.stringify(body)` with `WEBHOOK_SECRET` -> check `ref` is `refs/heads/<BRANCH>` -> if any commit modified `map.txt`, full `loadKeys(false, body.after)`; otherwise per-key remove/modify for changed `keys/*` files. Response is `{ ok, actions: [...] }` or `{ ok: false, error }` with 400/401.

**Known defects (do not rely on this behavior; fix only when asked, since this code is slated for removal):**

- `WKDEntryManager.updatePubKey` re-adds `oldPubKey` instead of `newPubKey`, so a "modify" webhook reports the new key but the store keeps the old one.
- `loadKeys` only adds/replaces entries; entries removed from `map.txt` stay in memory until restart.
- `mapItemRegex` is a module-level `/g` regex; a throw inside the `exec` loop leaves a stale `lastIndex`.
- `emailRegex` interpolates `EMAIL_DOMAIN` unescaped.
- Signature comparison uses `===`, not `crypto.timingSafeEqual`, and hashes re-serialized JSON rather than the raw body.
- One unparsable key file or a `map.txt` entry without `P:` lines rejects the whole load.

## Key Directories

- `src/` - all source. `src/lib/` holds the domain classes, `src/lib/util/` holds stateless helper functions.
- `dist/` - `tsc` output, gitignored, required by `pnpm start`.
- `.github/workflows/` - CI (lint + compile) and release image build.

There is no `scripts/`, `docs/` or test directory (`eslintConfig.ignorePatterns` mentions `scripts/*`, which does not exist).

## Development Commands

```bash
pnpm install            # install dependencies
pnpm run lint           # eslint . --ignore-path .gitignore --ext .ts
pnpm run lint:fix       # same, with --fix
pnpm run compile        # tsc --build tsconfig.json -> dist/ (also the only typecheck)
pnpm run build          # lint && compile (what Docker and CI rely on)
pnpm run start:dev      # compile && start
pnpm start              # node dist/index.js (needs a prior compile)
```

Running needs a `.env` (copy `.env.example`). `WEBHOOK_SECRET` is mandatory: `src/constants.ts` throws at import time without it. Startup performs live requests to GitHub, so it needs network access.

Docker: `docker run -d -p 3000:3000 --env-file .env ghcr.io/gnuweeb/pgpkeys-wkd-server:latest`. The final stage copies from `/tmp/build`, which the `Dockerfile` never sets; it depends on the `ghcr.io/hazmi35/node` base image's working directory.

## Code Conventions & Common Patterns

- **Formatting**: 4-space indent, double quotes, semicolons, no trailing commas, lines up to ~120 columns. Style is enforced only by ESLint (`@hazmi35/eslint-config/typescript`, configured inline in `package.json`); there is no Prettier or EditorConfig.
- **Modules**: ESM (`"type": "module"`, `module: Node16`). Relative imports MUST carry the `.js` extension: `import { Server } from "./server.js";`. No path aliases, no JSON imports (`resolveJsonModule: false`).
- **Naming**: class files PascalCase (`WKDEntryManager.ts`, `PubKeySet.ts`); function/util files camelCase, one exported function per file named like the file (`fetchContent.ts`, `verifySignature.ts`). Constants camelCase.
- **Class style**: explicit `public`/`private` modifiers and explicit return types on every method; short accessors written on one line. Domain containers extend built-ins (`WKDEntryManager extends Map`, `PubKeySet extends Set`) rather than wrapping them.
- **State**: the only mutable state is `Server.wkd`. Utilities receive it as a parameter (`updateHook(req, res, wkd)`); there is no DI container and no global singleton.
- **Config**: read `process.env` only in `src/constants.ts` (which also loads `dotenv/config`) and import the named constants elsewhere. Shared regexes live there too.
- **Errors**: library code throws plain `Error` with a descriptive message; there is no `try/catch` in `src/`. Route handlers return early with `res.status(n).send({ ok: false, error })`. `fetchContent` returns `null` for anything but 200/304. Uncaught exceptions and unhandled rejections are logged and exit the process (`src/index.ts`).
- **Async**: `async/await`; `Promise.all` for parallel key fetches; no timeouts or retries on `fetch`.
- **Logging**: Fastify's pino logger only (`server.fastify.log`, `req.log`); no `console.*`.
- **Lint suppressions**: narrow, single-line, with a reason (`// @ts-expect-error False positive ...`, `// eslint-disable-next-line <rule>`).
- **TypeScript**: `strict: true`, target ES2022. `importHelpers` + `noEmitHelpers` are on while `tslib` is not a runtime dependency, so avoid syntax that needs emit helpers (e.g. decorators).

## Important Files

- `ROADMAP.md` - plan for the rewrite: goal, decisions, kernel.org reference model, WKD behaviour, phases, open items.
- `src/index.ts` - entry point: process signal/exception handlers, `server.start(port, host)`.
- `src/server.ts` - `Server` class: Fastify instance, route registration, start/close.
- `src/constants.ts` - environment config and `map.txt` regexes.
- `src/lib/WKDEntryManager.ts` - key store, `map.txt` parsing, GitHub URL builders.
- `src/lib/PubKeySet.ts` - per-entry key set, `combineBinary()` builds the response body.
- `src/lib/util/updateHook.ts` - webhook handler; `verifySignature.ts`, `fetchContent.ts` - helpers.
- `.env.example` - `PORT`, `HOST`, `REPOSITORY`, `BRANCH`, `EMAIL_DOMAIN`, `WEBHOOK_SECRET` (defaults for all but the last are in `src/constants.ts`).
- `package.json` - scripts and inline `eslintConfig`. `tsconfig.json` is JSONC (contains comments).
- `Dockerfile`, `.github/workflows/lint-compile.yml`, `.github/workflows/build-release.yml`.

`README.md` gives the webhook path as `/internal/updateHook`; the real route is `/.well-known/openpgpkey/internal/updateHook` (the README assumes a reverse proxy mapping that prefix).

## Runtime/Tooling Preferences

- Node.js 18+ (README; Docker uses a floating `lts` image, typings are `@types/node` 20). Not Bun or Deno.
- pnpm 8 only (`pnpm-lock.yaml`, lockfile v6). Newer pnpm refuses the lockfile (`ERR_PNPM_BROKEN_LOCKFILE` with pnpm 12); when the installed pnpm is newer, run pnpm 8 through npx: `npx -y pnpm@8.15.9 install --frozen-lockfile`, then `npx -y pnpm@8.15.9 run build`. Do not regenerate the lockfile, and do not add `package-lock.json` or `yarn.lock`. No `engines` or `packageManager` field enforces this.
- Stack: `fastify` 4, `@fastify/compress`, `openpgp` 5, `node-fetch` 3, `dotenv`. Prefer these over adding dependencies.
- Default branch `master`; release tags are bare semver (`1.0.1`).
- Hosting: `origin` is `git.gnuweeb.net/GNUWeeb/pgpkeys-wkd-server` (GitLab). There is no `.gitlab-ci.yml`. The GitHub workflows in `.github/` and the `ghcr.io` image they publish on a GitHub release are leftovers from GitHub hosting, and `README.md` still gives the GitHub clone URL.

## Testing & QA

- There are no tests, no test framework and no coverage target. Do not claim tests were run.
- The verification gate is `pnpm run build` (lint + typecheck); it must pass before a change is done. Run it locally: no CI runs on GitLab. (`lint-compile.yml` delegates to the external reusable workflow `Hazmi35/workflows/.github/workflows/pnpm-eslint-typescript.yml@master` and only ever ran on GitHub.)
- For behavior changes, smoke-test manually: `pnpm run start:dev`, then `curl -i localhost:3000/.well-known/openpgpkey/hu/<wkdHash>` (take a `W:` value from `map.txt` in `GNUWeeb/pgpkeys`) and `curl -i localhost:3000/.well-known/openpgpkey/policy`.
- If tests are added, mock GitHub (`fetch`) rather than hitting the network, and bind to loopback on port 0.

## Git Commit Rules

Apply to every commit.

### Scope and timing

- Atomic commits: one self-contained logical change each. No commit may leave the tree known-broken (`pnpm run build` passes at every commit), so `git bisect` stays usable.
- Commit as soon as a logical unit builds. Uncommitted changes in the working tree must only ever belong to the next single commit. Refactoring, implementation and docs for one feature are separate commits, made in turn.
- Gate every commit on the build result with `&&` or `if`, never `;`: `pnpm run build && git commit -s ...`.

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
# resolve conflicts, if any; then: pnpm run build
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

The merged tree passes "pnpm run build", and a local instance served
the expected keys after replaying push webhooks for a removed entry
and a modified key.

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
- Servers started for checks bind to loopback only, on port 0 or a random high port (`HOST=127.0.0.1 PORT=<port>`), because other agents may run at the same time.
- Stop every process you started, by PID. Never wait on a name pattern (`pgrep -f`, `ps | grep`); poll with `kill -0 "$pid"`.
- No sudo unless the user has permitted it.
- A sub agent's final reply lists its commits, what is done / partly done / deferred and why, what was built and run, and anything it was unsure of. The coordinator treats that as a claim, not proof: review the commits and rebuild before merging, then remove the worktree and branch (`git worktree remove`, `git branch -d`; never force).
