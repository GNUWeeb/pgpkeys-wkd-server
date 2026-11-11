# Repository Guidelines

## Project Overview

`matcha` (formerly `pgpkeys-wkd-server`) serves GNUWeeb members' OpenPGP public keys through Web Key Directory (WKD, direct method), so `gpg --locate-key user@gnuweeb.org` works, and gives members a dashboard at `pgp.gnuweeb.org` where they log in by mailed link and manage their own keys. License: GPL-2.0.

**Status: phases 1 to 7 and 9 of `ROADMAP.md` are implemented in this repository (phase 8 is deferred); the production deployment (DNS, TLS, nginx, SMTP credentials) is pending on the servers.** `ROADMAP.md` holds the plan and the settled decisions; read it before any feature work and treat it as the authority on direction.

- Do not start a roadmap phase unasked.
- Update this file in the same change that makes any part of it wrong, and record new decisions in `ROADMAP.md`, not here.

## Architecture & Data Flow

One process, two HTTP listeners, one SQLite database:

```
cmd/matcha/main.go: config.Load(os.Getenv) -> store.Open(DATABASE_PATH) -> web.New(..., mail.New(SMTP)) -> reminder loop in a goroutine -> one http.Server per listener -> serve() until SIGINT/SIGTERM -> graceful Shutdown -> wait for the reminder loop and for login mails in flight
```

- **WKD listener** (`WKD_ADDR`, `wkd.NewHandler`): `GET`/`HEAD /.well-known/openpgpkey/hu/<hash>` returns the WKD views of every key stored under that hash, concatenated newest first (key creation time), as `application/octet-stream`; 404 when there is none or the hash is malformed. `?l=` is ignored. `GET /.well-known/openpgpkey/policy` is one comment line. Only the nginx in front of `gnuweeb.org` is meant to reach this listener.
- **Dashboard listener** (`DASHBOARD_ADDR`, `web.New`, chi router): login by mailed link, then the member's keys: list (`GET /`), add (`GET /keys/new`, `POST /keys`, pasted text or a file), remove with a confirmation page (`GET`/`POST /keys/{fpr}/remove`), and the member's web of trust (`GET /trust`). Static files under `/static/` sit outside the CSRF and session middleware, so they set no cookies.

`serve()` runs the servers in an `errgroup`; if one fails to listen, all are shut down and the process exits non-zero.

**Keys** (`internal/keys`, go-crypto's v2 API `openpgp/v2`): `keys.Parse(input, address, now)` accepts armored or binary input up to 1 MiB holding exactly one public key with a self-signed, unrevoked User ID whose address matches (case-insensitively); secret keys are refused. The key must also pass the usability rule at `now`, with the address's User ID self-signed with an accepted hash; a revoked key is accepted so its revocation gets published. A refusal by the rule is a `*keys.Unusable` carrying the `Problem`. It returns the key as uploaded (binary) and its **WKD view**, built from the raw packets: signatures after a User ID or User Attribute are kept only when the primary key issued them, identities left without a signature are dropped, signatures on the primary key and subkeys are kept (so designated-revoker revocations reach clients), and trust, marker and other packets are dropped. All User IDs stay, as on kernel.org.

**Key health** (`health.go`): `keys.Check(data, now)` applies kernel.org's usability rule (what `sq` accepts) through go-crypto's policy (`policy`): a key is usable when its primary key is valid and at least one key may sign; self-signatures with MD5, SHA-1 or RIPEMD-160 do not count; DSA, ElGamal, RSA under 2048 bits and refused curves cannot sign. It returns `Usable`, `SigningUntil` (the latest end of a usable signing key, each capped by the primary key's expiry, as kernel.org's `pgpkey-expiry.py` computes it) and `Problems`, each with the fix and the GnuPG commands. go-crypto caches each signature's verdict in the parsed key, including expiry at the time asked, so `Check` reads the key three times and asks each copy one kind of question; keep it that way. `permissive` (in `keys.go`) judges signatures without any algorithm policy, for listing User IDs. GnuPG 2.4 keeps the hash of a self-signature it replaces, so the commands that repair a weak hash pass `--cert-digest-algo SHA512`.

**Certifications** (`certs.go`): `keys.Certifications(data, signers, now)` returns the third-party certifications on a key's User IDs made by one of `signers` (stored keys), keeping those that verify, pass the hash policy, have not expired and are not revoked by a later revocation from the same signer; certifications by other keys are only counted. It matches issuers by fingerprint or key ID before reading a signer, so it reads only the signers it needs.

**Store** (`internal/store`): table `keys`, unique on `(address, fingerprint)`; re-uploading a key replaces it and keeps its row ID. `wkd_hash` is derived from the address inside `PutKey`, never passed in. Addresses are stored as given, so callers normalize them first. `expiry_reminders` holds, per key row (deleted with it), the date and threshold of the last reminder mailed. Schema changes are appended to `migrations` in `store.go` (tracked by `PRAGMA user_version`); never edit a released migration.

**Reminders** (`internal/reminder`): `Loop` runs `Run` at start and then every 24 hours. `Run` checks every stored key and mails its address 30, 10 and 3 days before `SigningUntil` (thresholds in `reminder.go`, the longest is `keys.ExpiryNotice`), once per date and threshold; a new date starts over, a failed mail is retried on the next run, and keys that already cannot sign are only logged.

**Keyring export** (`internal/export`, `matcha export DIR` in `main.go`): `export.Write` puts each stored fingerprint, from its latest upload, into `keys/<FPR>.asc` (armored, as uploaded) or, when its primary key has expired and it is not revoked, `keys/expired/<FPR>.asc`. It rewrites a file only when its bytes differ, removes key files (fingerprint-named `.asc`) of keys no longer stored, and never touches other files. The command needs only `DATABASE_PATH` (`config.DatabasePath`) and refuses a missing database file, since an empty database would export as "remove everything".

**WKD hash** (`wkd.Hash`): the local-part with only ASCII upper case lower-cased, SHA-1, z-base-32; tested against the draft's vector and two kernel.org entries.

**Login** (`internal/web`, see `login.go`):

1. `POST /login` takes an address, which `normalizeAddress` checks (ASCII dot-atom local-part, domain `EMAIL_DOMAIN`) and lower-cases. Every valid address gets the same "check your mail" page: the mail goes out in a goroutine (`sendLink`, tracked by `Server.Wait`), and an address past its limit (5 links per hour, counted in `login_tokens`) silently gets none. A client past 20 requests per hour (in-memory `limiter`, keyed by `REAL_IP_HEADER` or the remote address) gets 429.
2. The mail links to `BASE_URL/login/confirm?token=<43 chars>` (256 random bits). Tokens and session IDs are stored only as SHA-256 hashes (`hashSecret`).
3. `GET /login/confirm` checks the token without using it and shows a button; `POST /login/confirm` uses it (`UseLoginToken`, an atomic `UPDATE ... RETURNING`), so a mail scanner opening the link does not log anyone in. Tokens live 15 minutes and work once.
4. The session cookie `__Host-matcha-session` (`Secure`, `HttpOnly`, `SameSite=Lax`, 7 days) maps to a `sessions` row; `POST /logout` deletes the row.

**CSRF** (`csrf.go`): double submit. A `__Host-matcha-csrf` cookie exists from the first response on; every non-GET request must carry the same value in the `csrf_token` form field or the `X-CSRF-Token` header, else 403. The same middleware caps request bodies at 2 MiB. **Security headers** (`securityHeaders` in `web.go`): strict CSP (`'self'` only, no inline script or style), `Referrer-Policy: no-referrer` (keeps tokens out of Referer), `X-Frame-Options: DENY`, `Cache-Control: no-store`.

**Mail** (`internal/mail`): `net/smtp` with `SMTP_TLS` `starttls` (required, not opportunistic), `implicit` or `none`; `PLAIN` auth when a username is set. Plain-text body, CRLF, header values checked for CR/LF.

**Keys in the dashboard** (`keys.go`): every handler is wrapped in `requireLogin` and takes the address from the session, never from the request, so a member sees and changes only their own keys; another member's fingerprint answers 404 like a missing one. Uploads go through `keys.Parse` with the session address; errors re-render the form with 422, a `*keys.Unusable` with its fix and commands. `keys.Describe` gives the list its fields (User IDs in key order, created, expires, expired, revoked, and the `Health` from `keys.Check`); keys with problems get a "What to fix" notice below the table. Each User ID shows the members whose keys certified it (`keys.Certifications` against every stored key, named by the addresses they are stored for, each linked to its public WKD URL; there is no dashboard page for another member's keys). Success redirects to `/?added=<fpr>` or `/?removed=<fpr>`, which shows the notice.

**Web of trust page** (`trust.go`): the members whose stored keys certified the member's keys, and the members whose stored keys the member's keys certified, grouped by the other key (`ui.TrustLink`). A member's keys certifying each other are left out. It shows only members linked to the session's address; there is no view of the whole directory and no root key (maintainer decision, `ROADMAP.md`). Every request runs `keys.Certifications` over all stored keys, which is fine for a directory of this size.

**Templates** (`internal/web/ui`): templ. Edit the `.templ` files, then run `go tool templ generate` and commit the generated `*_templ.go` files with them; the build does not generate. Every page works without JavaScript; htmx (`hx-boost` on `<body>`) only swaps pages in place. Its config (`htmxConfig` in `layout.templ`) disables eval and inline styles, as the CSP requires, and swaps 4xx/5xx responses so form errors show.

**Static files** (`internal/web/static`, embedded by `assets.go`): `matcha.css` (written here after greentea's look; light and dark by `prefers-color-scheme`; no inline styles anywhere, the CSP forbids them), `favicon.svg`, `htmx.min.js` 2.0.11 (0BSD, `htmx-LICENSE.txt`), Inter and JetBrains Mono `woff2` (OFL, `*-OFL.txt`, the Latin cuts greentea ships). URLs carry `?v=<sha256 prefix>` and are cached for a year; `url("name")` references inside the stylesheet are rewritten to versioned URLs at startup. Do not copy greentea's stylesheet (it has no license).

## Key Directories

- `cmd/matcha/` - the binary: wiring, signal handling, server lifecycle.
- `internal/config/` - settings from the environment.
- `internal/export/` - the keyring export.
- `internal/keys/` - upload checks, the WKD view and the usability rule; `testdata/` holds a DSA key made with GnuPG.
- `internal/mail/` - SMTP client.
- `internal/reminder/` - the daily key check and expiry reminder mails.
- `internal/store/` - SQLite database and migrations.
- `internal/web/` - dashboard handlers and middleware; `internal/web/ui/` - templ components; `internal/web/static/` - embedded CSS, htmx, fonts.
- `internal/wkd/` - WKD hash and HTTP routes.
- `deploy/nginx/` - example nginx server blocks for `gnuweeb.org` (WKD prefix) and `pgp.gnuweeb.org` (dashboard).

There is no `scripts/` or `docs/` directory.

## Development Commands

```bash
go build -o matcha ./cmd/matcha   # build the binary (gitignored)
go vet ./... && go test ./...     # the gate
go tool templ generate            # after editing internal/web/ui/*.templ
go run ./cmd/matcha               # run with settings from the environment
go run ./cmd/matcha export DIR    # write the keyring into DIR (needs DATABASE_PATH)
docker build -t matcha .          # image; podman build works the same
docker compose up -d --build      # the deployment in compose.yaml (needs .env)
```

Configuration is read from the environment only; the binary does not read `.env`. `SMTP_HOST` is required; everything else has a default (`internal/config/config.go`). For a local run: `set -a; . ./.env; set +a; go run ./cmd/matcha`. Docker: `docker run --env-file .env -p 127.0.0.1:8080:8080 -p 127.0.0.1:8081:8081 matcha`. The session and CSRF cookies are `Secure`; browsers accept them on `http://localhost`, other clients may need HTTPS (the tests use `httptest.NewTLSServer`).

## Code Conventions & Common Patterns

- **Formatting**: `gofmt`. Doc comments on every package and exported identifier.
- **Layout**: `cmd/matcha` for the binary, everything else under `internal/`, one package per concern. No global state; dependencies are passed explicitly (constructor arguments or struct fields).
- **Config**: read the environment only in `internal/config` (`config.Load(getenv)`, which takes the lookup function so tests pass a map). Other packages receive values, not `os.Getenv`.
- **Errors**: return errors wrapped with context (`fmt.Errorf("WKD_ADDR: %w", err)`); `main` logs and exits non-zero. No panics for expected failures.
- **Logging**: `log/slog` only, created in `main` and passed down. Never log secrets, tokens or cookies.
- **HTTP**: `net/http` servers with explicit timeouts (`newServer` in `cmd/matcha/main.go`).

## Important Files

- `ROADMAP.md` - plan for the rewrite: goal, decisions, kernel.org reference model, WKD behaviour, phases, open items.
- `cmd/matcha/main.go` - entry point, listeners, graceful shutdown, the `export` command.
- `internal/export/export.go` - `Write`, the keyring layout.
- `internal/config/config.go` - every environment variable and its default.
- `internal/keys/keys.go` - `Parse` and `wkdView`; `health.go` - `Check` and the policy; `certs.go` - `Certifications`; `describe.go` - `Describe`; `packets.go` splits raw packets.
- `internal/reminder/reminder.go` - reminder thresholds, the mail text, `Loop` and `Run`.
- `internal/store/store.go` - `Open` and the migrations; `keys.go` - key queries; `login.go` - tokens and sessions; `reminders.go` - reminder state.
- `internal/web/web.go` - routes, constants (lifetimes, limits), security headers; `login.go`, `keys.go`, `trust.go`, `session.go`, `csrf.go`, `ratelimit.go`, `assets.go`.
- `internal/web/ui/layout.templ` - page frame (bare before login, sidebar after), htmx config; `login.templ`, `keys.templ`, `trust.templ`.
- `internal/wkd/handler.go`, `hash.go` - WKD routes and hash.
- `.env.example` - documented settings; copy to `.env` (gitignored).
- `Dockerfile` - Go build stage, Debian slim runtime, static binary, CA bundle copied from the build stage (for SMTP TLS), non-root user (uid 10001), volume `/var/lib/matcha` for the database; base images pinned by digest.
- `compose.yaml` - the deployment: ports on loopback for the host's nginx, `.env` as settings, `REAL_IP_HEADER=X-Real-IP`, volume `matcha-data`, read-only root file system, no capabilities.
- `deploy/nginx/*.conf` - examples, kept in step with the listeners and with matcha's 2 MiB form cap (`client_max_body_size`). DNS, TLS and the live nginx configuration are maintained by hand on the servers, not here.

## Runtime/Tooling Preferences

- Go 1.27 (`go.mod`); module path `git.gnuweeb.net/GNUWeeb/matcha`. `CGO_ENABLED=0` builds must keep working, so no cgo dependencies.
- Dependencies: `github.com/ProtonMail/go-crypto` (OpenPGP through its v2 API `openpgp/v2`, the one that applies algorithm policy; not the deprecated `golang.org/x/crypto/openpgp`), `modernc.org/sqlite` (pure Go, driver name `sqlite`), `github.com/go-chi/chi/v5`, `github.com/a-h/templ` (library, and the generator as a `tool` in `go.mod`), `golang.org/x/sync`. Prefer the standard library.
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
