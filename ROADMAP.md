# Roadmap

Plan for turning `pgpkeys-wkd-server` from a read-only mirror of the `GNUWeeb/pgpkeys` repository into a self-service key directory modelled on kernel.org's key infrastructure. Each phase below states whether it is done. Facts marked "observed" were checked on 2026-11-10; items marked "unverified" must be checked in the phase that needs them.

## Goal

A GNUWeeb member logs in at `https://pgp.gnuweeb.org` with a link mailed to their `@gnuweeb.org` address, adds or removes their own OpenPGP public keys, and `gpg --locate-key user@gnuweeb.org` returns those keys through Web Key Directory (WKD). What the service does with keys follows what kernel development needs: keys that verify signed tags, commits and patches, and that other developers can fetch and trust the way they do for `@kernel.org`.

From the handover (repository owner):

1. New domain `https://pgp.gnuweeb.org` for the dashboard.
2. Login page takes `user@gnuweeb.org`; no password.
3. The dashboard mails a secret link to that address, from `pgp@gnuweeb.org` (SMTP credentials to be provided).
4. The user logs in through the link.
5. The user adds or removes public keys in the dashboard.
6. One private endpoint serves `/.well-known/openpgpkey/hu/<wkd hash>`; the nginx in front of `https://gnuweeb.org` will `proxy_pass` to it.
7. The dashboard follows the design of the webmail (greentea).

Added by the maintainer:

- A rewrite in Go and a self-contained Dockerfile.
- No GitHub Actions; the project lives on `git.gnuweeb.net` (GitLab).
- A rewrite under a new name. Sane WKD compliance rather than full compliance.
- The dashboard is written with htmx.
- kernel.org is the reference for behaviour.

## Decisions

Settled by the maintainer on 2026-11-11:

| Topic | Decision |
| --- | --- |
| Other User IDs in the WKD response | Kept, as kernel.org does. This deviates from section 5 of the WKD draft (see "WKD Behaviour"). |
| `GNUWeeb/pgpkeys` repository | No longer where keys are submitted. The service's database is the source of truth; the repository becomes a generated export (phase 7), committed with signed commits (phase 8). |
| Keys already in `GNUWeeb/pgpkeys` | Not imported. The directory starts empty and members upload through the dashboard. |
| Keys per address | Several allowed; all are served, newest first. |
| Who may log in | Any `@gnuweeb.org` address that receives the link, aliases included. |
| Web of trust | Display only. A key is published whether or not other members certified it. |
| Dockerfile | Self-contained: builds with plain `docker build .`, pinned base images, explicit `WORKDIR`, non-root user. |
| CI | None for now. The gate is the local build; images are built by hand. |
| Dashboard CSS | Written here, reproducing greentea's look. greentea's stylesheet is not copied. |
| Rename | Yes, as part of the rewrite, to `matcha`. Renaming the GitLab project changes the URL given in the handover, so that step needs the owner's agreement. |
| Language | Go, with `github.com/ProtonMail/go-crypto` for OpenPGP and templ, chi and htmx for the dashboard (greentea's stack). Bun and Rust with Sequoia were considered and dropped. |
| Storage | SQLite: one file, no extra service. |
| Key-health checker | Go, in the service, with go-crypto's v2 API and its policy settings (decided 2026-11-11, replacing `sq`). kernel.org runs `sq inspect` (`pgpkey-expiry.py` in `pgpkeys.git`), but `sq` 1.3.1 has no machine-readable output for it, adds a 22 MB binary and its libraries to the image, and its text changes between releases. Accepted cost: the rule follows Sequoia's standard policy as listed in phase 6, not its every date-dependent detail. |
| Go module path | `git.gnuweeb.net/GNUWeeb/matcha`, the URL the project gets once renamed. |
| Listeners | Two addresses: `WKD_ADDR` for the WKD routes, reachable only by the `gnuweeb.org` nginx, and `DASHBOARD_ADDR` for `pgp.gnuweeb.org`. Dashboard routes do not exist on the WKD listener and the reverse. |
| Phase 5 in the repository | Deployment section in `README.md`, example nginx configuration for both hosts, and a `compose.yaml`. DNS, TLS, the nginx changes on `gnuweeb.org` and the production `.env` are done by hand on the servers. |

## Where We Are (observed)

- Phase 1 replaced the Node service (which mirrored `GNUWeeb/pgpkeys` from GitHub into memory) with a Go skeleton; see `AGENTS.md` for the current state.
- WKD for `gnuweeb.org` is not being served: `https://gnuweeb.org/.well-known/openpgpkey/policy` answers 302 to `https://www.gnuweeb.org/...`, which answers 404.
- `openpgpkey.gnuweeb.org` and `pgp.gnuweeb.org` do not resolve.
- `GNUWeeb/pgpkeys` also exists on `git.gnuweeb.net` (imported 2026-06-16). It holds `keys/<FINGERPRINT>.asc`, a generated `map.txt` and `genmap.py`; members add keys by pull request.
- The GitHub workflows were deleted in phase 1; there is no `.gitlab-ci.yml`.

## Reference Model: kernel.org (observed)

**WKD** (fetched for `torvalds@kernel.org` and `gregkh@kernel.org`):

- Direct method only; `openpgpkey.kernel.org` does not resolve.
- `GET` and `HEAD` on `/.well-known/openpgpkey/hu/<hash>` answer 200, `application/octet-stream`, binary.
- `/.well-known/openpgpkey/policy` is one comment line.
- The served key keeps all of its User IDs (three on the `gregkh` key, two on the `torvalds` key), not only the `@kernel.org` one.
- Every signature on the served keys is a self-signature; third-party certifications are not served.
- Published for every account, regenerated about once a day. A member has to add the `@kernel.org` User ID to their key; without it clients report "no valid user IDs".

**Keyring repository** (`pgpkeys.git`):

- `keys/*.asc`: armored keys with all User IDs; `keys/expired/` keeps expired keys so old signatures stay checkable.
- `graphs/`: SVG trust paths to the root key (Linus Torvalds).
- `scripts/`: refresh, weak-hash audit and expiry tooling. Commits are signed, and the refresh script verifies the commit signature before importing.

**Admission (web of trust)**:

- A key enters the keyring only with at least one signature from a key already in it, so every key traces to the root.
- A kernel.org account needs signatures from at least two active account holders.

**Key health**:

- A key counts as usable when `sq` (Sequoia) accepts at least one of its signing (sub)keys. Expired keys, SHA-1 self-signatures, DSA keys and keys with no signing key are rejected.
- Account holders get a reminder 30, 10 and 3 days before their key expires.

**Client side**: developers are told to use GnuPG 2.4 or later, with `auto-key-locate wkd,dane,local`, `auto-key-retrieve` and `trust-model tofu+pgp`. Web of trust is the admission rule; it is not what developers are told to rely on for everyday verification.

## WKD Behaviour

The specification is the Internet-Draft `draft-koch-openpgp-webkey-service` (revision 22, 2026-07-22, individual draft, expires 2027-01-23). It is not an RFC and can still change. Target: key discovery (section 3.1) with the direct method, served the way kernel.org serves it.

| Behaviour | Node service (removed in phase 1) | matcha (phase 2) |
| --- | --- | --- |
| `GET .../hu/<hash>` returns the binary keys for the address, concatenated, newest first | yes | yes, ordered by key creation time |
| `HEAD` on the same URL | yes | yes |
| `application/octet-stream`, not ASCII-armored | yes | yes |
| `.../policy` is served (zero length is enough) | yes | yes, one comment line |
| Hash is z-base-32 of SHA-1 of the local-part with ASCII upper case mapped to lower case | no (trusts `W:` lines in `map.txt`; `genmap.py` does not lower-case) | computed from the address |
| The served key carries a User ID with the requested address | not checked on the key itself | enforced on upload |
| Third-party certifications are not served | no (whole key is served) | stripped from the WKD view |
| Other User IDs on the key | served | served |
| No HTTP 401 below the well-known prefix | webhook route can answer 401 | no such route |
| `?l=<local-part>` query parameter | ignored | ignored |

Known deviation: section 5 of the draft says other User IDs and their binding signatures MUST be removed before publication. kernel.org does not do this, and the same section requires clients to drop the other User IDs themselves.

Out of scope:

- The Web Key Directory Update Protocol (section 4). The dashboard replaces it.
- The advanced method. Clients try `openpgpkey.<domain>` first and fall back to the direct method only when that host has no address, so `openpgpkey.gnuweeb.org` must stay unresolvable and must not be caught by a wildcard record.

Test vector from the draft: local-part `Joe.Doe` hashes to `iy9q119eutrkn8s1mk4r39qejnbu3n5q`.

## Target Shape

One process, one local database, two HTTP surfaces:

- **WKD (private, behind the `gnuweeb.org` nginx)**: `GET`/`HEAD /.well-known/openpgpkey/hu/<hash>` and `GET /.well-known/openpgpkey/policy`.
- **Dashboard (`pgp.gnuweeb.org`)**: login, magic-link landing, key list, add key, remove key, logout.

The store keeps each key as submitted, including third-party certifications (needed for the web of trust display and the keyring export). The WKD response is a derived view without them. The GitHub fetching code, `map.txt` parsing and the webhook are deleted.

## Phases

Each phase is merged on its own and leaves the tree building. `AGENTS.md` and `README.md` are updated in the phase that makes them wrong. Phases 1 to 5 deliver the handover; 6 to 9 are the kernel.org-style additions.

Current scope (maintainer, 2026-11-11): phases 6, 7 and 9, after phases 1 to 5. Deferred by the maintainer on 2026-11-11: the production part of phase 5 and all of phase 8.

### 1. Tooling and rename

- Start a Go module named `matcha`; the service is rewritten, not ported.
- Remove the Node toolchain: `package.json`, `pnpm-lock.yaml`, `tsconfig.json`, `src/`. Done together, rather than keeping `src/` until phase 2: production does not route WKD to the Node service, and the sources cannot build without the toolchain.
- Apply the new name: module, binary and image name, `README.md`, `AGENTS.md`.
- Rewrite the `Dockerfile` as decided above: Go build stage, Debian runtime stage, static binary.
- Delete `.github/`.
- Local gate replacing `pnpm run build`: `go vet` and `go test`.

Done when: the image builds with `docker build .` and the container starts.

Status: done 2026-11-11. The image was built with `podman build .` (the Docker daemon was not running on the build machine; the Dockerfile uses nothing Podman-specific) and the container answered on both ports as uid 10001.

### 2. Key store and WKD

- Storage layer for keys, indexed by address and WKD hash; several keys per address.
- Upload-time checks: public key material only, a User ID with the member's address, a size cap.
- WKD routes served from the store as in the table above.
- Remove the `pgpkeys` sync and the webhook (done in phase 1 with the Node sources).
- First automated tests: the draft's hash vector, the WKD view (no third-party certifications), several keys for one address, `GET`/`HEAD`/404, policy.

Done when: `gpg --auto-key-locate wkd --locate-keys` against a local instance returns the key, with a fresh `GNUPGHOME`.

Status: done 2026-11-11. In containers on one network, nginx with a test CA served `https://gnuweeb.test/.well-known/openpgpkey/` from the image, `openpgpkey.gnuweeb.test` did not resolve, and GnuPG 2.4 in a fresh `GNUPGHOME` (`--auto-key-locate clear,wkd,nodefault --locate-keys alice@gnuweeb.test`) imported the key. The uploaded key carried a certification by a second key and two User IDs; the served bytes held both User IDs and only self-signatures. Decided here: an upload is stored dearmored but otherwise byte for byte; the WKD view is cut from those raw packets, not re-serialized by `go-crypto`, whose `Entity.Serialize` would emit User IDs in map order and drop User Attributes. Upload cap 1 MiB.

### 3. Login by mailed link

- Request form accepts any address in the configured domain and always answers the same way, so it does not reveal which addresses exist.
- Token: random, at least 128 bits, stored hashed, single use, short lifetime; per-address and per-client rate limits.
- The link opens a confirmation page and the token is consumed by a `POST`, so mail scanners that prefetch links do not burn it.
- Session cookie with the `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Lax`; CSRF token on every state-changing request.
- Mail is sent from `pgp@gnuweeb.org` over SMTP. Credentials live only in `.env` (gitignored) and are never committed or logged.

Done when: a login round trip works against a local SMTP catcher, and expired, reused and forged tokens are rejected by tests.

Status: done 2026-11-11. In containers, nginx with a test CA proxied `https://pgp.gnuweeb.test` to the image, which mailed through Mailpit with STARTTLS and `AUTH PLAIN` (and, in a second run, implicit TLS); with curl the link page answered 200 without using the token, the `POST` logged in with a `__Host-matcha-session` cookie (`Secure; HttpOnly; SameSite=Lax`), reusing the token answered 400 and logout ended the session. `internal/web/login_test.go` rejects expired, reused and forged tokens. Decided here: tokens are 256 random bits, kept as SHA-256 and valid 15 minutes; sessions last 7 days; at most 5 links per address and 20 requests per client per hour; mail is sent in the background so that neither the answer nor its timing depends on the address or on the mail server; CSRF uses a double-submit `__Host-` cookie, which also covers the login forms. `SMTP_TLS=starttls` fails rather than falls back when the server offers no STARTTLS.

### 4. Dashboard

- Server-rendered HTML (templ) with htmx; no client-side framework, no CDN.
- Pages: login, "check your mail", link confirmation, key list (fingerprint, User IDs, created, expires, revoked), add key (paste or upload), remove key with confirmation.
- A user can only see and change keys for the address they logged in with.
- Own CSS that reproduces greentea's look (see below).

Done when: add and remove work in a browser, with and without JavaScript, in light and dark themes.

Status: done 2026-11-11. In headless Chromium against a local instance (mail through Mailpit), login, adding a pasted key, removal and logout went through in all four combinations of JavaScript on or off and the light or dark scheme: with JavaScript as htmx requests, without as plain form posts. Also checked: adding a key from a file without JavaScript, and a rejected upload showing its error on the form with and without JavaScript. No console or CSP errors. At 390 px wide the sidebar becomes a bar above the content. Tests cover adding, removing, rejected uploads, a member reaching another member's key (404) or publishing a key for another address (422), pages without login, and static files. Decided here: removal uses a confirmation page instead of a script dialog, so it works without JavaScript; the theme follows the device only (no switch); the fonts are greentea's Latin cuts of Inter and JetBrains Mono (OFL), and htmx comes from the `htmx.org` npm package (0BSD), whose `htmx.min.js` is byte for byte greentea's.

### 5. Deployment

- DNS record for `pgp.gnuweeb.org`; TLS.
- nginx on `gnuweeb.org` proxies the whole `/.well-known/openpgpkey/` prefix (the `policy` file is mandatory, not only `hu/`), ahead of the redirect to `www`.
- Production `.env` with the SMTP credentials.
- The directory starts empty; announce to members that they upload their keys through the dashboard.

Done when: a member uploads a key and `gpg --locate-key <member>@gnuweeb.org` returns it from an outside machine.

Status: the repository's part is done 2026-11-11; the production part is not. In the repository: `compose.yaml`, example nginx server blocks in `deploy/nginx/`, and a deployment section in `README.md`. Checked with `podman compose` and the repository's `compose.yaml` plus a test overlay (Mailpit, an nginx running the two example blocks with `gnuweeb.org` renamed to `gnuweeb.test` and a test CA): a member logged in by mailed link over STARTTLS, uploaded a key file, GnuPG 2.4.7 in a fresh `GNUPGHOME` located it through `https://gnuweeb.test/.well-known/openpgpkey/`, removing it made WKD answer 404, `POST` below the prefix got 403 and `/` the redirect to `www`. The container ran with a read-only root file system and no capabilities. Still to do on the servers, by the owner: the DNS record and certificate for `pgp.gnuweeb.org`, the nginx changes, the production `.env` with the SMTP credentials for `pgp@gnuweeb.org`, starting the service, the announcement, and the check from an outside machine named in "Done when".

### 6. Key health and expiry reminders

- Apply kernel.org's usability rule on upload and in a daily check: at least one usable signing (sub)key; flag expired keys, weak-hash (SHA-1, MD5, RIPEMD-160) self-signatures, DSA and keys with no signing key. The dashboard explains what to fix.
- Mail a reminder 30, 10 and 3 days before a key expires.
- Expired keys stay available so old signatures remain checkable.

Status: done 2026-11-11, in Go (see the decision on the key-health checker). `keys.Check` applies the rule on upload and in the dashboard; a check at start and then daily mails the reminders and logs keys that cannot sign. Decided here: a refused upload explains the problem with the GnuPG commands that fix it; a revoked key is accepted, so that the revocation gets published; the dashboard warns from 30 days before a key stops signing. Checked against `sq` 1.3.1 (Debian 13) with keys made by GnuPG 2.4.9: both agree on a sound key, a key whose signing subkey expires first, an expired key, a key self-signed with SHA-1 (refused) and an RSA-1024 key (refused); they differ on DSA (see "Open Items"). With a local instance and Mailpit, the list showed the problem and its commands in light and dark and at 390 px, a SHA-1 key was refused with its fix, and a restart mailed one reminder 10 days before a signing subkey ended and none on the next restart.

### 7. Keyring export

- Write `keys/<FINGERPRINT>.asc` (and `keys/expired/`) from the store into a local directory laid out like kernel.org's `pgpkeys.git`, so `gpg --import keys/*.asc` works on it. Armored, all User IDs and certifications as stored; the same store gives the same bytes, so an unchanged store produces no diff.
- No git operations and no signing key: the export runs and is tested on its own.

Status: done 2026-11-11. `matcha export DIR` writes the export; README's "Keyring export" describes it. Decided here: file names keep the full fingerprint, as `GNUWeeb/pgpkeys` has them today (kernel.org uses the 16-digit key ID); `keys/expired/` takes keys whose primary key has expired, the test kernel.org's `korg-move-expired.py` applies; revoked keys stay in `keys/` so that importing the keyring spreads the revocation (kernel.org removes them by hand); a key stored for several addresses is written once, from its latest upload; files the export does not own are left alone, since phase 8 decides what happens to `map.txt` and `genmap.py`. Checked: on a local instance with three uploaded keys, the export wrote three files, a second run changed nothing, a missing database was refused, and GnuPG 2.4.9 in a fresh `GNUPGHOME` imported all three from `keys/*.asc`; the image runs the command too.

### 8. Keyring publishing

- Commit the export to `GNUWeeb/pgpkeys` with signed commits and push it, so the repository follows the store.
- The published export replaces the repository's hand-maintained content (`map.txt`, `genmap.py`, the pull-request flow). Which key signs the commits, and how it is held on the server, is decided here.

Status: deferred by the maintainer, 2026-11-11.

### 9. Web of trust display

- Show, per key, which other members' keys certified it.
- Optional: a graph of certifications between members.
- No gate: publication never depends on certifications.

Status: done 2026-11-11, without the optional graph. Under each User ID the key list names the members whose stored keys certified it, by the addresses those keys are stored for, and counts certifications by keys outside the directory. Decided here: a certification counts when it verifies against a stored key, uses a hash the phase 6 policy accepts, has not expired and was not revoked later by the same signer; certifications sit with the User ID they are about rather than in a column, which made the table wider than a desktop page. Not done: the graph. It would show every member's address to every member, which is the owner's call; the per-key list shows only those who certified the member's own key. Checked: GnuPG 2.4.9 certified a stored key with two members' keys and one outside key; after the upload the list named both members and counted the third, in light and dark and at 390 px without widening the page.

## Design Reference: greentea (observed)

greentea is Go with templ templates. Its stylesheet is a reference, not a source to copy.

- Hand-written CSS with custom properties, no framework: `internal/web/static/greentea.css`. Light tokens include `--bg #f4f6f4`, `--surface #ffffff`, `--text #16201a`, `--accent #1d6b47`; dark `--bg #0e1310`, `--surface #151c18`, `--text #e5ebe7`. Radii 6/8/10/12px, control height 2.5rem.
- Themes: `prefers-color-scheme` plus a `data-theme` attribute on `<html>`.
- Fonts: self-hosted Inter and JetBrains Mono (OFL).
- htmx 2.0.11, vendored; `hx-boost` on `<body>`; CSRF token sent through `hx-headers`.
- Layouts: `.bare` (pre-login, one card about 30rem wide) and `.shell` (sidebar plus content); see `internal/web/ui/layout.templ` and `login.templ`.
- Components to mirror: `.btn` (`-primary`, `-danger`, `-quiet`), `.card`, `.flash`, `.field`, `.tbl`, `.badge`, `.empty`, the confirm dialog.

## Open Items

- Checked in phase 2: `go-crypto`'s `Identity.Signatures` holds every signature on a User ID, self-signatures included, not only third-party ones; `ReadKeyRing` rejects a key whose User ID self-signature does not verify and lists only self-signed User IDs. GnuPG accepts the WKD view (`--check-sigs`: all good), and a certification by another key verifies with `VerifyUserIdSignature`.
- Chosen in phase 2: `modernc.org/sqlite`, a pure-Go driver, so `CGO_ENABLED=0` builds keep working.
- Checked in phase 6: `sq` 1.3.1 accepts a DSA-2048 key made by GnuPG 2.4.9, so "DSA keys are rejected" in the kernel.org reference model does not hold for `sq` itself. The rule here refuses DSA, as phase 6 lists it.
- Checked in phase 6: GnuPG 2.4.9 keeps the hash of the self-signature it replaces, so `gpg --quick-set-expire` alone left a SHA-1 key on SHA-1; with `--cert-digest-algo SHA512` the new self-signatures used SHA-512 and the key passed. kernel.org's documentation says a recent GnuPG repairs such keys; 2.4.9 does not.
- Renaming the GitLab project needs the owner's agreement.

## References

- WKD draft: <https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/>
- kernel.org accounts and web of trust: <https://www.kernel.org/doc/projects/korg/accounts.html>
- kernel.org keyring: <https://korg.docs.kernel.org/pgpkeys.html>, <https://git.kernel.org/pub/scm/docs/kernel/pgpkeys.git>
- kernel.org WKD and User IDs: <https://korg.docs.kernel.org/mail.html>
- Kernel Maintainer PGP guide: <https://docs.kernel.org/process/maintainer-pgp-guide.html>
- greentea: <https://git.gnuweeb.net/ammarfaizi2/greentea>
- This repository: <https://git.gnuweeb.net/GNUWeeb/pgpkeys-wkd-server>
