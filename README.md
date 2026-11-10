# matcha

GNUWeeb's OpenPGP key directory. It serves members' public keys through [Web Key Directory](https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/) (WKD) and gives members a dashboard where they manage their own keys.

This is a rewrite in progress (formerly `pgpkeys-wkd-server`); see [ROADMAP.md](ROADMAP.md) for the plan.

## End-user usage

Any OpenPGP client that supports WKD can fetch a member's key, for example GnuPG 2.1.23 or later:

```bash
gpg --locate-key hzmi@gnuweeb.org
```

See the [GnuPG WKD page](https://gnupg.org/faq/wkd.html) for more information.

## Server usage

### Requirements

- Go 1.27 or later, or Docker (or Podman).

### Building

```bash
git clone https://git.gnuweeb.net/GNUWeeb/pgpkeys-wkd-server.git
cd pgpkeys-wkd-server
go build -o matcha ./cmd/matcha
```

### Configuration

matcha reads its settings from the environment. `.env.example` lists them with their defaults; copy it to `.env`, fill in the SMTP settings and keep the file private (it holds the SMTP password).

| Variable | Default | Meaning |
| --- | --- | --- |
| `WKD_ADDR` | `127.0.0.1:8080` | Listen address of the WKD routes |
| `DASHBOARD_ADDR` | `127.0.0.1:8081` | Listen address of the dashboard |
| `DATABASE_PATH` | `matcha.db` | SQLite database file, created if missing |
| `EMAIL_DOMAIN` | `gnuweeb.org` | Mail domain whose members log in and whose keys are served |
| `BASE_URL` | `https://pgp.gnuweeb.org` | Public URL of the dashboard; mailed login links point below it |
| `REAL_IP_HEADER` | (none) | Header with the client address set by the reverse proxy, for the per-client rate limit |
| `SMTP_HOST` | (required) | SMTP server for login mails |
| `SMTP_TLS` | `starttls` | `starttls`, `implicit` or `none` (local mail catcher only) |
| `SMTP_PORT` | `587`, or `465` with `implicit` | SMTP port |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | (none) | SMTP credentials; both or neither |
| `MAIL_FROM` | `pgp@` + `EMAIL_DOMAIN` | Sender of login mails |

### Running

```bash
set -a; . ./.env; set +a
./matcha
```

### Docker

```bash
docker build -t matcha .
docker run -d --env-file .env -v matcha-data:/var/lib/matcha \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:8081:8081 --name matcha matcha
```

Inside the container both listeners bind every interface (`WKD_ADDR=:8080`, `DASHBOARD_ADDR=:8081`); choose with `-p` where each port is reachable. The database lives at `/var/lib/matcha/matcha.db` on the image's volume; keep that volume across upgrades.

### Deployment

The intended setup for GNUWeeb: matcha in a container on the host that runs the nginx for `gnuweeb.org` and `pgp.gnuweeb.org`, both ports on loopback.

1. **DNS**: an `A`/`AAAA` record for `pgp.gnuweeb.org`. Keep `openpgpkey.gnuweeb.org` without any record and out of any wildcard: clients that find an address for it use the advanced WKD method, which matcha does not serve, and never fall back to `gnuweeb.org`.
2. **TLS**: a certificate for `pgp.gnuweeb.org` (the dashboard's cookies need HTTPS); `gnuweeb.org` already has one.
3. **Settings**: copy `.env.example` to `.env` next to `compose.yaml`, set the SMTP settings for `pgp@gnuweeb.org` and `chmod 600 .env`. The defaults of `EMAIL_DOMAIN` and `BASE_URL` already fit; `compose.yaml` sets `REAL_IP_HEADER`.
4. **Start**: `docker compose up -d --build` (or `podman compose`). The container runs as uid 10001 with a read-only root file system and no capabilities; the database is on the `matcha-data` volume.
5. **nginx**: [`deploy/nginx/gnuweeb.org.conf`](deploy/nginx/gnuweeb.org.conf) shows what the `gnuweeb.org` server block needs: the whole `/.well-known/openpgpkey/` prefix proxied to `127.0.0.1:8080`, matched before the redirect to `www.gnuweeb.org`. [`deploy/nginx/pgp.gnuweeb.org.conf`](deploy/nginx/pgp.gnuweeb.org.conf) is the dashboard's server block, proxying to `127.0.0.1:8081`. Both are examples; adapt the certificate paths.
6. **Check** from another machine:

   ```bash
   curl -sI https://gnuweeb.org/.well-known/openpgpkey/policy   # 200
   host openpgpkey.gnuweeb.org                                   # must not resolve
   ```

   then log in at `https://pgp.gnuweeb.org`, add a key, and in a fresh `GNUPGHOME` run `gpg --auto-key-locate clear,wkd,nodefault --locate-keys you@gnuweeb.org`.

The directory starts empty: members upload their own keys through the dashboard. To back up, stop the container (`docker compose stop`) and copy the volume's `matcha.db`; the database runs in WAL mode, so a copy taken while it runs can miss recent writes.

Upgrade with `git pull && docker compose up -d --build`; the schema is migrated at startup, and an older binary refuses a database written by a newer one.

## WKD

The WKD listener serves the direct method: `GET` and `HEAD` on `/.well-known/openpgpkey/hu/<hash>` and `GET /.well-known/openpgpkey/policy`. The nginx in front of the mail domain must proxy the whole `/.well-known/openpgpkey/` prefix to it, ahead of any redirect. Each served key keeps all of its User IDs but none of the certifications made by other keys.

## Dashboard

Members log in at `BASE_URL` with their address: matcha mails them a link that works once, for 15 minutes, and the link's page asks for a button press before it logs them in, so mail scanners that open links do not use it up. A session lasts 7 days or until logout. At most 5 links per hour are mailed to one address, and one client may ask for 20 per hour. The dashboard sets its cookies with the `__Host-` prefix, which needs HTTPS (browsers make an exception for `http://localhost`).

After login, the start page lists the member's keys (fingerprint, User IDs, creation and expiry dates, status). **Add key** takes a pasted key or a file, armored or binary, up to 1 MiB; it must be a public key with a User ID for the member's address, and uploading a key again replaces it (for example after extending its expiry). **Remove** asks for confirmation; WKD stops serving the key at once. A member sees and changes only the keys of the address they logged in with. The pages work without JavaScript; with it, htmx swaps them in place.

Keys are judged by the rule kernel.org applies: a key is usable while its primary key is valid and one of its keys may sign. Self-signatures made with MD5, SHA-1 or RIPEMD-160 do not count, and DSA, ElGamal and RSA keys under 2048 bits cannot sign. An upload that fails the rule is refused, except a revoked key, so that its revocation gets published. The key list marks keys that cannot sign or stop signing within 30 days and lists, under **What to fix**, the problem and the GnuPG commands that fix it. Keys that expire stay listed and served, so old signatures can still be checked.

matcha checks every key when it starts and then daily, and mails the member 30, 10 and 3 days before their key stops signing, with the commands that extend it. Each reminder goes out once per expiry date; uploading the key with a new date starts them over.

## License

GPL-2.0, see [LICENSE](LICENSE).
