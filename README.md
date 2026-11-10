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

matcha reads its settings from the environment. `.env.example` lists them with their defaults; copy it to `.env` and edit it.

| Variable | Default | Meaning |
| --- | --- | --- |
| `WKD_ADDR` | `127.0.0.1:8080` | Listen address of the WKD routes |
| `DASHBOARD_ADDR` | `127.0.0.1:8081` | Listen address of the dashboard |
| `DATABASE_PATH` | `matcha.db` | SQLite database file, created if missing |

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

## WKD

The WKD listener serves the direct method: `GET` and `HEAD` on `/.well-known/openpgpkey/hu/<hash>` and `GET /.well-known/openpgpkey/policy`. The nginx in front of the mail domain must proxy the whole `/.well-known/openpgpkey/` prefix to it, ahead of any redirect. Each served key keeps all of its User IDs but none of the certifications made by other keys.

## License

GPL-2.0, see [LICENSE](LICENSE).
