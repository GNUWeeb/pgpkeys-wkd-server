# pgpkeys-wkd-server

A Simple HTTP Server to serve GNUWeeb's [pgpkeys](https://github.com/GNUWeeb/pgpkeys) via [Web Key Directory](https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service)

## End-user usage
Any OpenPGP client that supports WKD can use this server to fetch GNUWeeb's public key.

For example on gnupg v2.1.23 or above:
```bash
$ gpg --locate-key hzmi@gnuweeb.org
```

See the [FAQ / WIKI](https://gnupg.org/faq/wkd.html) for more information.

## Server usage
### Requirements
- Node.js v18.0.0 or above
- pnpm v8.0.0 or above
### Installation
```bash
$ git clone https://github.com/GNUWeeb/pgpkeys-wkd-server.git
$ cd pgpkeys-wkd-server
$ pnpm install
```
### Configuration
Copy .env.example to .env and fill/edit the values

For GitHub webhook use `application/json` and make sure to set the secret in the GitHub webhook settings and in the .env file.
Use `/internal/updateHook` (see notes for details for full path) as a path. This only needs the push event.

### Running
```bash
$ pnpm start
```
OR use any other process manager.

### Docker
You could use Docker and skip installing Node.js and pnpm and cloning the repo.
```bash
$ docker run -d -p 3000:3000 --env-file .env --name pgpkeys-wkd-server ghcr.io/gnuweeb/pgpkeys-wkd-server:latest
```
OR you can use docker compose yourself.

### Notes
Make sure to map a URL in `https://<EMAIL_DOMAIN>/.well-known/openpgpkey` to the server.

For Docker, you can use something like [watchtower](https://github.com/containrrr/watchtower) to keep the server up to date.
