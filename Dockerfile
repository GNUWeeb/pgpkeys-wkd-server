# Base images are pinned by the digest of their multi-platform index, so
# a rebuild uses the same bits until someone bumps both tag and digest.
FROM docker.io/library/golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS build

WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "-s -w" -o /out/matcha ./cmd/matcha

FROM docker.io/library/debian:13.7-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# A fixed uid, so a volume mounted for matcha has a known owner.
ARG MATCHA_UID=10001

# /var/lib/matcha holds the SQLite database; a volume mounted there
# starts with this owner and mode.
RUN groupadd --system --gid ${MATCHA_UID} matcha \
 && useradd --system --uid ${MATCHA_UID} --gid matcha --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin matcha \
 && install -d -o matcha -g matcha -m 0700 /var/lib/matcha

COPY --from=build /out/matcha /usr/local/bin/matcha

# Inside the container both listeners bind every interface; publish the
# WKD port only where the nginx in front of the mail domain reaches it.
ENV WKD_ADDR=:8080 DASHBOARD_ADDR=:8081 DATABASE_PATH=/var/lib/matcha/matcha.db
VOLUME /var/lib/matcha
EXPOSE 8080/tcp 8081/tcp

USER matcha
ENTRYPOINT ["/usr/local/bin/matcha"]
