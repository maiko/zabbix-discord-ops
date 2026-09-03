# syntax=docker/dockerfile:1.12@sha256:93bfd3b68c109427185cd78b4779fc82b484b0b7618e36d0f104d4d801e66d25

FROM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

WORKDIR /src

COPY go.mod ./
COPY cmd/zabbix-discord-ops/ ./cmd/zabbix-discord-ops/
COPY internal/ ./internal/

ARG VERSION=dev
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/zabbix-discord-ops \
    ./cmd/zabbix-discord-ops

FROM scratch

ARG CREATED
ARG GIT_SHA
ARG VERSION=dev
LABEL org.opencontainers.image.title="Zabbix Discord Ops" \
      org.opencontainers.image.description="Tenant-aware, interactive Discord operations for Zabbix" \
      org.opencontainers.image.url="https://github.com/maiko/zabbix-discord-ops" \
      org.opencontainers.image.source="https://github.com/maiko/zabbix-discord-ops" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.version="${VERSION}"

COPY --link --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --link --from=builder /out/zabbix-discord-ops /zabbix-discord-ops

USER 65532:65532
EXPOSE 9088/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/zabbix-discord-ops", "-healthcheck", "http://127.0.0.1:9088/healthz"]

ENTRYPOINT ["/zabbix-discord-ops"]
