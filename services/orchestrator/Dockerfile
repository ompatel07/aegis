# ─────────────────────────────────────────────────────────────────────────────
# Aegis orchestrator image (multi-stage). Pure-Go (CGO disabled); go-git means
# no system git binary is required at runtime.
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0 GOOS=linux
RUN go mod tidy
RUN go build -trimpath -ldflags="-s -w" -o /out/orchestrator ./cmd

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates && adduser -D -u 10001 aegis
COPY --from=builder /out/orchestrator /usr/local/bin/orchestrator

# Shared workspace volume (mounted in docker-compose, also used by the scanner).
RUN mkdir -p /workspaces && chown aegis:aegis /workspaces
USER aegis
ENV WORKSPACE_DIR=/workspaces

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep -x orchestrator >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/orchestrator"]
