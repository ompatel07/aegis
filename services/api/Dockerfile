# ─────────────────────────────────────────────────────────────────────────────
# Aegis API service image (multi-stage).
# Dependencies are resolved at build time with `go mod tidy`, which generates a
# verified go.sum, so the repo can ship go.mod alone.
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates
WORKDIR /src

# Copy sources and resolve modules. (tidy needs the source to know imports.)
COPY . .
ENV CGO_ENABLED=0 GOOS=linux
RUN go mod tidy
RUN go build -trimpath -ldflags="-s -w" -o /out/api ./cmd

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM alpine:3.20

# ca-certificates only; the healthcheck uses BusyBox wget (built into alpine),
# so no curl or other extra tooling is shipped in the production image.
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 aegis
COPY --from=builder /out/api /usr/local/bin/api

USER aegis
ENV API_PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/health >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/api"]
