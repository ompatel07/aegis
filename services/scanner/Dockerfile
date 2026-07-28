# ─────────────────────────────────────────────────────────────────────────────
# Aegis scanner service image.
# Bundles: Python 3.12 + Semgrep (pip), Trivy + Gitleaks binaries, and Node/Go
# toolchains so the deployment engine can run real builds.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    TRIVY_VERSION=0.71.2 \
    GITLEAKS_VERSION=8.21.2 \
    GO_VERSION=1.22.10 \
    NODE_MAJOR=20 \
    JOERN_VERSION=4.0.570 \
    PATH=/usr/local/go/bin:/usr/local/bin:$PATH

# ── System deps + Trivy + Gitleaks + Node + Go ───────────────────────────────
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        curl ca-certificates git gnupg xz-utils tar libgomp1; \
    \
    # Resolve arch-specific asset names once.
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) gl_arch="x64";   go_arch="amd64"; trivy_arch="Linux-64bit" ;; \
        arm64) gl_arch="arm64"; go_arch="arm64"; trivy_arch="Linux-ARM64" ;; \
        *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    \
    # Trivy (direct release tarball — the piped install.sh from main is flaky).
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${trivy_arch}.tar.gz" \
        -o /tmp/trivy.tar.gz; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    rm /tmp/trivy.tar.gz; \
    \
    # Gitleaks (pinned release binary).
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz" \
        -o /tmp/gitleaks.tar.gz; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    rm /tmp/gitleaks.tar.gz; \
    \
    # Go (for `go build` deployment checks + Go projects).
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" -o /tmp/go.tar.gz; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm /tmp/go.tar.gz; \
    \
    # Node.js (for npm install / build deployment checks + JS/TS projects).
    curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -; \
    apt-get install -y --no-install-recommends nodejs; \
    \
    apt-get purge -y --auto-remove gnupg; \
    rm -rf /var/lib/apt/lists/*

# ── Optional: Joern deep-scan engine (Apache-2.0) + JRE ───────────────────────
# Enabled only for the dedicated deep-scan sidecar (INCLUDE_JOERN=true); the
# fast-path scanner image stays lean. joern-cli is ~2GB unpacked, so it is
# intentionally isolated behind this build arg rather than bundled everywhere.
ARG INCLUDE_JOERN=false
RUN set -eux; \
    if [ "$INCLUDE_JOERN" = "true" ]; then \
        apt-get update; \
        apt-get install -y --no-install-recommends openjdk-21-jre-headless unzip; \
        curl -fsSL "https://github.com/joernio/joern/releases/download/v${JOERN_VERSION}/joern-cli.zip" \
            -o /tmp/joern-cli.zip; \
        unzip -q /tmp/joern-cli.zip -d /opt; \
        rm /tmp/joern-cli.zip; \
        ln -sf /opt/joern-cli/joern /usr/local/bin/joern; \
        ln -sf /opt/joern-cli/joern-parse /usr/local/bin/joern-parse; \
        rm -rf /var/lib/apt/lists/*; \
    fi

# ── Python dependencies (cached layer) ───────────────────────────────────────
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# ── Application code ─────────────────────────────────────────────────────────
COPY . .

# ── Non-root runtime user + writable caches ──────────────────────────────────
RUN set -eux; \
    useradd --create-home --uid 10001 aegis; \
    mkdir -p /opt/aegis/cache/semgrep /opt/aegis/cache/trivy /opt/aegis/models /workspaces; \
    chown -R aegis:aegis /opt/aegis /workspaces /app

USER aegis

ENV SCANNER_HOST=0.0.0.0 \
    SCANNER_PORT=8000 \
    SEMGREP_RULES_CACHE=/opt/aegis/cache/semgrep \
    TRIVY_CACHE_DIR=/opt/aegis/cache/trivy \
    FP_MODEL_PATH=/opt/aegis/models/fp_classifier.joblib

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
