# Aegis — Development Guide

This guide covers running the full stack locally, triggering a scan, the
environment variables each service needs, and how a scan flows end to end.

---

## 1. Prerequisites

- **Docker** + **Docker Compose v2** (`docker compose`, not the legacy `docker-compose`)
- **make**
- ~6 GB free disk (the scanner image bundles Semgrep, Trivy, Gitleaks, Node, and Go)

Optional, only for running a service outside Docker:
- Go 1.22+, Python 3.12+, Node 20+

---

## 2. Run the full stack

```bash
cp .env.example .env          # then edit secrets (see §4)
make dev                      # builds images + starts everything with hot reload
```

`make dev` uses `docker-compose.yml` + `docker-compose.override.yml`. On first run
it will:

1. start **postgres** and **redis** and wait for them to be healthy,
2. run the **migrate** one-shot service (applies `database/migrations`),
3. build + start **scanner**, **api**, **orchestrator**, **web**, and **nginx**.

When it settles:

| URL | What |
| --- | --- |
| http://localhost | Dashboard (Next.js via nginx) |
| http://localhost/api/health | API health (DB + Redis checks) |
| http://localhost:8000/health | Scanner health (tool availability) — dev only |
| http://localhost:8080/health | API direct — dev only |

Other handy targets:

```bash
make logs           # tail all logs
make ps             # list services
make migrate        # re-apply migrations (idempotent)
make psql           # psql shell into the database
make down           # stop everything
make clean          # stop + delete volumes (fresh start)
```

> **Migrations** also run automatically via the `migrate` compose service, so a
> plain `make dev` gives you a fully migrated database. `make migrate` is there
> for re-runs after adding new migration files.

---

## 3. Trigger a test scan

The whole flow is exercised through the dashboard, but here it is via the API so
you can see each step.

### 3.1 Register + log in

```bash
# Register (returns a user + access/refresh tokens)
curl -s http://localhost/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"name":"Dev","email":"dev@example.com","password":"password123"}' | tee /tmp/auth.json

ACCESS=$(jq -r '.data.tokens.access_token' /tmp/auth.json)
```

### 3.2 Create a project (point it at any public repo)

```bash
curl -s http://localhost/api/v1/projects \
  -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' \
  -d '{"name":"Juice Shop","repo_url":"https://github.com/juice-shop/juice-shop","repo_type":"github","default_branch":"master"}' \
  | tee /tmp/project.json

PROJECT=$(jq -r '.data.id' /tmp/project.json)
```

### 3.3 Trigger the scan

```bash
curl -s -X POST "http://localhost/api/v1/projects/$PROJECT/scans" \
  -H "Authorization: Bearer $ACCESS" | tee /tmp/scan.json

SCAN=$(jq -r '.data.id' /tmp/scan.json)
```

The scan starts as `queued`. Watch it progress:

```bash
watch -n 3 "curl -s http://localhost/api/v1/scans/$SCAN -H 'Authorization: Bearer $ACCESS' | jq '.data.scan | {status, overall_grade, security_score, quality_score, deployment_score}'"
```

### 3.4 Read the findings

```bash
curl -s "http://localhost/api/v1/scans/$SCAN/findings?pillar=security&severity=critical" \
  -H "Authorization: Bearer $ACCESS" | jq '.data[] | {severity, title, file_path, line_start}'
```

Or just open the project in the dashboard — the scan detail page polls and renders
the tabbed Quality / Security / Deployment views automatically.

---

## 4. Environment variables

Copy `.env.example` → `.env`. The important ones:

| Variable | Used by | Notes |
| --- | --- | --- |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | postgres, all DB clients | Change the password for anything non-local. |
| `JWT_ACCESS_SECRET` / `JWT_REFRESH_SECRET` | api | `openssl rand -hex 32`. Access TTL 15m, refresh 7d. |
| `TOKEN_ENCRYPTION_KEY` | api | **Exactly 64 hex chars** (AES-256). Encrypts integration tokens. |
| `NEXTAUTH_SECRET` | web | `openssl rand -base64 32`. |
| `NEXTAUTH_URL` | web | Public base URL, e.g. `http://localhost`. |
| `NEXT_PUBLIC_API_URL` | web (build-time) | Browser → API base, default `http://localhost/api/v1`. |
| `WORKER_CONCURRENCY` | orchestrator | Parallel scans per worker. |
| `DEPLOYMENT_BUILD_ENABLED` | scanner | Set `false` to disable running project build commands. |

Per-service `.env.example` files under `services/*/` and `web/` document every
variable that service reads (useful when running a service standalone).

---

## 5. How the pipeline flows

```
 1. POST /projects/:id/scans            (api)        → create scan row (status=queued)
 2. publish "scan:run" to Redis         (api)        → Asynq queue "scans"
 3. consume job                         (orchestrator)
 4. status → running                    (orchestrator → DB)
 5. shallow clone repo → /workspaces/<scanId>   (orchestrator, go-git)
 6. detect language / project type      (orchestrator)
 7. parallel fan-out (errgroup-style):  (orchestrator → scanner HTTP)
        /scan/sast        Semgrep
        /scan/sca         Trivy
        /scan/secrets     Gitleaks
        /scan/quality     radon + lizard + duplication
        /scan/deployment  build + smoke
 8. normalize findings + scores         (orchestrator: aggregator + scoring)
        security = 100 − (25·crit + 10·high + 3·med + 1·low), floored
        quality  = weighted sub-scores (complexity/dup/maint/coverage/docs)
        deploy   = succeeded/attempted build steps
        overall  = 0.40·sec + 0.35·qual + 0.25·deploy → grade A–F
 9. persist (single transaction):       (orchestrator → DB)
        bulk-insert findings + update scan (scores, counts, raw_* JSONB, status=completed)
10. delete cloned repo                  (orchestrator, deferred cleanup)
11. dashboard polls /scans/:id          (web) → renders results
```

A failure in any single scanner engine is captured as a **degraded** result (no
findings from that engine, recorded in `error_message`) rather than failing the
whole scan — partial intelligence beats none. A clone/persist failure marks the
scan `failed` (after Asynq's retry budget for transient errors).

### Shared workspace

The orchestrator and scanner share the `workspaces` Docker volume mounted at
`/workspaces`. The orchestrator clones into `/workspaces/<scanId>` and passes that
absolute path to the scanner, which reads the same files. No source code leaves
the cluster.

---

## 6. Running a single service outside Docker

Example — the API:

```bash
cd services/api
cp .env.example .env        # point DATABASE_URL/REDIS_ADDR at localhost
go run ./cmd
```

Example — the scanner (with the tool binaries on your PATH):

```bash
cd services/scanner
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Keep `postgres` and `redis` running via Docker (`docker compose up -d postgres redis`)
while developing a single service locally.

---

## 7. Tests & linting

```bash
make test           # Go (api, orchestrator) + Python (scanner) + web
make lint           # go vet/gofmt + ruff/black + next lint
```

The orchestrator ships unit tests for the scoring model
(`services/orchestrator/internal/scoring`) and the scanner for severity
normalization (`services/scanner/tests`).
