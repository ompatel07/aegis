# Aegis

> Enterprise-grade automated code intelligence platform — code quality, security, and deployment testing in one privacy-first pipeline.

Aegis ingests any codebase (app, website, automation script, API) and runs it through a
**3-pillar analysis pipeline**, producing a unified, graded report.

| Pillar | What it does | Competes with |
| ------ | ------------ | ------------- |
| **Quality** | AST-based smells, cyclomatic complexity, duplication, maintainability, docs/coverage | SonarQube |
| **Security** | SAST (taint/dataflow), SCA (CVE), secrets detection, OWASP Top 10, IaC scanning | Snyk, Checkmarx |
| **Deployment** | Build verification, smoke tests, env compatibility, container & dependency checks | *(unique)* |

---

## Architecture

```
                                  ┌─────────────────────────────┐
                                  │           Nginx             │
                                  │   /api/* → api  ·  /* → web  │
                                  └───────────┬─────────────────┘
                        ┌─────────────────────┼─────────────────────┐
                        │                     │                     │
                 ┌──────▼──────┐       ┌──────▼──────┐       ┌──────▼───────┐
                 │   web       │       │   api (Go)  │       │  (browser)   │
                 │  Next.js 14 │──────▶│  Chi router │       │              │
                 └─────────────┘       │  JWT auth   │       └──────────────┘
                                       │  webhooks   │
                                       └──────┬──────┘
                                              │ enqueue (Asynq / Redis)
                                       ┌──────▼───────────┐
                                       │ orchestrator (Go)│
                                       │ pipeline + score │
                                       └──────┬───────────┘
                                              │ HTTP (parallel fan-out)
                                       ┌──────▼───────────┐
                                       │ scanner (Python) │
                                       │ FastAPI          │
                                       │ semgrep · trivy  │
                                       │ gitleaks · radon │
                                       └──────────────────┘

        Shared infra:  PostgreSQL 16  ·  Redis 7
```

### Service responsibilities

- **`services/api`** (Go 1.22, Chi) — Public API gateway. Auth (JWT access + refresh),
  project/scan CRUD, findings, GitHub webhooks (HMAC verified), and publishing scan jobs to the queue.
- **`services/orchestrator`** (Go 1.22, Asynq worker) — Consumes scan jobs, clones the repo,
  detects language/framework, fans out to the scanner in parallel, aggregates + scores results,
  persists findings, and cleans up.
- **`services/scanner`** (Python 3.12, FastAPI) — Stateless analysis engine wrapping
  Semgrep, Trivy, Gitleaks, radon/lizard, and the deployment build/smoke harness.
- **`web`** (Next.js 14, App Router) — Dashboard: projects, scan history, trends, and the
  findings drill-down view.

---

## Privacy-first AI strategy

Aegis is layered so enterprises can adopt it without source code ever leaving their infrastructure:

| Layer | What runs | Data exposure |
| ----- | --------- | ------------- |
| **1 — Deterministic scanners** | Semgrep + Trivy + Gitleaks in isolated containers | None — fully local |
| **2 — Local FP filter** | ML classifier on scan *metadata* (rule type, file type, AST depth) | None — no source |
| **3 — Local severity scorer** | Reachability/exploitability via call-graph metadata | None — no source |
| **4 — AI fix suggestions** | *Opt-in.* Sends only the 10–30 vulnerable lines + issue type to an LLM | Snippet-level, audited |
| **5 — AI report generation** | *Opt-in.* Plain-English summary from findings JSON | Findings JSON only |

Layers 1–3 are the default and ship in Phase 1. Layers 4–5 are opt-in and gated behind
explicit per-project configuration with a full audit log.

---

## Quick start

Requires Docker + Docker Compose and `make`.

```bash
cp .env.example .env          # then edit secrets
make dev                      # build + start the full stack with hot reload
make migrate                  # apply database migrations
```

- Dashboard:        http://localhost
- API health:       http://localhost/api/health
- Scanner health:   http://localhost:8000/health (internal; exposed in dev only)

See **[DEVELOPMENT.md](DEVELOPMENT.md)** for the full local workflow, how to trigger a test
scan, and the end-to-end pipeline walkthrough.

### Make targets

| Command | Description |
| ------- | ----------- |
| `make dev` | Start the full stack with hot reload |
| `make build` | Build all Docker images |
| `make down` | Stop all services |
| `make logs` | Tail all logs |
| `make migrate` | Apply database migrations |
| `make migrate-down` | Roll back the last migration |
| `make test` | Run all test suites |
| `make lint` | Lint all services |
| `make clean` | Remove containers + volumes |

---

## Scoring model

**Security score** starts at 100 and subtracts per finding: critical −25, high −10,
medium −3, low −1 (floored at 0).

**Quality score** is a weighted average: complexity 30%, duplication 20%,
maintainability 25%, test coverage 15%, documentation 10%.

**Overall score** weights the pillars: security 40%, quality 35%, deployment 25%, and maps
to a grade — A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40.

---

## Repository layout

```
services/api/           Go — API gateway + auth + webhooks
services/orchestrator/  Go — pipeline job processor + scoring
services/scanner/       Python — analysis engine (FastAPI)
web/                    Next.js 14 dashboard
database/migrations/    golang-migrate SQL files
docker/nginx/           Reverse proxy config
docker-compose.yml      Full local dev stack
Makefile                Developer entry points
```

## License

Proprietary — © Aegis. All rights reserved.
