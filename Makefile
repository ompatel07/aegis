# ─────────────────────────────────────────────────────────────────────────────
# Aegis — developer entry points
#
# Usage: make <target>.  Run `make help` to list everything.
# ─────────────────────────────────────────────────────────────────────────────

# Load .env if present so DATABASE_URL etc. are available to host-run commands.
ifneq (,$(wildcard ./.env))
include .env
export
endif

COMPOSE        ?= docker compose
COMPOSE_DEV    := $(COMPOSE) -f docker-compose.yml -f docker-compose.override.yml
MIGRATIONS_DIR := database/migrations
# DATABASE_URL is consumed by golang-migrate. Falls back to compose defaults.
DATABASE_URL   ?= postgres://aegis:aegis@localhost:5432/aegis?sslmode=disable

# Run golang-migrate via its official image so contributors need nothing installed.
MIGRATE = docker run --rm --network host \
	-v "$(CURDIR)/$(MIGRATIONS_DIR)":/migrations \
	migrate/migrate -path=/migrations -database "$(DATABASE_URL)"

.DEFAULT_GOAL := help

# ─── Lifecycle ───────────────────────────────────────────────────────────────

.PHONY: dev
dev: ## Start the full stack with hot reload
	$(COMPOSE_DEV) up --build

.PHONY: up
up: ## Start the full stack in the background (production-like)
	$(COMPOSE) up -d --build

.PHONY: build
build: ## Build all Docker images
	$(COMPOSE) build

.PHONY: down
down: ## Stop all services
	$(COMPOSE) down

.PHONY: logs
logs: ## Tail logs from all services
	$(COMPOSE) logs -f --tail=100

.PHONY: ps
ps: ## Show running services
	$(COMPOSE) ps

# ─── Database ────────────────────────────────────────────────────────────────

.PHONY: migrate
migrate: ## Apply all up migrations
	$(MIGRATE) up

.PHONY: migrate-down
migrate-down: ## Roll back the most recent migration
	$(MIGRATE) down 1

.PHONY: migrate-force
migrate-force: ## Force the migration version (usage: make migrate-force version=N)
	$(MIGRATE) force $(version)

.PHONY: migrate-create
migrate-create: ## Scaffold a new migration (usage: make migrate-create name=add_foo)
	$(MIGRATE) create -ext sql -dir /migrations -seq $(name)

.PHONY: psql
psql: ## Open a psql shell against the running database
	$(COMPOSE) exec postgres psql -U aegis -d aegis

# ─── Quality ─────────────────────────────────────────────────────────────────

.PHONY: test
test: test-api test-orchestrator test-scanner test-web ## Run all test suites

.PHONY: test-api
test-api: ## Run Go API tests
	cd services/api && go test ./... -race -cover

.PHONY: test-orchestrator
test-orchestrator: ## Run Go orchestrator tests
	cd services/orchestrator && go test ./... -race -cover

.PHONY: test-scanner
test-scanner: ## Run Python scanner tests
	cd services/scanner && python -m pytest -q

.PHONY: test-web
test-web: ## Run frontend tests
	cd web && npm run test --if-present

.PHONY: smoke
smoke: ## Engine smoke test in Docker — asserts every engine finds issues + taint rules pass
	$(COMPOSE) run --rm --no-deps scanner \
		python -m pytest tests/test_engines_smoke.py tests/test_taint_rules.py -v

.PHONY: lint
lint: lint-api lint-orchestrator lint-scanner lint-web ## Lint all services

.PHONY: lint-api
lint-api:
	cd services/api && go vet ./... && gofmt -l .

.PHONY: lint-orchestrator
lint-orchestrator:
	cd services/orchestrator && go vet ./... && gofmt -l .

.PHONY: lint-scanner
lint-scanner:
	cd services/scanner && ruff check . && black --check .

.PHONY: lint-web
lint-web:
	cd web && npm run lint

# ─── Cleanup ─────────────────────────────────────────────────────────────────

.PHONY: clean
clean: ## Remove containers, networks, and volumes
	$(COMPOSE) down -v --remove-orphans

# ─── Meta ────────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
