package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"

	"github.com/aegis-platform/api/internal/httpx"
)

// HealthHandler reports liveness/readiness including dependency checks.
type HealthHandler struct {
	db  *sqlx.DB
	rdb *redis.Client
}

func NewHealthHandler(db *sqlx.DB, rdb *redis.Client) *HealthHandler {
	return &HealthHandler{db: db, rdb: rdb}
}

// Get handles GET /health. Returns 200 when all dependencies are reachable,
// 503 otherwise, with a per-dependency breakdown.
func (h *HealthHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	checks := map[string]string{"database": "ok", "redis": "ok"}
	healthy := true

	if err := h.db.PingContext(ctx); err != nil {
		checks["database"] = "unreachable"
		healthy = false
	}
	if err := h.rdb.Ping(ctx).Err(); err != nil {
		checks["redis"] = "unreachable"
		healthy = false
	}

	status := http.StatusOK
	overall := "ok"
	if !healthy {
		status = http.StatusServiceUnavailable
		overall = "degraded"
	}
	httpx.WriteSuccess(w, status, map[string]any{
		"status": overall, "service": "api", "checks": checks,
	})
}
