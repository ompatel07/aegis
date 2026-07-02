package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
)

// IntelligenceHandler serves the intelligence status + notifications routes.
type IntelligenceHandler struct {
	repo *repository.IntelligenceRepository
	log  zerolog.Logger
}

func NewIntelligenceHandler(repo *repository.IntelligenceRepository, log zerolog.Logger) *IntelligenceHandler {
	return &IntelligenceHandler{repo: repo, log: log}
}

var syncIntervals = map[string]time.Duration{
	"nvd":     24 * time.Hour,
	"osv":     6 * time.Hour,
	"ghsa":    24 * time.Hour,
	"semgrep": 7 * 24 * time.Hour,
}

type sourceStatus struct {
	models.SyncStatus
	NextSync *time.Time `json:"next_sync,omitempty"`
}

// Status handles GET /api/v1/intelligence/status.
func (h *IntelligenceHandler) Status(w http.ResponseWriter, r *http.Request) {
	statuses, err := h.repo.SyncStatus(r.Context())
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	counts, total, err := h.repo.CVECounts(r.Context())
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}

	sources := make([]sourceStatus, 0, len(statuses))
	for _, s := range statuses {
		ss := sourceStatus{SyncStatus: s}
		if s.LastStartedAt != nil {
			if iv, ok := syncIntervals[s.Source]; ok {
				next := s.LastStartedAt.Add(iv)
				ss.NextSync = &next
			}
		}
		sources = append(sources, ss)
	}

	httpx.WriteSuccess(w, http.StatusOK, map[string]any{
		"sources":    sources,
		"cve_counts": counts,
		"total_cves": total,
	})
}

// ListNotifications handles GET /api/v1/notifications.
func (h *IntelligenceHandler) ListNotifications(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	items, err := h.repo.ListNotifications(r.Context(), userID, 50)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	unread, err := h.repo.UnreadCount(r.Context(), userID)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]any{
		"notifications": items,
		"unread_count":  unread,
	})
}

// MarkNotificationRead handles PATCH /api/v1/notifications/{id}/read.
func (h *IntelligenceHandler) MarkNotificationRead(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	id := chi.URLParam(r, "id")
	if err := h.repo.MarkNotificationRead(r.Context(), id, userID); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
