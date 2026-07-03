package handlers

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/services"
)

// AIHandler serves the opt-in AI fix-suggestion routes.
type AIHandler struct {
	ai  *services.AIService
	log zerolog.Logger
}

func NewAIHandler(ai *services.AIService, log zerolog.Logger) *AIHandler {
	return &AIHandler{ai: ai, log: log}
}

// Status handles GET /api/v1/ai/status — whether an AI backend is configured.
func (h *AIHandler) Status(w http.ResponseWriter, r *http.Request) {
	httpx.WriteSuccess(w, http.StatusOK, map[string]any{
		"enabled":  h.ai.Enabled(),
		"provider": h.ai.Provider(),
	})
}

// SuggestFix handles POST /api/v1/findings/{findingId}/suggest-fix. Advisory only;
// the client shows a diff and requires an explicit Apply. Every call is audited.
func (h *AIHandler) SuggestFix(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	findingID := chi.URLParam(r, "findingId")

	suggestion, err := h.ai.SuggestFix(r.Context(), findingID, userID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrAIDisabled):
			httpx.WriteError(w, httpx.ErrBadRequest(err.Error()))
		case errors.Is(err, services.ErrAINotEnabled):
			httpx.WriteError(w, httpx.ErrForbidden(err.Error()))
		default:
			writeServiceError(w, h.log, err)
		}
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, suggestion)
}

// Audit handles GET /api/v1/ai/audit — the user's recent AI-call trail.
func (h *AIHandler) Audit(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	entries, err := h.ai.RecentAudit(r.Context(), userID, 100)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, entries)
}
