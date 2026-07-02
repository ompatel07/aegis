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

// RuleHandler serves per-project custom-rule routes.
type RuleHandler struct {
	rules *services.RuleService
	log   zerolog.Logger
}

func NewRuleHandler(rules *services.RuleService, log zerolog.Logger) *RuleHandler {
	return &RuleHandler{rules: rules, log: log}
}

type createRuleRequest struct {
	Name     string `json:"name" validate:"required,max=255"`
	RuleYAML string `json:"rule_yaml" validate:"required,max=100000"`
}

// Create handles POST /api/v1/projects/{id}/rules — validate + store a rule.
func (h *RuleHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createRuleRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	userID := middleware.UserID(r.Context())
	projectID := chi.URLParam(r, "id")

	rule, err := h.rules.Create(r.Context(), projectID, userID, req.Name, req.RuleYAML)
	if err != nil {
		var invalid *services.InvalidRuleError
		if errors.As(err, &invalid) {
			httpx.WriteError(w, httpx.ErrBadRequest(invalid.Error()))
			return
		}
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusCreated, rule)
}

// List handles GET /api/v1/projects/{id}/rules.
func (h *RuleHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	projectID := chi.URLParam(r, "id")
	items, err := h.rules.List(r.Context(), projectID, userID)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, items)
}

// Delete handles DELETE /api/v1/rules/{ruleId}.
func (h *RuleHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	id := chi.URLParam(r, "ruleId")
	if err := h.rules.Delete(r.Context(), id, userID); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
