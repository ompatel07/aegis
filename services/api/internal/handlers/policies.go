package handlers

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
	"github.com/aegis-platform/api/internal/services"
)

// PolicyHandler serves policy configuration + evaluation routes.
type PolicyHandler struct {
	policies *services.PolicyService
	log      zerolog.Logger
}

func NewPolicyHandler(policies *services.PolicyService, log zerolog.Logger) *PolicyHandler {
	return &PolicyHandler{policies: policies, log: log}
}

// Templates: GET /policies/templates — the named presets.
func (h *PolicyHandler) Templates(w http.ResponseWriter, r *http.Request) {
	httpx.WriteSuccess(w, http.StatusOK, h.policies.Templates())
}

// Get: GET /projects/{id}/policy — the active policy (null if unset).
func (h *PolicyHandler) Get(w http.ResponseWriter, r *http.Request) {
	p, err := h.policies.Get(r.Context(), chi.URLParam(r, "id"), middleware.UserID(r.Context()))
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// Distinguish "project not found" from "no policy yet": try to detect
			// via the returned error; simplest is to return null policy on any
			// not-found here since Get already checked project access first.
			httpx.WriteSuccess(w, http.StatusOK, nil)
			return
		}
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, p)
}

type policyRequest struct {
	Name     string               `json:"name" validate:"omitempty,max=96"`
	Template string               `json:"template" validate:"omitempty,oneof=startup growing enterprise compliance custom"`
	Config   *models.PolicyConfig `json:"config"`
}

// Set: PUT /projects/{id}/policy.
func (h *PolicyHandler) Set(w http.ResponseWriter, r *http.Request) {
	var req policyRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	p, err := h.policies.Set(r.Context(), chi.URLParam(r, "id"),
		middleware.UserID(r.Context()), req.Name, req.Template, req.Config)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, p)
}

// Evaluate: GET /scans/{scanId}/policy — evaluate + store the scan's result.
func (h *PolicyHandler) Evaluate(w http.ResponseWriter, r *http.Request) {
	res, err := h.policies.Evaluate(r.Context(), chi.URLParam(r, "scanId"), middleware.UserID(r.Context()))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, res)
}
