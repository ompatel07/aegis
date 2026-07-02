package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/services"
)

// IntegrationHandler serves the GitHub integration CRUD routes.
type IntegrationHandler struct {
	integrations *services.IntegrationService
	log          zerolog.Logger
}

func NewIntegrationHandler(s *services.IntegrationService, log zerolog.Logger) *IntegrationHandler {
	return &IntegrationHandler{integrations: s, log: log}
}

type connectGitHubRequest struct {
	InstallationID string `json:"installation_id" validate:"omitempty,max=64"`
	AccessToken    string `json:"access_token" validate:"omitempty,max=512"`
}

// Connect handles POST /api/v1/projects/{id}/integrations/github. The response
// includes the webhook URL and the generated secret (shown once) so the user can
// configure the webhook in GitHub.
func (h *IntegrationHandler) Connect(w http.ResponseWriter, r *http.Request) {
	var req connectGitHubRequest
	if r.ContentLength != 0 {
		if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
			httpx.WriteError(w, apiErr)
			return
		}
	}
	userID := middleware.UserID(r.Context())
	projectID := chi.URLParam(r, "id")

	res, err := h.integrations.ConnectGitHub(r.Context(), projectID, userID, services.ConnectGitHubInput{
		InstallationID: req.InstallationID,
		AccessToken:    req.AccessToken,
	})
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusCreated, res)
}

// ListForProject handles GET /api/v1/projects/{id}/integrations.
func (h *IntegrationHandler) ListForProject(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	projectID := chi.URLParam(r, "id")

	items, err := h.integrations.ListForProject(r.Context(), projectID, userID)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, items)
}

// Delete handles DELETE /api/v1/integrations/{integrationId}.
func (h *IntegrationHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	id := chi.URLParam(r, "integrationId")

	if err := h.integrations.Delete(r.Context(), id, userID); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
