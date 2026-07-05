package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/services"
)

// ProjectHandler serves the /projects routes.
type ProjectHandler struct {
	projects *services.ProjectService
	log      zerolog.Logger
}

func NewProjectHandler(projects *services.ProjectService, log zerolog.Logger) *ProjectHandler {
	return &ProjectHandler{projects: projects, log: log}
}

type projectRequest struct {
	Name          string  `json:"name" validate:"required,min=1,max=255"`
	Description   *string `json:"description" validate:"omitempty,max=5000"`
	RepoURL       *string `json:"repo_url" validate:"omitempty,url,max=1024"`
	RepoType      *string `json:"repo_type" validate:"omitempty,oneof=github gitlab bitbucket upload"`
	DefaultBranch string  `json:"default_branch" validate:"omitempty,max=255"`
	Language        *string `json:"language" validate:"omitempty,max=64"`
	AIFixEnabled    *bool   `json:"ai_fix_enabled"`
	GrandfatherMode *bool   `json:"grandfather_mode"`
}

func (r projectRequest) toInput() services.ProjectInput {
	return services.ProjectInput{
		Name: r.Name, Description: r.Description, RepoURL: r.RepoURL,
		RepoType: r.RepoType, DefaultBranch: r.DefaultBranch, Language: r.Language,
		AIFixEnabled: r.AIFixEnabled, GrandfatherMode: r.GrandfatherMode,
	}
}

// List handles GET /api/v1/projects.
func (h *ProjectHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	page := httpx.QueryInt(r, "page", 1, 1, 1_000_000)
	perPage := httpx.QueryInt(r, "per_page", 20, 1, 100)

	projects, total, err := h.projects.List(r.Context(), userID, perPage, (page-1)*perPage)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WritePaginated(w, projects, page, perPage, total)
}

// Create handles POST /api/v1/projects.
func (h *ProjectHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req projectRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	userID := middleware.UserID(r.Context())

	project, err := h.projects.Create(r.Context(), userID, req.toInput())
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusCreated, project)
}

// Get handles GET /api/v1/projects/{id}.
func (h *ProjectHandler) Get(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	id := chi.URLParam(r, "id")

	project, err := h.projects.Get(r.Context(), id, userID)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, project)
}

// Update handles PUT /api/v1/projects/{id}.
func (h *ProjectHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req projectRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	userID := middleware.UserID(r.Context())
	id := chi.URLParam(r, "id")

	project, err := h.projects.Update(r.Context(), id, userID, req.toInput())
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, project)
}

// Baseline handles GET /api/v1/projects/{id}/baseline — the project's memory
// (baseline profile, per-rule baseline, team-learning feedback stats).
func (h *ProjectHandler) Baseline(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	data, err := h.projects.Baseline(r.Context(), chi.URLParam(r, "id"), userID)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, data)
}

// AICodeMemory handles GET /api/v1/projects/{id}/ai-code-memory — the project's
// AI-generated-code footprint over time.
func (h *ProjectHandler) AICodeMemory(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	data, err := h.projects.AICodeMemory(r.Context(), chi.URLParam(r, "id"), userID)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, data)
}

// Delete handles DELETE /api/v1/projects/{id}.
func (h *ProjectHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	id := chi.URLParam(r, "id")

	if err := h.projects.Delete(r.Context(), id, userID); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]string{"message": "project deleted"})
}
