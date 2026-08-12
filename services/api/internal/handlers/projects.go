package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/gitremote"
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
	OrganizationID  *string `json:"organization_id" validate:"omitempty,uuid"`
}

func (r projectRequest) toInput() services.ProjectInput {
	return services.ProjectInput{
		Name: r.Name, Description: r.Description, RepoURL: r.RepoURL,
		RepoType: r.RepoType, DefaultBranch: r.DefaultBranch, Language: r.Language,
		AIFixEnabled: r.AIFixEnabled, GrandfatherMode: r.GrandfatherMode,
		OrganizationID: r.OrganizationID,
	}
}

type detectBranchesRequest struct {
	RepoURL     string `json:"repo_url" validate:"required,url,max=1024"`
	AccessToken string `json:"access_token" validate:"omitempty,max=512"`
}

// DetectBranches handles POST /api/v1/projects/detect-branches — inspects a remote
// repo (no clone) and returns its default branch + branch list so the connect-repo
// UI can offer "use default (auto-detected)" or "choose a branch". Failures map to
// a clear, user-facing message rather than a raw git error.
func (h *ProjectHandler) DetectBranches(w http.ResponseWriter, r *http.Request) {
	var req detectBranchesRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	def, branches, err := h.projects.DetectBranches(r.Context(), req.RepoURL, req.AccessToken)
	if err != nil {
		httpx.WriteError(w, httpx.ErrBadRequest(friendlyRepoError(err, req.AccessToken != "")))
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]any{
		"default_branch": def,
		"branches":       branches,
	})
}

// friendlyRepoError turns a raw go-git/transport error into a clear message a real
// user can act on (bad URL, missing auth, empty repo). Used by connect + scan flows.
func friendlyRepoError(err error, hadToken bool) string {
	msg := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, gitremote.ErrNoBranches):
		return "This repository has no branches yet (it looks empty). Push some code first, then connect it."
	case strings.Contains(msg, "authentication required") || strings.Contains(msg, "authorization failed") || strings.Contains(msg, "403"):
		if hadToken {
			return "Couldn't access the repository — the access token was rejected. Check that the token is valid and has read access to this repo."
		}
		return "This repository is private or doesn't exist. If it's private, provide an access token (or connect the integration); if it's public, double-check the URL."
	case strings.Contains(msg, "repository not found") || strings.Contains(msg, "not found") || strings.Contains(msg, "could not resolve") || strings.Contains(msg, "no such host"):
		return "Couldn't find the repository at that URL. Check the URL (and that the repo exists and is spelled correctly)."
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		return "Timed out reaching the repository. Check the URL and that the host is reachable, then try again."
	default:
		return "Couldn't access the repository. Check the URL and your access token/permissions."
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

// Lifecycle handles GET /api/v1/projects/{id}/lifecycle — the project's
// finding-lifecycle summary: per-status counts (new/existing/resolved/reopened)
// and the resolved findings (which are absent from any current scan's findings).
func (h *ProjectHandler) Lifecycle(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserID(r.Context())
	data, err := h.projects.Lifecycle(r.Context(), chi.URLParam(r, "id"), userID)
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
