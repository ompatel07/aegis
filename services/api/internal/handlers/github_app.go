package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/githubapp"
	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/repository"
	"github.com/aegis-platform/api/internal/services"
)

// GitHubAppHandler serves the GitHub App webhook + dashboard integration routes.
type GitHubAppHandler struct {
	svc  *services.GitHubAppService
	repo *repository.GitHubAppRepository
	log  zerolog.Logger
}

func NewGitHubAppHandler(svc *services.GitHubAppService, repo *repository.GitHubAppRepository, log zerolog.Logger) *GitHubAppHandler {
	return &GitHubAppHandler{svc: svc, repo: repo, log: log}
}

// Webhook: POST /webhooks/github/app — verified GitHub App events.
func (h *GitHubAppHandler) Webhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody))
	if err != nil {
		httpx.WriteError(w, httpx.ErrBadRequest("could not read body"))
		return
	}
	app := h.svc.App()
	if !app.Enabled() {
		httpx.WriteSuccess(w, http.StatusOK, map[string]string{"status": "app_disabled"})
		return
	}
	if !githubapp.VerifySignature(app.WebhookSecret(), body, r.Header.Get("X-Hub-Signature-256")) {
		httpx.WriteError(w, httpx.ErrUnauthorized("invalid signature"))
		return
	}
	event := r.Header.Get("X-GitHub-Event")
	if err := h.svc.HandleWebhook(r.Context(), event, body); err != nil {
		// Log but still 200 — GitHub retries on non-2xx and the event is durable.
		h.log.Warn().Err(err).Str("event", event).Msg("github app webhook handling error")
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]string{"status": "ok", "event": event})
}

// InstallURL: GET /integrations/github/install-url — the "Install Aegis" target.
func (h *GitHubAppHandler) InstallURL(w http.ResponseWriter, r *http.Request) {
	app := h.svc.App()
	url := ""
	if app.Enabled() {
		url = app.InstallURL()
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]any{"enabled": app.Enabled(), "install_url": url})
}

// Installations: GET /integrations/github/installations — connected installs + repos.
func (h *GitHubAppHandler) Installations(w http.ResponseWriter, r *http.Request) {
	insts, err := h.repo.ListInstallations(r.Context())
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	type instView struct {
		repository.GHInstallationView
		Repos []repository.GHRepoView `json:"repos"`
	}
	out := make([]instView, 0, len(insts))
	for _, i := range insts {
		repos, _ := h.repo.ListRepos(r.Context(), i.InstallationID)
		out = append(out, instView{GHInstallationView: i, Repos: repos})
	}
	httpx.WriteSuccess(w, http.StatusOK, out)
}

// ToggleRepo: PATCH /integrations/github/repos/{id} {enabled}.
func (h *GitHubAppHandler) ToggleRepo(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		httpx.WriteError(w, httpx.ErrBadRequest("invalid body"))
		return
	}
	if err := h.repo.SetRepoEnabled(r.Context(), chi.URLParam(r, "id"), body.Enabled); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]bool{"enabled": body.Enabled})
}

var _ = strconv.Atoi // reserved
