package handlers

import (
	"io"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/services"
)

// VCSHandler serves GitLab & Bitbucket webhooks.
type VCSHandler struct {
	svc *services.VCSService
	log zerolog.Logger
}

func NewVCSHandler(svc *services.VCSService, log zerolog.Logger) *VCSHandler {
	return &VCSHandler{svc: svc, log: log}
}

func (h *VCSHandler) handle(w http.ResponseWriter, r *http.Request, provider, eventHeader string) {
	p := h.svc.Provider(provider)
	if p == nil || !p.Enabled() {
		httpx.WriteSuccess(w, http.StatusOK, map[string]string{"status": "provider_disabled"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody))
	if err != nil {
		httpx.WriteError(w, httpx.ErrBadRequest("could not read body"))
		return
	}
	if !p.VerifyWebhook(r, body) {
		httpx.WriteError(w, httpx.ErrUnauthorized("invalid webhook signature"))
		return
	}
	event := r.Header.Get(eventHeader)
	if err := h.svc.HandleWebhook(r.Context(), provider, event, body); err != nil {
		h.log.Warn().Err(err).Str("provider", provider).Str("event", event).Msg("vcs webhook error")
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GitLab: POST /webhooks/gitlab.
func (h *VCSHandler) GitLab(w http.ResponseWriter, r *http.Request) {
	h.handle(w, r, "gitlab", "X-Gitlab-Event")
}

// Bitbucket: POST /webhooks/bitbucket.
func (h *VCSHandler) Bitbucket(w http.ResponseWriter, r *http.Request) {
	h.handle(w, r, "bitbucket", "X-Event-Key")
}
