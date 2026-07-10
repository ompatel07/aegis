package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/notify"
	"github.com/aegis-platform/api/internal/services"
)

// NotifyHandler serves notification settings routes.
type NotifyHandler struct {
	svc *services.NotificationService
	log zerolog.Logger
}

func NewNotifyHandler(svc *services.NotificationService, log zerolog.Logger) *NotifyHandler {
	return &NotifyHandler{svc: svc, log: log}
}

// GetSettings: GET /notifications/settings.
func (h *NotifyHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	s, err := h.svc.GetSettings(r.Context(), middleware.UserID(r.Context()))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, s)
}

type settingsRequest struct {
	EmailEnabled      bool   `json:"email_enabled"`
	EmailScanComplete bool   `json:"email_scan_complete"`
	EmailNewCritical  bool   `json:"email_new_critical"`
	DigestFrequency   string `json:"digest_frequency" validate:"omitempty,oneof=daily weekly never"`
	SeverityThreshold string `json:"severity_threshold" validate:"omitempty,oneof=critical high medium all"`
}

// UpdateSettings: PUT /notifications/settings.
func (h *NotifyHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req settingsRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	if req.DigestFrequency == "" {
		req.DigestFrequency = "weekly"
	}
	if req.SeverityThreshold == "" {
		req.SeverityThreshold = "high"
	}
	st := &models.NotificationSettings{
		UserID: middleware.UserID(r.Context()), EmailEnabled: req.EmailEnabled,
		EmailScanComplete: req.EmailScanComplete, EmailNewCritical: req.EmailNewCritical,
		DigestFrequency: req.DigestFrequency, SeverityThreshold: req.SeverityThreshold,
	}
	if err := h.svc.UpdateSettings(r.Context(), st); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, st)
}

// GetProjectSlack: GET /projects/{id}/slack.
func (h *NotifyHandler) GetProjectSlack(w http.ResponseWriter, r *http.Request) {
	s, err := h.svc.GetProjectSlack(r.Context(), chi.URLParam(r, "id"), middleware.UserID(r.Context()))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, s)
}

type slackRequest struct {
	WebhookURL  string `json:"webhook_url" validate:"omitempty,url"`
	Enabled     bool   `json:"enabled"`
	MinSeverity string `json:"min_severity" validate:"omitempty,oneof=critical high medium all"`
}

// SetProjectSlack: PUT /projects/{id}/slack.
func (h *NotifyHandler) SetProjectSlack(w http.ResponseWriter, r *http.Request) {
	var req slackRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	// SSRF guard: a webhook URL must be a real Slack incoming webhook.
	if req.WebhookURL != "" {
		if err := notify.ValidateSlackWebhookURL(req.WebhookURL); err != nil {
			httpx.WriteError(w, httpx.ErrBadRequest(err.Error()))
			return
		}
	}
	err := h.svc.SetProjectSlack(r.Context(), chi.URLParam(r, "id"), middleware.UserID(r.Context()),
		req.WebhookURL, req.Enabled, req.MinSeverity)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]bool{"enabled": req.Enabled})
}
