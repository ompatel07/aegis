package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/repository"
	"github.com/aegis-platform/api/internal/services"
)

// maxWebhookBody caps the webhook payload to a sane size.
const maxWebhookBody = 5 << 20 // 5 MiB

// WebhookHandler processes inbound VCS webhooks.
type WebhookHandler struct {
	integrations *repository.GithubIntegrationRepository
	scans        *services.ScanService
	log          zerolog.Logger
}

func NewWebhookHandler(
	integrations *repository.GithubIntegrationRepository,
	scans *services.ScanService,
	log zerolog.Logger,
) *WebhookHandler {
	return &WebhookHandler{integrations: integrations, scans: scans, log: log}
}

// githubPushPayload is the subset of the push event we consume.
type githubPushPayload struct {
	Ref        string `json:"ref"`
	After      string `json:"after"`
	Repository struct {
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
}

// GitHub handles POST /api/v1/webhooks/github.
//
// Flow: read the raw body, identify the project by repository URL, look up the
// per-project webhook secret, verify the X-Hub-Signature-256 HMAC over the raw
// body, then (for push events only) enqueue a scan.
func (h *WebhookHandler) GitHub(w http.ResponseWriter, r *http.Request) {
	event := r.Header.Get("X-GitHub-Event")

	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody))
	if err != nil {
		httpx.WriteError(w, httpx.ErrBadRequest("could not read request body"))
		return
	}

	// Acknowledge non-push events (ping, etc.) without doing work.
	if event != "push" {
		h.log.Debug().Str("event", event).Msg("ignoring non-push webhook")
		httpx.WriteSuccess(w, http.StatusOK, map[string]string{"status": "ignored", "event": event})
		return
	}

	var payload githubPushPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		httpx.WriteError(w, httpx.ErrBadRequest("malformed webhook payload"))
		return
	}

	// Resolve the integration (and its secret) by repository URL.
	integration, err := h.integrations.FindByRepoURLs(r.Context(), payload.Repository.HTMLURL, payload.Repository.CloneURL)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// Unknown repo — do not reveal whether it exists.
			httpx.WriteError(w, httpx.ErrUnauthorized("signature verification failed"))
			return
		}
		writeServiceError(w, h.log, err)
		return
	}

	// Verify the HMAC signature BEFORE trusting any payload field.
	if !verifySignature(r.Header.Get("X-Hub-Signature-256"), body, integration.WebhookSecret) {
		httpx.WriteError(w, httpx.ErrUnauthorized("signature verification failed"))
		return
	}

	branch := strings.TrimPrefix(payload.Ref, "refs/heads/")

	scan, err := h.scans.TriggerWebhook(r.Context(), integration.ProjectID, branch, payload.After)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}

	h.log.Info().
		Str("project_id", integration.ProjectID).
		Str("scan_id", scan.ID).
		Str("branch", branch).
		Msg("webhook triggered scan")

	httpx.WriteSuccess(w, http.StatusAccepted, map[string]string{
		"status": "accepted", "scan_id": scan.ID,
	})
}

// verifySignature checks an X-Hub-Signature-256 header ("sha256=<hex>") against
// HMAC-SHA256(body, secret) using a constant-time comparison.
func verifySignature(header string, body []byte, secret string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) || secret == "" {
		return false
	}
	want := strings.TrimPrefix(header, prefix)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	got := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(got), []byte(want))
}
