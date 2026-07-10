package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// slackWebhookHost is the only host Slack serves incoming webhooks from.
const slackWebhookHost = "hooks.slack.com"

// ValidateSlackWebhookURL enforces that a webhook URL is a genuine Slack
// incoming webhook (https + hooks.slack.com). Slack webhooks are always on that
// host, so pinning it prevents SSRF: without this a project member could point
// the URL at http://169.254.169.254/… (cloud metadata) or an internal service
// and have the server POST to it on every scan completion.
func ValidateSlackWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid webhook URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("slack webhook must use https")
	}
	if u.Hostname() != slackWebhookHost {
		return fmt.Errorf("slack webhook host must be %s", slackWebhookHost)
	}
	return nil
}

// Slack posts messages to Slack incoming-webhook URLs (per-project routing).
// A bot-token OAuth app install is the richer option; incoming webhooks are the
// simplest reliable path and need no OAuth round-trip.
type Slack struct {
	http Doer
}

func NewSlack(doer Doer) *Slack {
	if doer == nil {
		doer = &http.Client{Timeout: 10 * time.Second}
	}
	return &Slack{http: doer}
}

// SlackMessage is a minimal Block Kit message.
type SlackMessage struct {
	Text   string           `json:"text"`
	Blocks []map[string]any `json:"blocks,omitempty"`
}

// Post delivers a message to a Slack incoming webhook.
func (s *Slack) Post(ctx context.Context, webhookURL string, msg SlackMessage) error {
	// Defense in depth: reject non-Slack hosts even if a bad URL was persisted.
	if err := ValidateSlackWebhookURL(webhookURL); err != nil {
		return err
	}
	payload, _ := json.Marshal(msg)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	return do2xx(s.http, req, "slack")
}
