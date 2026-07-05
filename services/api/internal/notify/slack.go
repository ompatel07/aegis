package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

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
	payload, _ := json.Marshal(msg)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	return do2xx(s.http, req, "slack")
}
