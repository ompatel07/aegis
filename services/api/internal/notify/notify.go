// Package notify delivers email + Slack notifications (Phase 2C TASK 7). Like
// the AI layer, the provider is a single config switch and defaults to a
// credential-free "log" sender so the platform is fully functional out of the
// box; real Resend / SendGrid / SMTP adapters activate when configured. HTTP
// adapters take an injectable transport so they're verified against a mock
// (build-real+simulate).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Email is one message.
type Email struct {
	To      string
	Subject string
	HTML    string
	Text    string
}

// Sender delivers email.
type Sender interface {
	Send(ctx context.Context, e Email) error
	Name() string
}

// Doer is the injectable HTTP surface for the API-based providers.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config selects + configures the email provider.
type Config struct {
	Provider  string // disabled | log | resend | sendgrid | smtp
	APIKey    string
	From      string
	SMTPHost  string
	SMTPPort  string
	SMTPUser  string
	SMTPPass  string
}

// NewSender builds the configured Sender. Unknown/empty → log (never nil).
func NewSender(cfg Config, doer Doer, log zerolog.Logger) Sender {
	if doer == nil {
		doer = &http.Client{Timeout: 15 * time.Second}
	}
	from := cfg.From
	if from == "" {
		from = "Aegis <notifications@aegis.local>"
	}
	switch strings.ToLower(cfg.Provider) {
	case "disabled":
		return noopSender{}
	case "resend":
		return &resendSender{key: cfg.APIKey, from: from, http: doer}
	case "sendgrid":
		return &sendgridSender{key: cfg.APIKey, from: from, http: doer}
	case "smtp":
		return &smtpSender{cfg: cfg, from: from}
	default:
		return &logSender{from: from, log: log}
	}
}

// ── log (default) ─────────────────────────────────────────────────────────────
type logSender struct {
	from string
	log  zerolog.Logger
}

func (s *logSender) Name() string { return "log" }
func (s *logSender) Send(_ context.Context, e Email) error {
	s.log.Info().Str("to", e.To).Str("subject", e.Subject).Str("from", s.from).
		Str("body", truncate(e.Text, 400)).Msg("email (log provider)")
	return nil
}

// ── disabled ──────────────────────────────────────────────────────────────────
type noopSender struct{}

func (noopSender) Name() string                         { return "disabled" }
func (noopSender) Send(context.Context, Email) error    { return nil }

// ── Resend ────────────────────────────────────────────────────────────────────
type resendSender struct {
	key, from string
	http      Doer
}

func (s *resendSender) Name() string { return "resend" }
func (s *resendSender) Send(ctx context.Context, e Email) error {
	payload, _ := json.Marshal(map[string]any{
		"from": s.from, "to": []string{e.To}, "subject": e.Subject, "html": e.HTML, "text": e.Text,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+s.key)
	req.Header.Set("Content-Type", "application/json")
	return do2xx(s.http, req, "resend")
}

// ── SendGrid ──────────────────────────────────────────────────────────────────
type sendgridSender struct {
	key, from string
	http      Doer
}

func (s *sendgridSender) Name() string { return "sendgrid" }
func (s *sendgridSender) Send(ctx context.Context, e Email) error {
	fromEmail := s.from
	if i := strings.LastIndex(s.from, "<"); i >= 0 {
		fromEmail = strings.TrimRight(strings.TrimSpace(s.from[i+1:]), ">")
	}
	payload, _ := json.Marshal(map[string]any{
		"personalizations": []map[string]any{{"to": []map[string]string{{"email": e.To}}}},
		"from":             map[string]string{"email": fromEmail},
		"subject":          e.Subject,
		"content":          []map[string]string{{"type": "text/plain", "value": e.Text}, {"type": "text/html", "value": e.HTML}},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.sendgrid.com/v3/mail/send", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+s.key)
	req.Header.Set("Content-Type", "application/json")
	return do2xx(s.http, req, "sendgrid")
}

// ── SMTP ──────────────────────────────────────────────────────────────────────
type smtpSender struct {
	cfg  Config
	from string
}

func (s *smtpSender) Name() string { return "smtp" }
func (s *smtpSender) Send(_ context.Context, e Email) error {
	addr := s.cfg.SMTPHost + ":" + s.cfg.SMTPPort
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		s.from, e.To, e.Subject, e.HTML)
	var auth smtp.Auth
	if s.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPass, s.cfg.SMTPHost)
	}
	return smtp.SendMail(addr, auth, s.from, []string{e.To}, []byte(msg))
}

func do2xx(doer Doer, req *http.Request, name string) error {
	resp, err := doer.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s send failed: %d", name, resp.StatusCode)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
