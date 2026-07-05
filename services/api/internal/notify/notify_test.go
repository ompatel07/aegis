package notify

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/models"
)

type mockDoer struct {
	status int
	last   *http.Request
}

func (m *mockDoer) Do(req *http.Request) (*http.Response, error) {
	m.last = req
	return &http.Response{StatusCode: m.status, Body: io.NopCloser(strings.NewReader(`{"id":"x"}`))}, nil
}

func sp(s string) *string { return &s }

func TestSenderFactoryDefaultsToLog(t *testing.T) {
	if NewSender(Config{}, nil, zerolog.Nop()).Name() != "log" {
		t.Fatal("empty provider should default to log")
	}
	if NewSender(Config{Provider: "disabled"}, nil, zerolog.Nop()).Name() != "disabled" {
		t.Fatal("disabled provider")
	}
	if NewSender(Config{Provider: "resend"}, nil, zerolog.Nop()).Name() != "resend" {
		t.Fatal("resend provider")
	}
}

func TestResendSendSuccessAndFailure(t *testing.T) {
	ok := &mockDoer{status: 200}
	s := NewSender(Config{Provider: "resend", APIKey: "k"}, ok, zerolog.Nop())
	if err := s.Send(context.Background(), Email{To: "a@b.com", Subject: "hi", Text: "x"}); err != nil {
		t.Fatalf("resend 200 should succeed: %v", err)
	}
	if !strings.Contains(ok.last.URL.Host, "resend.com") {
		t.Fatalf("expected resend host, got %s", ok.last.URL.Host)
	}
	fail := NewSender(Config{Provider: "resend", APIKey: "k"}, &mockDoer{status: 401}, zerolog.Nop())
	if err := fail.Send(context.Background(), Email{To: "a@b.com"}); err == nil {
		t.Fatal("resend 401 should error")
	}
}

func TestScanCompleteEmailContents(t *testing.T) {
	scan := &models.Scan{OverallGrade: sp("C")}
	findings := []models.Finding{{Severity: "critical"}, {Severity: "high"}, {Severity: "low"}}
	e := ScanCompleteEmail("dev@x.com", "http://dash/p", "acme", scan, findings)
	if !strings.Contains(e.Subject, "acme") || !strings.Contains(e.Subject, "C") {
		t.Fatalf("subject: %s", e.Subject)
	}
	if !strings.Contains(e.Text, "critical: 1") || !strings.Contains(e.HTML, "http://dash/p") {
		t.Fatalf("body missing counts/link:\n%s", e.Text)
	}
}

func TestInvitationEmailHasAcceptURL(t *testing.T) {
	e := InvitationEmail("new@x.com", "http://dash", "Acme", "boss@x.com", "tok123")
	if !strings.Contains(e.Text, "/invitations/accept?token=tok123") {
		t.Fatalf("invitation missing accept url: %s", e.Text)
	}
}

func TestSlackMessageHasBlocks(t *testing.T) {
	m := SlackScanMessage("http://dash", "acme", &models.Scan{OverallGrade: sp("B")}, []models.Finding{{Severity: "high"}})
	if len(m.Blocks) < 2 || !strings.Contains(m.Text, "acme") {
		t.Fatalf("slack message malformed: %+v", m)
	}
}
