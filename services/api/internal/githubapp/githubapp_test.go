package githubapp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockDoer replays queued responses and records the requests it received — the
// "simulated GitHub" used to verify the App without a live org.
type mockDoer struct {
	calls     []*http.Request
	responses []mockResp
}
type mockResp struct {
	status int
	body   string
}

func (m *mockDoer) Do(req *http.Request) (*http.Response, error) {
	m.calls = append(m.calls, req)
	r := m.responses[0]
	m.responses = m.responses[1:]
	return &http.Response{StatusCode: r.status, Body: io.NopCloser(strings.NewReader(r.body))}, nil
}

func testKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

func TestDisabledWhenUnconfigured(t *testing.T) {
	app, err := New(Config{}, nil)
	if err != nil || app.Enabled() {
		t.Fatalf("expected nil/disabled app, got app=%v err=%v", app, err)
	}
}

func TestInstallationTokenMintedAndCached(t *testing.T) {
	m := &mockDoer{responses: []mockResp{
		{http.StatusCreated, `{"token":"ghs_abc","expires_at":"2999-01-01T00:00:00Z"}`},
	}}
	app, err := New(Config{AppID: "123", PrivateKeyPEM: testKeyPEM(t)}, m)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := app.InstallationToken(context.Background(), 42)
	if err != nil || tok != "ghs_abc" {
		t.Fatalf("token=%q err=%v", tok, err)
	}
	// Second call must be served from cache (no more queued responses).
	tok2, err := app.InstallationToken(context.Background(), 42)
	if err != nil || tok2 != "ghs_abc" {
		t.Fatalf("cached token=%q err=%v", tok2, err)
	}
	if len(m.calls) != 1 {
		t.Fatalf("expected 1 GitHub call (rest cached), got %d", len(m.calls))
	}
	// The app authenticated with a signed JWT.
	if !strings.HasPrefix(m.calls[0].Header.Get("Authorization"), "Bearer ") {
		t.Fatal("expected Bearer app JWT on token request")
	}
}

func TestSingleUpdateableComment(t *testing.T) {
	m := &mockDoer{responses: []mockResp{
		{http.StatusCreated, `{"token":"ghs_x","expires_at":"2999-01-01T00:00:00Z"}`}, // token
		{http.StatusCreated, `{"id":555}`},                                            // create comment
		{http.StatusOK, `{"id":555}`},                                                 // update comment
	}}
	app, _ := New(Config{AppID: "1", PrivateKeyPEM: testKeyPEM(t)}, m)
	c := app.Client(42)

	id, err := c.UpsertIssueComment(context.Background(), "acme/app", 7, 0, "first")
	if err != nil || id != 555 {
		t.Fatalf("create: id=%d err=%v", id, err)
	}
	// Update reuses the SAME comment id (no new comment → no spam).
	id2, err := c.UpsertIssueComment(context.Background(), "acme/app", 7, id, "updated")
	if err != nil || id2 != 555 {
		t.Fatalf("update: id=%d err=%v", id2, err)
	}
	last := m.calls[len(m.calls)-1]
	if last.Method != http.MethodPatch || !strings.Contains(last.URL.Path, "/issues/comments/555") {
		t.Fatalf("update should PATCH the existing comment, got %s %s", last.Method, last.URL.Path)
	}
}

func TestCreateCheckRun(t *testing.T) {
	m := &mockDoer{responses: []mockResp{
		{http.StatusCreated, `{"token":"t","expires_at":"2999-01-01T00:00:00Z"}`},
		{http.StatusCreated, `{"id":9001}`},
	}}
	app, _ := New(Config{AppID: "1", PrivateKeyPEM: testKeyPEM(t)}, m)
	id, err := app.Client(1).CreateCheckRun(context.Background(), "acme/app", "Aegis Security", "sha1", "in_progress", "http://x")
	if err != nil || id != 9001 {
		t.Fatalf("checkrun id=%d err=%v", id, err)
	}
}

func TestVerifySignature(t *testing.T) {
	secret, payload := "s3cr3t", []byte(`{"hello":"world"}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	good := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if !VerifySignature(secret, payload, good) {
		t.Fatal("valid signature rejected")
	}
	if VerifySignature(secret, payload, "sha256=deadbeef") {
		t.Fatal("invalid signature accepted")
	}
	if !VerifySignature("", payload, "anything") {
		t.Fatal("empty secret should skip verification")
	}
}

func TestAddedLinesParsesPatch(t *testing.T) {
	patch := "@@ -1,3 +1,4 @@\n line1\n-old\n+new1\n+new2\n line3"
	// New-file lines: 1 (context), 2 (+new1), 3 (+new2), 4 (context line3).
	added := addedLines(patch)
	if !added[2] || !added[3] {
		t.Fatalf("expected added lines 2,3; got %v", added)
	}
	if added[1] || added[4] {
		t.Fatalf("context lines must not be marked added; got %v", added)
	}
}
