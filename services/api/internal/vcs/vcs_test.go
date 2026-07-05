package vcs

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

// ── GitLab ────────────────────────────────────────────────────────────────────

func TestGitLabDisabledWithoutToken(t *testing.T) {
	if NewGitLab(GitLabConfig{}, nil).Enabled() {
		t.Fatal("gitlab should be disabled without a token")
	}
}

func TestGitLabWebhookTokenVerify(t *testing.T) {
	g := NewGitLab(GitLabConfig{Token: "t", WebhookSecret: "s3cr3t"}, nil)
	ok := httptest.NewRequest("POST", "/", nil)
	ok.Header.Set("X-Gitlab-Token", "s3cr3t")
	bad := httptest.NewRequest("POST", "/", nil)
	bad.Header.Set("X-Gitlab-Token", "nope")
	if !g.VerifyWebhook(ok, nil) || g.VerifyWebhook(bad, nil) {
		t.Fatal("gitlab token verification wrong")
	}
}

func TestGitLabParseMergeRequest(t *testing.T) {
	g := NewGitLab(GitLabConfig{Token: "t"}, nil)
	payload := `{"object_attributes":{"iid":7,"action":"open","source_branch":"feat",
		"last_commit":{"id":"abc123"}},"project":{"id":42,"path_with_namespace":"grp/app","default_branch":"main"}}`
	ev, err := g.ParseEvent("Merge Request Hook", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != EventMergeOpen || ev.PRNumber != 7 || ev.CommitSHA != "abc123" || ev.ProjectRef != "42" || ev.RepoFullName != "grp/app" {
		t.Fatalf("bad gitlab MR event: %+v", ev)
	}
}

func TestGitLabSingleUpdateableNote(t *testing.T) {
	m := &mockDoer{responses: []mockResp{
		{http.StatusCreated, `{"id":88}`}, // create note
		{http.StatusOK, `{"id":88}`},      // update note
	}}
	g := NewGitLab(GitLabConfig{Token: "t"}, m)
	id, err := g.UpsertComment(context.Background(), "42", 7, 0, "hello")
	if err != nil || id != 88 {
		t.Fatalf("create note id=%d err=%v", id, err)
	}
	id2, _ := g.UpsertComment(context.Background(), "42", 7, id, "updated")
	if id2 != 88 {
		t.Fatalf("update should reuse note 88, got %d", id2)
	}
	last := m.calls[len(m.calls)-1]
	if last.Method != http.MethodPut || !strings.Contains(last.URL.Path, "/notes/88") {
		t.Fatalf("update should PUT existing note; got %s %s", last.Method, last.URL.Path)
	}
}

// ── Bitbucket ─────────────────────────────────────────────────────────────────

func TestBitbucketWebhookHMAC(t *testing.T) {
	b := NewBitbucket(BitbucketConfig{Token: "t", WebhookSecret: "sec"}, nil)
	body := []byte(`{"x":1}`)
	mac := hmac.New(sha256.New, []byte("sec"))
	mac.Write(body)
	good := httptest.NewRequest("POST", "/", nil)
	good.Header.Set("X-Hub-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	bad := httptest.NewRequest("POST", "/", nil)
	bad.Header.Set("X-Hub-Signature", "sha256=deadbeef")
	if !b.VerifyWebhook(good, body) || b.VerifyWebhook(bad, body) {
		t.Fatal("bitbucket HMAC verification wrong")
	}
}

func TestBitbucketParsePullRequest(t *testing.T) {
	b := NewBitbucket(BitbucketConfig{Token: "t"}, nil)
	payload := `{"pullrequest":{"id":3,"source":{"branch":{"name":"feat"},"commit":{"hash":"deadbeef"}}},
		"repository":{"full_name":"ws/repo","mainbranch":{"name":"main"}}}`
	ev, err := b.ParseEvent("pullrequest:created", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != EventMergeOpen || ev.PRNumber != 3 || ev.CommitSHA != "deadbeef" || ev.ProjectRef != "ws/repo" {
		t.Fatalf("bad bitbucket PR event: %+v", ev)
	}
}

func TestBitbucketDiffParsing(t *testing.T) {
	diff := "diff --git a/app.js b/app.js\n--- a/app.js\n+++ b/app.js\n@@ -1,2 +1,3 @@\n line1\n+added\n line2\n"
	changed := parseMultiFileDiff(diff, bbHunkRe)
	lines, ok := changed["app.js"]
	if !ok || !lines[2] {
		t.Fatalf("expected app.js line 2 added; got %v", changed)
	}
}
