package ai

import (
	"context"
	"strings"
	"testing"
)

func TestNewSelectsBackendOrDisabled(t *testing.T) {
	if New(Config{Provider: "disabled"}) != nil {
		t.Fatal("disabled should return nil backend")
	}
	if New(Config{Provider: ""}) != nil {
		t.Fatal("empty provider should return nil backend")
	}
	if b := New(Config{Provider: "mock"}); b == nil || b.Provider() != "mock" {
		t.Fatalf("mock backend not selected: %+v", b)
	}
	if b := New(Config{Provider: "claude"}); b == nil || b.Provider() != "claude" {
		t.Fatal("claude backend not selected")
	}
	if b := New(Config{Provider: "openai", Model: "gpt-4o"}); b == nil || b.Provider() != "openai" || b.Model() != "gpt-4o" {
		t.Fatal("openai backend/model not selected")
	}
	// Azure / self-hosted resolve to the OpenAI-compatible adapter.
	if b := New(Config{Provider: "self-hosted"}); b == nil || b.Provider() != "openai" {
		t.Fatal("self-hosted should map to openai-compatible adapter")
	}
}

func TestMockBackendIsDeterministicAndOffline(t *testing.T) {
	b := New(Config{Provider: "mock"})
	out, err := b.Complete(context.Background(), "sys", "user")
	if err != nil || out == "" {
		t.Fatalf("mock complete: %v %q", err, out)
	}
	if !strings.Contains(out, "mock backend") {
		t.Fatalf("unexpected mock output: %q", out)
	}
}

func TestBuildFixPromptIsSnippetOnly(t *testing.T) {
	sys, user := BuildFixPrompt(FixInput{
		RuleName: "SQL injection", Message: "Untrusted input in query", CWE: "CWE-89",
		File: "app/x.js", Line: 42, Language: "javascript",
		Snippet: "db.query('SELECT * FROM u WHERE id=' + id)",
	})
	if !strings.Contains(sys, "secure-coding") {
		t.Fatal("system prompt missing")
	}
	if !strings.Contains(user, "db.query") || !strings.Contains(user, "app/x.js:42") {
		t.Fatalf("user prompt missing snippet/location: %q", user)
	}
	// The prompt must NOT invite sending more of the file.
	if strings.Contains(strings.ToLower(user), "full file") {
		t.Fatal("prompt should not request the full file")
	}
}

func TestPromptHashStableAndSensitive(t *testing.T) {
	h1 := PromptHash("a", "b")
	h2 := PromptHash("a", "b")
	h3 := PromptHash("a", "c")
	if h1 != h2 {
		t.Fatal("hash should be stable")
	}
	if h1 == h3 {
		t.Fatal("hash should change with the prompt")
	}
	if len(h1) != 64 {
		t.Fatalf("expected sha256 hex, got %d chars", len(h1))
	}
}
