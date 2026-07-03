package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// FixInput is the snippet-only context sent to the model. The Snippet is the
// vulnerable lines already captured with the finding — never the full file.
type FixInput struct {
	RuleName string
	Message  string
	CWE      string
	File     string
	Line     int
	Language string
	Snippet  string
}

// Suggestion is the advisory result returned to the UI.
type Suggestion struct {
	Suggestion string `json:"suggestion"`
	Model      string `json:"model"`
	Provider   string `json:"provider"`
}

const systemPrompt = "You are a secure-coding assistant. Given a single vulnerable " +
	"code snippet and a finding description, return a corrected version of ONLY that " +
	"snippet in a fenced code block, then a 2-3 sentence explanation. Do not ask for " +
	"more of the file. Keep changes minimal and safe."

// BuildFixPrompt returns the (system, user) messages. The snippet is truncated
// defensively so we never send more than a small window of code.
func BuildFixPrompt(in FixInput) (string, string) {
	snippet := in.Snippet
	if len(snippet) > 4000 {
		snippet = snippet[:4000]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Finding: %s\n", in.RuleName)
	if in.Message != "" {
		fmt.Fprintf(&b, "Description: %s\n", in.Message)
	}
	if in.CWE != "" {
		fmt.Fprintf(&b, "Weakness: %s\n", in.CWE)
	}
	if in.Language != "" {
		fmt.Fprintf(&b, "Language: %s\n", in.Language)
	}
	fmt.Fprintf(&b, "Location: %s", in.File)
	if in.Line > 0 {
		fmt.Fprintf(&b, ":%d", in.Line)
	}
	b.WriteString("\n\nVulnerable snippet:\n```\n")
	b.WriteString(snippet)
	b.WriteString("\n```\n\nReturn a fixed version of this snippet and a short explanation.")
	return systemPrompt, b.String()
}

// PromptHash is stored in the audit log (never the prompt text itself).
func PromptHash(system, user string) string {
	h := sha256.Sum256([]byte(system + "\x00" + user))
	return hex.EncodeToString(h[:])
}
