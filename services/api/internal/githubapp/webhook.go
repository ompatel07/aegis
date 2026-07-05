package githubapp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// VerifySignature checks GitHub's X-Hub-Signature-256 header (HMAC-SHA256) in
// constant time. An empty secret means signatures aren't enforced (dev only).
func VerifySignature(secret string, payload []byte, sigHeader string) bool {
	if secret == "" {
		return true
	}
	if !strings.HasPrefix(sigHeader, "sha256=") {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(sigHeader))
}

// ── Event payloads (only the fields Aegis uses) ───────────────────────────────

type Repo struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	CloneURL      string `json:"clone_url"`
}

type Account struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

type Installation struct {
	ID int64 `json:"id"`
}

// PushEvent — a branch push.
type PushEvent struct {
	Ref          string       `json:"ref"`  // refs/heads/<branch>
	After        string       `json:"after"` // head sha
	Repository   Repo         `json:"repository"`
	Installation Installation `json:"installation"`
}

func (e PushEvent) Branch() string { return strings.TrimPrefix(e.Ref, "refs/heads/") }

// PullRequestEvent — opened / synchronize / reopened.
type PullRequestEvent struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Head struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
	} `json:"pull_request"`
	Repository   Repo         `json:"repository"`
	Installation Installation `json:"installation"`
}

// InstallationEvent — created / deleted.
type InstallationEvent struct {
	Action       string `json:"action"`
	Installation struct {
		ID          int64          `json:"id"`
		Account     Account        `json:"account"`
		Permissions map[string]any `json:"permissions"`
	} `json:"installation"`
	Repositories []Repo `json:"repositories"`
}

// InstallationRepositoriesEvent — added / removed.
type InstallationRepositoriesEvent struct {
	Action              string       `json:"action"`
	Installation        Installation `json:"installation"`
	RepositoriesAdded   []Repo       `json:"repositories_added"`
	RepositoriesRemoved []Repo       `json:"repositories_removed"`
}

// CheckRunEvent — rerequested.
type CheckRunEvent struct {
	Action       string       `json:"action"`
	CheckRun     struct {
		HeadSHA string `json:"head_sha"`
	} `json:"check_run"`
	Repository   Repo         `json:"repository"`
	Installation Installation `json:"installation"`
}

// Parse unmarshals a payload into T.
func Parse[T any](payload []byte) (T, error) {
	var v T
	err := json.Unmarshal(payload, &v)
	return v, err
}
