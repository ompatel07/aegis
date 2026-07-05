// Package vcs is the multi-VCS abstraction (Phase 2C TASK 2). A single
// VCSProvider interface is implemented for GitLab and Bitbucket (GitHub keeps its
// richer App integration in internal/githubapp). This is Aegis's real
// differentiator vs GitHub Advanced Security: PR/MR checks + a single updateable
// comment work everywhere, not just on GitHub.
//
// All providers accept an injectable HTTP Doer so they can be verified end-to-end
// against a mock (the agreed build-real+simulate path) without a live account.
package vcs

import (
	"context"
	"net/http"
	"time"
)

// Doer is the minimal HTTP surface a provider needs.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

func defaultDoer(d Doer) Doer {
	if d != nil {
		return d
	}
	return &http.Client{Timeout: 20 * time.Second}
}

// EventKind is the normalized webhook event type.
type EventKind string

const (
	EventPush        EventKind = "push"         // branch push (scan default branch)
	EventMergeOpen   EventKind = "merge_open"   // MR/PR opened or updated (scan + comment)
	EventUnsupported EventKind = "unsupported"  // acknowledged, ignored
)

// Event is a provider-agnostic webhook event.
type Event struct {
	Kind         EventKind
	RepoFullName string // group/project or workspace/repo
	Branch       string
	CommitSHA    string
	PRNumber     int    // MR iid / PR id
	DefaultBranch string
	ProjectRef   string // provider project id/slug used for API calls
}

// State is a normalized commit/pipeline status.
type State string

const (
	StatePending State = "pending"
	StateSuccess State = "success"
	StateFailed  State = "failed"
)

// VCSProvider is the common contract implemented per platform.
type VCSProvider interface {
	// Name identifies the provider ("gitlab" | "bitbucket").
	Name() string
	// Enabled reports whether credentials are configured.
	Enabled() bool
	// VerifyWebhook authenticates an inbound webhook request.
	VerifyWebhook(r *http.Request, body []byte) bool
	// ParseEvent normalizes a webhook payload for the given event header.
	ParseEvent(eventHeader string, body []byte) (Event, error)
	// UpsertComment posts (commentID==0) or edits the single PR/MR comment,
	// returning the comment id — the no-spam strategy.
	UpsertComment(ctx context.Context, projectRef string, prNumber int, commentID int64, markdown string) (int64, error)
	// SetStatus sets a commit/pipeline status for the head SHA.
	SetStatus(ctx context.Context, projectRef, sha string, state State, description, targetURL string) error
	// ChangedLines returns, per file, the added line numbers in the PR/MR.
	ChangedLines(ctx context.Context, projectRef string, prNumber int) (map[string]map[int]bool, error)
}
