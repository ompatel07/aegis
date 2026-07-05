package vcs

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// BitbucketConfig configures the Bitbucket Cloud provider. Token is an OAuth
// access token (or app-password-derived bearer). WebhookSecret enables HMAC
// verification of the X-Hub-Signature header.
type BitbucketConfig struct {
	Token         string
	WebhookSecret string
}

// Bitbucket implements VCSProvider for Bitbucket Cloud.
type Bitbucket struct {
	cfg  BitbucketConfig
	http Doer
}

func NewBitbucket(cfg BitbucketConfig, doer Doer) *Bitbucket {
	return &Bitbucket{cfg: cfg, http: defaultDoer(doer)}
}

const bbAPIBase = "https://api.bitbucket.org/2.0"

func (b *Bitbucket) Name() string  { return "bitbucket" }
func (b *Bitbucket) Enabled() bool { return b != nil && b.cfg.Token != "" }

// VerifyWebhook checks the X-Hub-Signature (HMAC-SHA256) if a secret is set.
func (b *Bitbucket) VerifyWebhook(r *http.Request, body []byte) bool {
	if b.cfg.WebhookSecret == "" {
		return true
	}
	sig := r.Header.Get("X-Hub-Signature")
	if !strings.HasPrefix(sig, "sha256=") {
		return false
	}
	mac := hmac.New(sha256.New, []byte(b.cfg.WebhookSecret))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(sig))
}

func (b *Bitbucket) ParseEvent(eventHeader string, body []byte) (Event, error) {
	switch eventHeader {
	case "repo:push":
		var p struct {
			Push struct {
				Changes []struct {
					New struct {
						Name   string `json:"name"`
						Target struct {
							Hash string `json:"hash"`
						} `json:"target"`
					} `json:"new"`
				} `json:"changes"`
			} `json:"push"`
			Repository struct {
				FullName   string `json:"full_name"`
				MainBranch struct {
					Name string `json:"name"`
				} `json:"mainbranch"`
			} `json:"repository"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return Event{}, err
		}
		if len(p.Push.Changes) == 0 {
			return Event{Kind: EventUnsupported}, nil
		}
		ch := p.Push.Changes[0].New
		return Event{
			Kind: EventPush, RepoFullName: p.Repository.FullName, Branch: ch.Name,
			CommitSHA: ch.Target.Hash, DefaultBranch: p.Repository.MainBranch.Name,
			ProjectRef: p.Repository.FullName,
		}, nil
	case "pullrequest:created", "pullrequest:updated":
		var p struct {
			PullRequest struct {
				ID     int `json:"id"`
				Source struct {
					Branch struct {
						Name string `json:"name"`
					} `json:"branch"`
					Commit struct {
						Hash string `json:"hash"`
					} `json:"commit"`
				} `json:"source"`
			} `json:"pullrequest"`
			Repository struct {
				FullName   string `json:"full_name"`
				MainBranch struct {
					Name string `json:"name"`
				} `json:"mainbranch"`
			} `json:"repository"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return Event{}, err
		}
		return Event{
			Kind: EventMergeOpen, RepoFullName: p.Repository.FullName, Branch: p.PullRequest.Source.Branch.Name,
			CommitSHA: p.PullRequest.Source.Commit.Hash, PRNumber: p.PullRequest.ID,
			DefaultBranch: p.Repository.MainBranch.Name, ProjectRef: p.Repository.FullName,
		}, nil
	}
	return Event{Kind: EventUnsupported}, nil
}

func (b *Bitbucket) do(ctx context.Context, method, path string, payload any) ([]byte, int, error) {
	var body *bytes.Reader
	if payload != nil {
		raw, _ := json.Marshal(payload)
		body = bytes.NewReader(raw)
	} else {
		body = bytes.NewReader(nil)
	}
	req, _ := http.NewRequestWithContext(ctx, method, bbAPIBase+path, body)
	req.Header.Set("Authorization", "Bearer "+b.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out := new(bytes.Buffer)
	_, _ = out.ReadFrom(resp.Body)
	return out.Bytes(), resp.StatusCode, nil
}

func (b *Bitbucket) UpsertComment(ctx context.Context, projectRef string, prNumber int, commentID int64, markdown string) (int64, error) {
	if commentID > 0 {
		_, code, err := b.do(ctx, http.MethodPut,
			fmt.Sprintf("/repositories/%s/pullrequests/%d/comments/%d", projectRef, prNumber, commentID),
			map[string]any{"content": map[string]string{"raw": markdown}})
		if err == nil && code == http.StatusOK {
			return commentID, nil
		}
	}
	body, code, err := b.do(ctx, http.MethodPost,
		fmt.Sprintf("/repositories/%s/pullrequests/%d/comments", projectRef, prNumber),
		map[string]any{"content": map[string]string{"raw": markdown}})
	if err != nil {
		return 0, err
	}
	if code != http.StatusCreated {
		return 0, fmt.Errorf("bitbucket create comment: %d: %s", code, string(body))
	}
	var out struct {
		ID int64 `json:"id"`
	}
	return out.ID, json.Unmarshal(body, &out)
}

func (b *Bitbucket) SetStatus(ctx context.Context, projectRef, sha string, state State, description, targetURL string) error {
	bbState := map[State]string{StatePending: "INPROGRESS", StateSuccess: "SUCCESSFUL", StateFailed: "FAILED"}[state]
	_, _, err := b.do(ctx, http.MethodPost,
		fmt.Sprintf("/repositories/%s/commit/%s/statuses/build", projectRef, sha),
		map[string]any{"key": "aegis", "state": bbState, "url": targetURL, "description": description})
	return err
}

var bbHunkRe = regexp.MustCompile(`@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

func (b *Bitbucket) ChangedLines(ctx context.Context, projectRef string, prNumber int) (map[string]map[int]bool, error) {
	// Bitbucket returns a raw unified diff for the whole PR.
	raw, code, err := b.do(ctx, http.MethodGet,
		fmt.Sprintf("/repositories/%s/pullrequests/%d/diff", projectRef, prNumber), nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("bitbucket pr diff: %d", code)
	}
	return parseMultiFileDiff(string(raw), bbHunkRe), nil
}

var bbNewPathRe = regexp.MustCompile(`(?m)^\+\+\+ b/(.+)$`)

// parseMultiFileDiff splits a multi-file unified diff (by "diff --git") and maps
// each file's new path to its added line numbers.
func parseMultiFileDiff(diff string, hunkRe *regexp.Regexp) map[string]map[int]bool {
	out := map[string]map[int]bool{}
	parts := strings.Split(diff, "diff --git ")
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			continue
		}
		m := bbNewPathRe.FindStringSubmatch(part)
		if m == nil {
			continue
		}
		out[m[1]] = parseAddedLines(part, hunkRe)
	}
	return out
}

var _ = strconv.Atoi
