package vcs

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// GitLabConfig configures the GitLab provider. BaseURL supports gitlab.com AND
// self-hosted instances. Token is an API token (or OAuth access token).
type GitLabConfig struct {
	BaseURL       string // e.g. https://gitlab.com
	Token         string
	WebhookSecret string
}

// GitLab implements VCSProvider for GitLab.com and self-hosted GitLab.
type GitLab struct {
	cfg  GitLabConfig
	http Doer
}

func NewGitLab(cfg GitLabConfig, doer Doer) *GitLab {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://gitlab.com"
	}
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")
	return &GitLab{cfg: cfg, http: defaultDoer(doer)}
}

func (g *GitLab) Name() string    { return "gitlab" }
func (g *GitLab) Enabled() bool   { return g != nil && g.cfg.Token != "" }
func (g *GitLab) apiURL(p string) string { return g.cfg.BaseURL + "/api/v4" + p }

// VerifyWebhook checks the X-Gitlab-Token header against the configured secret.
func (g *GitLab) VerifyWebhook(r *http.Request, _ []byte) bool {
	if g.cfg.WebhookSecret == "" {
		return true
	}
	got := r.Header.Get("X-Gitlab-Token")
	return subtle.ConstantTimeCompare([]byte(got), []byte(g.cfg.WebhookSecret)) == 1
}

func (g *GitLab) ParseEvent(eventHeader string, body []byte) (Event, error) {
	switch eventHeader {
	case "Push Hook":
		var p struct {
			Ref     string `json:"ref"`
			After   string `json:"checkout_sha"`
			Project struct {
				ID                int64  `json:"id"`
				PathWithNamespace string `json:"path_with_namespace"`
				DefaultBranch     string `json:"default_branch"`
			} `json:"project"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return Event{}, err
		}
		branch := strings.TrimPrefix(p.Ref, "refs/heads/")
		return Event{
			Kind: EventPush, RepoFullName: p.Project.PathWithNamespace, Branch: branch,
			CommitSHA: p.After, DefaultBranch: p.Project.DefaultBranch,
			ProjectRef: strconv.FormatInt(p.Project.ID, 10),
		}, nil
	case "Merge Request Hook":
		var p struct {
			ObjectAttributes struct {
				IID          int    `json:"iid"`
				Action       string `json:"action"`
				SourceBranch string `json:"source_branch"`
				LastCommit   struct {
					ID string `json:"id"`
				} `json:"last_commit"`
			} `json:"object_attributes"`
			Project struct {
				ID                int64  `json:"id"`
				PathWithNamespace string `json:"path_with_namespace"`
				DefaultBranch     string `json:"default_branch"`
			} `json:"project"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return Event{}, err
		}
		a := p.ObjectAttributes
		if a.Action != "open" && a.Action != "reopen" && a.Action != "update" {
			return Event{Kind: EventUnsupported}, nil
		}
		return Event{
			Kind: EventMergeOpen, RepoFullName: p.Project.PathWithNamespace, Branch: a.SourceBranch,
			CommitSHA: a.LastCommit.ID, PRNumber: a.IID, DefaultBranch: p.Project.DefaultBranch,
			ProjectRef: strconv.FormatInt(p.Project.ID, 10),
		}, nil
	}
	return Event{Kind: EventUnsupported}, nil
}

func (g *GitLab) do(ctx context.Context, method, path string, payload any) ([]byte, int, error) {
	var body *bytes.Reader
	if payload != nil {
		raw, _ := json.Marshal(payload)
		body = bytes.NewReader(raw)
	} else {
		body = bytes.NewReader(nil)
	}
	req, _ := http.NewRequestWithContext(ctx, method, g.apiURL(path), body)
	req.Header.Set("PRIVATE-TOKEN", g.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out := new(bytes.Buffer)
	_, _ = out.ReadFrom(resp.Body)
	return out.Bytes(), resp.StatusCode, nil
}

func (g *GitLab) UpsertComment(ctx context.Context, projectRef string, prNumber int, commentID int64, markdown string) (int64, error) {
	if commentID > 0 {
		_, code, err := g.do(ctx, http.MethodPut,
			fmt.Sprintf("/projects/%s/merge_requests/%d/notes/%d", projectRef, prNumber, commentID),
			map[string]any{"body": markdown})
		if err == nil && code == http.StatusOK {
			return commentID, nil
		}
	}
	body, code, err := g.do(ctx, http.MethodPost,
		fmt.Sprintf("/projects/%s/merge_requests/%d/notes", projectRef, prNumber),
		map[string]any{"body": markdown})
	if err != nil {
		return 0, err
	}
	if code != http.StatusCreated {
		return 0, fmt.Errorf("gitlab create note: %d: %s", code, string(body))
	}
	var out struct {
		ID int64 `json:"id"`
	}
	return out.ID, json.Unmarshal(body, &out)
}

func (g *GitLab) SetStatus(ctx context.Context, projectRef, sha string, state State, description, targetURL string) error {
	glState := map[State]string{StatePending: "running", StateSuccess: "success", StateFailed: "failed"}[state]
	_, _, err := g.do(ctx, http.MethodPost,
		fmt.Sprintf("/projects/%s/statuses/%s", projectRef, sha),
		map[string]any{"state": glState, "name": "aegis", "description": description, "target_url": targetURL})
	return err
}

var glHunkRe = regexp.MustCompile(`@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

func (g *GitLab) ChangedLines(ctx context.Context, projectRef string, prNumber int) (map[string]map[int]bool, error) {
	body, code, err := g.do(ctx, http.MethodGet,
		fmt.Sprintf("/projects/%s/merge_requests/%d/changes", projectRef, prNumber), nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("gitlab mr changes: %d", code)
	}
	var doc struct {
		Changes []struct {
			NewPath string `json:"new_path"`
			Diff    string `json:"diff"`
		} `json:"changes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := map[string]map[int]bool{}
	for _, c := range doc.Changes {
		out[c.NewPath] = parseAddedLines(c.Diff, glHunkRe)
	}
	return out, nil
}

// parseAddedLines converts a unified diff into the set of added new-file lines.
func parseAddedLines(patch string, hunkRe *regexp.Regexp) map[int]bool {
	lines := map[int]bool{}
	cur := 0
	for _, ln := range strings.Split(patch, "\n") {
		if m := hunkRe.FindStringSubmatch(ln); m != nil {
			cur, _ = strconv.Atoi(m[1])
			continue
		}
		switch {
		case strings.HasPrefix(ln, "+"):
			lines[cur] = true
			cur++
		case strings.HasPrefix(ln, "-"):
		default:
			cur++
		}
	}
	return lines
}
