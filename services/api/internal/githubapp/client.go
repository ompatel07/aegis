package githubapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Client performs GitHub REST calls scoped to one installation.
type Client struct {
	app            *App
	installationID int64
}

// Client returns an installation-scoped client.
func (a *App) Client(installationID int64) *Client {
	return &Client{app: a, installationID: installationID}
}

func (c *Client) request(ctx context.Context, method, path string, payload any) ([]byte, int, error) {
	token, err := c.app.InstallationToken(ctx, c.installationID)
	if err != nil {
		return nil, 0, err
	}
	var body *bytes.Reader
	if payload != nil {
		raw, _ := json.Marshal(payload)
		body = bytes.NewReader(raw)
	} else {
		body = bytes.NewReader(nil)
	}
	req, _ := http.NewRequestWithContext(ctx, method, apiBase+path, body)
	req.Header.Set("Authorization", authHeader(token))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	return c.app.do(req)
}

// CheckRunOutput carries a check-run's rich output + inline annotations.
type CheckRunOutput struct {
	Title       string       `json:"title"`
	Summary     string       `json:"summary"`
	Annotations []Annotation `json:"annotations,omitempty"`
}

// Annotation is one inline PR annotation (Checks API).
type Annotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"` // notice | warning | failure
	Message         string `json:"message"`
	Title           string `json:"title,omitempty"`
}

// CreateCheckRun opens a check run (status "in_progress" or "queued").
func (c *Client) CreateCheckRun(ctx context.Context, repoFullName, name, headSHA, status, detailsURL string) (int64, error) {
	payload := map[string]any{"name": name, "head_sha": headSHA, "status": status, "details_url": detailsURL}
	body, code, err := c.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/check-runs", repoFullName), payload)
	if err != nil {
		return 0, err
	}
	if code != http.StatusCreated {
		return 0, fmt.Errorf("create check-run: %d: %s", code, string(body))
	}
	var out struct {
		ID int64 `json:"id"`
	}
	return out.ID, json.Unmarshal(body, &out)
}

// UpdateCheckRun completes a check run with a conclusion + output/annotations.
func (c *Client) UpdateCheckRun(ctx context.Context, repoFullName string, checkRunID int64, conclusion string, output CheckRunOutput) error {
	// GitHub caps annotations at 50 per request.
	if len(output.Annotations) > 50 {
		output.Annotations = output.Annotations[:50]
	}
	payload := map[string]any{"status": "completed", "conclusion": conclusion, "output": output}
	body, code, err := c.request(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/check-runs/%d", repoFullName, checkRunID), payload)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("update check-run: %d: %s", code, string(body))
	}
	return nil
}

// UpsertIssueComment posts a new PR comment, or edits the existing one when
// commentID is non-zero — the single-updateable-comment strategy (no spam).
func (c *Client) UpsertIssueComment(ctx context.Context, repoFullName string, prNumber int, commentID int64, markdown string) (int64, error) {
	if commentID > 0 {
		_, code, err := c.request(ctx, http.MethodPatch,
			fmt.Sprintf("/repos/%s/issues/comments/%d", repoFullName, commentID), map[string]any{"body": markdown})
		if err != nil {
			return 0, err
		}
		if code == http.StatusOK {
			return commentID, nil
		}
		// Comment was deleted upstream — fall through and create a fresh one.
	}
	body, code, err := c.request(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/issues/%d/comments", repoFullName, prNumber), map[string]any{"body": markdown})
	if err != nil {
		return 0, err
	}
	if code != http.StatusCreated {
		return 0, fmt.Errorf("create pr comment: %d: %s", code, string(body))
	}
	var out struct {
		ID int64 `json:"id"`
	}
	return out.ID, json.Unmarshal(body, &out)
}

// SetCommitStatus posts a commit status (belt-and-suspenders alongside the check).
func (c *Client) SetCommitStatus(ctx context.Context, repoFullName, sha, state, description, targetURL string) error {
	payload := map[string]any{"state": state, "description": description, "context": "aegis/security", "target_url": targetURL}
	_, _, err := c.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/statuses/%s", repoFullName, sha), payload)
	return err
}

var hunkRe = regexp.MustCompile(`@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// ChangedLines returns, per file, the set of line numbers the PR added/changed —
// used to annotate only touched lines. Parses the unified-diff patches from the
// PR files endpoint.
func (c *Client) ChangedLines(ctx context.Context, repoFullName string, prNumber int) (map[string]map[int]bool, error) {
	body, code, err := c.request(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/pulls/%d/files?per_page=300", repoFullName, prNumber), nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("list pr files: %d", code)
	}
	var files []struct {
		Filename string `json:"filename"`
		Patch    string `json:"patch"`
	}
	if err := json.Unmarshal(body, &files); err != nil {
		return nil, err
	}
	out := map[string]map[int]bool{}
	for _, f := range files {
		out[f.Filename] = addedLines(f.Patch)
	}
	return out, nil
}

// addedLines parses a unified-diff patch into the set of added line numbers.
func addedLines(patch string) map[int]bool {
	lines := map[int]bool{}
	if patch == "" {
		return lines
	}
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
			// removed line — does not advance the new-file counter
		default:
			cur++
		}
	}
	return lines
}
