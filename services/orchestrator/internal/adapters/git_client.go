// Package adapters integrates the orchestrator with external systems: the git
// host (clone) and the scanner service (HTTP).
package adapters

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
)

// GitClient clones repositories into per-scan workspace directories.
type GitClient struct {
	workspaceDir string
	cloneDepth   int
}

func NewGitClient(workspaceDir string, cloneDepth int) *GitClient {
	return &GitClient{workspaceDir: workspaceDir, cloneDepth: cloneDepth}
}

// Checkout is a cloned repository on disk plus a cleanup func.
type Checkout struct {
	Dir     string
	Cleanup func()
}

// authFor returns HTTP Basic auth for a token, choosing the username the host
// expects (GitHub: x-access-token, GitLab: oauth2, Bitbucket: x-token-auth).
// The token is passed as the password so it is never part of the URL — it never
// lands in a persisted repo_url, a log line, or a go-git error message.
func authFor(repoURL, token string) transport.AuthMethod {
	if token == "" {
		return nil
	}
	user := "x-access-token" // GitHub (and a safe default for most hosts)
	lc := strings.ToLower(repoURL)
	switch {
	case strings.Contains(lc, "gitlab"):
		user = "oauth2"
	case strings.Contains(lc, "bitbucket"):
		user = "x-token-auth"
	}
	return &githttp.BasicAuth{Username: user, Password: token}
}

// Clone performs a shallow clone of repoURL@branch into a fresh directory named
// after the scan id. When token is non-empty the clone is authenticated (private
// repos); the token is used as HTTP Basic auth, never embedded in the URL. The
// returned Cleanup removes the directory.
func (g *GitClient) Clone(ctx context.Context, scanID, repoURL, branch, token string) (*Checkout, error) {
	if err := os.MkdirAll(g.workspaceDir, 0o750); err != nil {
		return nil, fmt.Errorf("create workspace root: %w", err)
	}
	dir := filepath.Join(g.workspaceDir, scanID)
	// Start from a clean slate in case a previous attempt left files behind.
	_ = os.RemoveAll(dir)

	opts := &git.CloneOptions{
		URL:          repoURL,
		Auth:         authFor(repoURL, token),
		Depth:        g.cloneDepth,
		SingleBranch: true,
		Tags:         git.NoTags,
	}
	if branch != "" {
		opts.ReferenceName = plumbing.NewBranchReferenceName(branch)
	}

	cleanup := func() { _ = os.RemoveAll(dir) }

	if _, err := git.PlainCloneContext(ctx, dir, false, opts); err != nil {
		cleanup()
		return nil, g.cloneError(ctx, repoURL, branch, token, err)
	}
	return &Checkout{Dir: dir, Cleanup: cleanup}, nil
}

// cloneError turns a raw clone failure into a clear, user-facing message. A
// missing-branch failure is the common real-user case (Phase 2G): we list the
// repo's actual branches so the message tells the user exactly what to pick.
func (g *GitClient) cloneError(ctx context.Context, repoURL, branch, token string, err error) error {
	msg := strings.ToLower(err.Error())
	missingRef := branch != "" && (strings.Contains(msg, "couldn't find remote ref") ||
		strings.Contains(msg, "reference not found") || strings.Contains(msg, "not found"))
	if missingRef {
		if names := g.remoteBranches(ctx, repoURL, token); len(names) > 0 {
			avail := names
			if len(avail) > 12 {
				avail = avail[:12]
			}
			return fmt.Errorf("branch %q was not found in %s. Available branches: %s",
				branch, repoURL, strings.Join(avail, ", "))
		}
		return fmt.Errorf("branch %q was not found in %s; check the branch name", branch, repoURL)
	}
	switch {
	case strings.Contains(msg, "authentication required") || strings.Contains(msg, "authorization failed"):
		return fmt.Errorf("couldn't access %s — repository is private and the access token was missing or rejected", repoURL)
	case strings.Contains(msg, "repository not found") || strings.Contains(msg, "no such host") || strings.Contains(msg, "could not resolve"):
		return fmt.Errorf("couldn't find the repository at %s — check the URL", repoURL)
	default:
		return fmt.Errorf("clone %s failed: %v", repoURL, err)
	}
}

// remoteBranches lists a repo's branch names without cloning (best-effort).
func (g *GitClient) remoteBranches(ctx context.Context, repoURL, token string) []string {
	rem := git.NewRemote(memory.NewStorage(), &gitconfig.RemoteConfig{Name: "origin", URLs: []string{repoURL}})
	refs, err := rem.ListContext(ctx, &git.ListOptions{Auth: authFor(repoURL, token)})
	if err != nil {
		return nil
	}
	var names []string
	for _, r := range refs {
		if r.Name().IsBranch() {
			names = append(names, r.Name().Short())
		}
	}
	sort.Strings(names)
	return names
}

// ExtractUpload extracts an uploaded code archive (Method B) into a per-scan
// sandbox instead of cloning. The Cleanup removes both the sandbox and the
// uploaded archive, so nothing persists past the scan.
func (g *GitClient) ExtractUpload(scanID, archivePath string) (*Checkout, error) {
	if err := os.MkdirAll(g.workspaceDir, 0o750); err != nil {
		return nil, fmt.Errorf("create workspace root: %w", err)
	}
	dir := filepath.Join(g.workspaceDir, scanID)
	_ = os.RemoveAll(dir)
	cleanup := func() {
		_ = os.RemoveAll(dir)
		_ = os.Remove(archivePath) // uploaded archive never persists past the scan
	}
	if _, err := ExtractArchive(archivePath, dir); err != nil {
		cleanup()
		return nil, fmt.Errorf("extract upload: %w", err)
	}
	return &Checkout{Dir: dir, Cleanup: cleanup}, nil
}

// DirSizeMB returns the total size of a directory tree in megabytes.
func DirSizeMB(dir string) (int, error) {
	var total int64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return int(total / (1024 * 1024)), nil
}
