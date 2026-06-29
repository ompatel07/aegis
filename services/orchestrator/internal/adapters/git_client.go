// Package adapters integrates the orchestrator with external systems: the git
// host (clone) and the scanner service (HTTP).
package adapters

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
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

// Clone performs a shallow clone of repoURL@branch into a fresh directory named
// after the scan id. The returned Cleanup removes the directory.
func (g *GitClient) Clone(ctx context.Context, scanID, repoURL, branch string) (*Checkout, error) {
	if err := os.MkdirAll(g.workspaceDir, 0o750); err != nil {
		return nil, fmt.Errorf("create workspace root: %w", err)
	}
	dir := filepath.Join(g.workspaceDir, scanID)
	// Start from a clean slate in case a previous attempt left files behind.
	_ = os.RemoveAll(dir)

	opts := &git.CloneOptions{
		URL:          repoURL,
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
		return nil, fmt.Errorf("clone %s: %w", repoURL, err)
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
