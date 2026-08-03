// Package gitremote inspects a remote git repository without cloning it — used to
// auto-detect the default branch and list branches when a user connects a repo,
// so Aegis never assumes "main" (the Phase-2G real-user branch bug).
package gitremote

import (
	"context"
	"errors"
	"sort"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
)

// ErrNoBranches is returned when a reachable remote advertises no branches
// (e.g. a brand-new empty repository).
var ErrNoBranches = errors.New("repository has no branches")

// authFor mirrors the orchestrator's clone auth: token as HTTP Basic password,
// with the username each host expects. Empty token → anonymous (public repos).
func authFor(repoURL, token string) transport.AuthMethod {
	if token == "" {
		return nil
	}
	user := "x-access-token" // GitHub + safe default
	lc := strings.ToLower(repoURL)
	switch {
	case strings.Contains(lc, "gitlab"):
		user = "oauth2"
	case strings.Contains(lc, "bitbucket"):
		user = "x-token-auth"
	}
	return &githttp.BasicAuth{Username: user, Password: token}
}

// Detect lists the remote's refs (no clone) and returns the default branch —
// resolved from the server's symbolic HEAD, falling back to main/master — plus
// the sorted list of branch names. A non-nil error means the remote could not be
// reached/authenticated (surface it to the user as a connection error).
func Detect(ctx context.Context, repoURL, token string) (defaultBranch string, branches []string, err error) {
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})
	refs, err := rem.ListContext(ctx, &git.ListOptions{Auth: authFor(repoURL, token)})
	if err != nil {
		return "", nil, err
	}

	var headTarget plumbing.ReferenceName
	seen := map[string]bool{}
	for _, r := range refs {
		if r.Name() == plumbing.HEAD && r.Type() == plumbing.SymbolicReference {
			headTarget = r.Target()
		}
		if r.Name().IsBranch() {
			name := r.Name().Short()
			if !seen[name] {
				seen[name] = true
				branches = append(branches, name)
			}
		}
	}
	sort.Strings(branches)

	if len(branches) == 0 {
		return "", nil, ErrNoBranches
	}

	switch {
	case headTarget != "" && headTarget.IsBranch():
		defaultBranch = headTarget.Short()
	case seen["main"]:
		defaultBranch = "main"
	case seen["master"]:
		defaultBranch = "master"
	default:
		defaultBranch = branches[0]
	}
	return defaultBranch, branches, nil
}
