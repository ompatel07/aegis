// Package githubapp implements a full GitHub App (Phase 2C TASK 1): JWT app
// authentication, installation-token management, the Checks API, and the
// single-updateable PR comment strategy.
//
// Credentials come from config (App id, PEM private key, webhook secret, OAuth
// client id/secret). When unset, App features are disabled — the platform still
// runs (mirrors the AI layer's opt-in posture). The HTTP transport is injectable
// so the App can be exercised end-to-end against a mock in tests (the agreed
// "build real + simulate" verification path) without a live GitHub org.
package githubapp

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const apiBase = "https://api.github.com"

// Doer is the minimal HTTP surface the App needs; the real client is
// *http.Client, tests inject a recorder/mock.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config holds the GitHub App credentials.
type Config struct {
	AppID         string
	PrivateKeyPEM string
	WebhookSecret string
	ClientID      string
	ClientSecret  string
	Slug          string // for the install URL: https://github.com/apps/<slug>/installations/new
}

// App is a configured GitHub App. A nil App means the feature is disabled.
type App struct {
	cfg        Config
	privateKey *rsa.PrivateKey
	http       Doer

	mu     sync.Mutex
	tokens map[int64]cachedToken // installation id -> access token
}

type cachedToken struct {
	token   string
	expires time.Time
}

// New builds an App from config. Returns (nil, nil) when unconfigured.
func New(cfg Config, doer Doer) (*App, error) {
	if cfg.AppID == "" || cfg.PrivateKeyPEM == "" {
		return nil, nil
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(cfg.PrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse github app private key: %w", err)
	}
	if doer == nil {
		doer = &http.Client{Timeout: 20 * time.Second}
	}
	return &App{cfg: cfg, privateKey: key, http: doer, tokens: map[int64]cachedToken{}}, nil
}

func (a *App) Enabled() bool          { return a != nil }
func (a *App) WebhookSecret() string  { return a.cfg.WebhookSecret }
func (a *App) InstallURL() string {
	if a.cfg.Slug == "" {
		return ""
	}
	return "https://github.com/apps/" + a.cfg.Slug + "/installations/new"
}

// appJWT mints a short-lived RS256 JWT identifying the App (used to mint
// installation tokens). Valid 9 minutes (GitHub allows up to 10).
func (a *App) appJWT() (string, error) {
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    a.cfg.AppID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	})
	return tok.SignedString(a.privateKey)
}

// InstallationToken returns a cached (or freshly minted) installation access
// token for the given installation, valid for the next minute at least.
func (a *App) InstallationToken(ctx context.Context, installationID int64) (string, error) {
	a.mu.Lock()
	if t, ok := a.tokens[installationID]; ok && time.Until(t.expires) > time.Minute {
		a.mu.Unlock()
		return t.token, nil
	}
	a.mu.Unlock()

	appJWT, err := a.appJWT()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", apiBase, installationID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")

	body, status, err := a.do(req)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated {
		return "", fmt.Errorf("mint installation token: github returned %d: %s", status, string(body))
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	a.mu.Lock()
	a.tokens[installationID] = cachedToken{token: out.Token, expires: out.ExpiresAt}
	a.mu.Unlock()
	return out.Token, nil
}

// do executes a request and returns the body + status.
func (a *App) do(req *http.Request) ([]byte, int, error) {
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	return body, resp.StatusCode, nil
}

// ExchangeOAuthCode swaps an OAuth code for the installer's identity is not
// needed for installation flow; installations arrive via webhook. This helper
// remains for the post-install redirect landing (no token exchange required).
var ErrNotConfigured = errors.New("github app not configured")

// authHeader returns the installation Bearer header value.
func authHeader(token string) string { return "Bearer " + strings.TrimSpace(token) }
