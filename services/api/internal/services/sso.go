package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"

	"github.com/aegis-platform/api/internal/auth"
	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
)

var (
	ErrSSONotConfigured = errors.New("sso not configured for this domain")
	ErrSSOState         = errors.New("invalid or expired sso state")
	ErrSSONoEmail       = errors.New("identity provider returned no email")
)

// SSOService drives OIDC (and SAML, see sso_saml.go) login + JIT provisioning.
type SSOService struct {
	repo    *repository.SSORepository
	users   *repository.UserRepository
	orgs    *repository.OrganizationRepository
	auth    *AuthService
	enc     *auth.Encryptor
	rdb     *redis.Client
	baseURL string
}

func NewSSOService(repo *repository.SSORepository, users *repository.UserRepository, orgs *repository.OrganizationRepository, authSvc *AuthService, enc *auth.Encryptor, rdb *redis.Client, baseURL string) *SSOService {
	return &SSOService{repo: repo, users: users, orgs: orgs, auth: authSvc, enc: enc, rdb: rdb, baseURL: strings.TrimRight(baseURL, "/")}
}

// Discover returns the enabled connection that owns an email address's domain.
func (s *SSOService) Discover(ctx context.Context, email string) (*models.SSOConnection, error) {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return nil, ErrSSONotConfigured
	}
	conn, err := s.repo.GetEnabledByDomain(ctx, email[at+1:])
	if err != nil {
		return nil, ErrSSONotConfigured
	}
	return conn, nil
}

func (s *SSOService) GetConnection(ctx context.Context, id string) (*models.SSOConnection, error) {
	return s.repo.GetConnection(ctx, id)
}

type oidcState struct {
	ConnID   string `json:"c"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
}

func (s *SSOService) oidcRedirectURL() string { return s.baseURL + "/api/v1/auth/sso/oidc/callback" }

func (s *SSOService) oauthConfig(ctx context.Context, conn *models.SSOConnection) (*oauth2.Config, *oidc.Provider, error) {
	if conn.OIDCIssuer == nil || conn.OIDCClientID == nil {
		return nil, nil, ErrSSONotConfigured
	}
	provider, err := oidc.NewProvider(ctx, *conn.OIDCIssuer)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discovery: %w", err)
	}
	secret := ""
	if conn.OIDCClientSecretEnc != nil && *conn.OIDCClientSecretEnc != "" {
		if secret, err = s.enc.Decrypt(*conn.OIDCClientSecretEnc); err != nil {
			return nil, nil, fmt.Errorf("decrypt client secret: %w", err)
		}
	}
	scopes := strings.Fields(conn.OIDCScopes)
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	return &oauth2.Config{
		ClientID:     *conn.OIDCClientID,
		ClientSecret: secret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  s.oidcRedirectURL(),
		Scopes:       scopes,
	}, provider, nil
}

// StartOIDC builds the IdP authorization URL and stashes state/nonce/PKCE.
func (s *SSOService) StartOIDC(ctx context.Context, conn *models.SSOConnection) (string, error) {
	conf, _, err := s.oauthConfig(ctx, conn)
	if err != nil {
		return "", err
	}
	state, nonce, verifier := randToken(), randToken(), oauth2.GenerateVerifier()
	st, _ := json.Marshal(oidcState{ConnID: conn.ID, Nonce: nonce, Verifier: verifier})
	if err := s.rdb.Set(ctx, "aegis:sso:oidc:"+state, st, 10*time.Minute).Err(); err != nil {
		return "", err
	}
	return conf.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// CompleteOIDC validates the callback, provisions the user, and issues tokens.
func (s *SSOService) CompleteOIDC(ctx context.Context, state, code string) (*models.User, *auth.TokenPair, error) {
	raw, err := s.rdb.GetDel(ctx, "aegis:sso:oidc:"+state).Bytes()
	if err != nil {
		return nil, nil, ErrSSOState
	}
	var st oidcState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, nil, ErrSSOState
	}
	conn, err := s.repo.GetConnection(ctx, st.ConnID)
	if err != nil {
		return nil, nil, err
	}
	conf, provider, err := s.oauthConfig(ctx, conn)
	if err != nil {
		return nil, nil, err
	}
	tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return nil, nil, fmt.Errorf("token exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, nil, errors.New("no id_token in response")
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: *conn.OIDCClientID}).Verify(ctx, rawID)
	if err != nil {
		return nil, nil, fmt.Errorf("verify id_token: %w", err)
	}
	if idToken.Nonce != st.Nonce {
		return nil, nil, errors.New("nonce mismatch")
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, nil, err
	}
	email := stringClaim(claims, conn.AttrEmail, "email")
	name := stringClaim(claims, conn.AttrName, "name")
	return s.provision(ctx, conn, idToken.Subject, email, name)
}

// provision links the external identity, ensures org membership, issues tokens.
func (s *SSOService) provision(ctx context.Context, conn *models.SSOConnection, externalID, email, name string) (*models.User, *auth.TokenPair, error) {
	if strings.TrimSpace(email) == "" {
		return nil, nil, ErrSSONoEmail
	}
	user, err := s.auth.ProvisionUser(ctx, email, name, conn.JITProvisioning)
	if err != nil {
		return nil, nil, err
	}
	if _, err := s.repo.UpsertIdentity(ctx, conn.ID, user.ID, externalID); err != nil {
		return nil, nil, err
	}
	// Join the org that owns the connection (idempotent). Empty inviter → NULL.
	if err := s.orgs.AddMember(ctx, conn.OrganizationID, user.ID, conn.DefaultRole, ""); err != nil {
		return nil, nil, err
	}
	pair, err := s.auth.IssueTokens(ctx, user)
	if err != nil {
		return nil, nil, err
	}
	return user, pair, nil
}

func stringClaim(claims map[string]any, key, fallback string) string {
	if key != "" {
		if v, ok := claims[key].(string); ok && v != "" {
			return v
		}
	}
	if v, ok := claims[fallback].(string); ok {
		return v
	}
	return ""
}

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
