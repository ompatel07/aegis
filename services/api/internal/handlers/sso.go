package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/auth"
	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
	"github.com/aegis-platform/api/internal/services"
)

// SSOHandler serves the public SSO login flow and org-scoped IdP administration.
type SSOHandler struct {
	svc          *services.SSOService
	repo         *repository.SSORepository
	orgs         *repository.OrganizationRepository
	enc          *auth.Encryptor
	dashboardURL string
	log          zerolog.Logger
}

func NewSSOHandler(svc *services.SSOService, repo *repository.SSORepository, orgs *repository.OrganizationRepository, enc *auth.Encryptor, dashboardURL string, log zerolog.Logger) *SSOHandler {
	return &SSOHandler{svc: svc, repo: repo, orgs: orgs, enc: enc, dashboardURL: strings.TrimRight(dashboardURL, "/"), log: log}
}

// ── Public login flow ────────────────────────────────────────────────────────

// Discover: GET /auth/sso/discover?email= — tells the login page where to route.
func (h *SSOHandler) Discover(w http.ResponseWriter, r *http.Request) {
	conn, err := h.svc.Discover(r.Context(), strings.TrimSpace(r.URL.Query().Get("email")))
	if err != nil {
		httpx.WriteError(w, httpx.ErrNotFound("no sso configured for this email domain"))
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]any{
		"connection_id": conn.ID,
		"protocol":      conn.Protocol,
		"display_name":  conn.DisplayName,
		"login_url":     fmt.Sprintf("/api/v1/auth/sso/%s/login", conn.ID),
	})
}

// Login: GET /auth/sso/{connID}/login — redirect the browser to the IdP.
func (h *SSOHandler) Login(w http.ResponseWriter, r *http.Request) {
	conn, err := h.repo.GetConnection(r.Context(), chi.URLParam(r, "connID"))
	if err != nil || !conn.Enabled {
		httpx.WriteError(w, httpx.ErrNotFound("sso connection not found"))
		return
	}
	var redirectURL string
	switch conn.Protocol {
	case "oidc":
		redirectURL, err = h.svc.StartOIDC(r.Context(), conn)
	case "saml":
		redirectURL, err = h.svc.StartSAML(r.Context(), conn)
	default:
		err = fmt.Errorf("unsupported protocol")
	}
	if err != nil {
		h.log.Error().Err(err).Str("conn", conn.ID).Msg("sso start failed")
		httpx.WriteError(w, httpx.ErrInternal())
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// OIDCCallback: GET /auth/sso/oidc/callback?state=&code= — finish + hand tokens
// to the SPA via the URL fragment (kept out of logs/referrers).
func (h *SSOHandler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Redirect(w, r, h.dashboardURL+"/login?sso_error="+e, http.StatusFound)
		return
	}
	_, pair, err := h.svc.CompleteOIDC(r.Context(), q.Get("state"), q.Get("code"))
	if err != nil {
		h.log.Warn().Err(err).Msg("oidc callback failed")
		http.Redirect(w, r, h.dashboardURL+"/login?sso_error=callback_failed", http.StatusFound)
		return
	}
	h.finishBrowserLogin(w, r, pair)
}

// SAMLACS: POST /auth/sso/saml/acs — the IdP posts the signed assertion here.
func (h *SSOHandler) SAMLACS(w http.ResponseWriter, r *http.Request) {
	_, pair, err := h.svc.CompleteSAML(r.Context(), r)
	if err != nil {
		h.log.Warn().Err(err).Msg("saml acs failed")
		http.Redirect(w, r, h.dashboardURL+"/login?sso_error=saml_failed", http.StatusFound)
		return
	}
	h.finishBrowserLogin(w, r, pair)
}

// SAMLMetadata: GET /auth/sso/{connID}/saml/metadata — SP descriptor for the IdP.
func (h *SSOHandler) SAMLMetadata(w http.ResponseWriter, r *http.Request) {
	xmlBytes, err := h.svc.SAMLMetadata(r.Context(), chi.URLParam(r, "connID"))
	if err != nil {
		httpx.WriteError(w, httpx.ErrNotFound("saml connection not found"))
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(xmlBytes)
}

func (h *SSOHandler) finishBrowserLogin(w http.ResponseWriter, r *http.Request, pair *auth.TokenPair) {
	frag := fmt.Sprintf("#access_token=%s&refresh_token=%s&expires_in=%d",
		pair.AccessToken, pair.RefreshToken, pair.ExpiresIn)
	http.Redirect(w, r, h.dashboardURL+"/auth/sso/complete"+frag, http.StatusFound)
}

// ── Org-scoped IdP administration (owner only) ───────────────────────────────

type connectionRequest struct {
	OrganizationID     string  `json:"organization_id" validate:"required,uuid"`
	Protocol           string  `json:"protocol" validate:"required,oneof=oidc saml"`
	DisplayName        string  `json:"display_name" validate:"max=255"`
	Enabled            bool    `json:"enabled"`
	EmailDomain        *string `json:"email_domain" validate:"omitempty,max=255"`
	OIDCIssuer         *string `json:"oidc_issuer" validate:"omitempty,url,max=1024"`
	OIDCClientID       *string `json:"oidc_client_id" validate:"omitempty,max=512"`
	OIDCClientSecret   *string `json:"oidc_client_secret" validate:"omitempty,max=1024"`
	OIDCScopes         string  `json:"oidc_scopes" validate:"max=512"`
	SAMLIdPEntityID    *string `json:"saml_idp_entity_id" validate:"omitempty,max=1024"`
	SAMLIdPSSOURL      *string `json:"saml_idp_sso_url" validate:"omitempty,url,max=1024"`
	SAMLIdPCertificate *string `json:"saml_idp_certificate" validate:"omitempty"`
	AttrEmail          string  `json:"attr_email" validate:"max=128"`
	AttrName           string  `json:"attr_name" validate:"max=128"`
	DefaultRole        string  `json:"default_role" validate:"omitempty,oneof=member admin"`
	JITProvisioning    bool    `json:"jit_provisioning"`
}

// requireOwner ensures the caller owns the org they're configuring.
func (h *SSOHandler) requireOwner(r *http.Request, orgID string) bool {
	role, err := h.orgs.RoleOf(r.Context(), orgID, middleware.UserID(r.Context()))
	return err == nil && role == "owner"
}

func (h *SSOHandler) CreateConnection(w http.ResponseWriter, r *http.Request) {
	var req connectionRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	if !h.requireOwner(r, req.OrganizationID) {
		httpx.WriteError(w, httpx.ErrForbidden("must be an organization owner"))
		return
	}
	conn := h.fromRequest(&req)
	if req.OIDCClientSecret != nil && *req.OIDCClientSecret != "" {
		enc, err := h.enc.Encrypt(*req.OIDCClientSecret)
		if err != nil {
			httpx.WriteError(w, httpx.ErrInternal())
			return
		}
		conn.OIDCClientSecretEnc = &enc
	}
	if err := h.repo.CreateConnection(r.Context(), conn); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusCreated, conn)
}

func (h *SSOHandler) fromRequest(req *connectionRequest) *models.SSOConnection {
	return &models.SSOConnection{
		OrganizationID: req.OrganizationID, Protocol: req.Protocol, DisplayName: req.DisplayName,
		Enabled: req.Enabled, EmailDomain: req.EmailDomain,
		OIDCIssuer: req.OIDCIssuer, OIDCClientID: req.OIDCClientID, OIDCScopes: req.OIDCScopes,
		SAMLIdPEntityID: req.SAMLIdPEntityID, SAMLIdPSSOURL: req.SAMLIdPSSOURL, SAMLIdPCertificate: req.SAMLIdPCertificate,
		AttrEmail: req.AttrEmail, AttrName: req.AttrName, DefaultRole: req.DefaultRole, JITProvisioning: req.JITProvisioning,
	}
}

func (h *SSOHandler) ListConnections(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("organization_id")
	if !h.requireOwner(r, orgID) {
		httpx.WriteError(w, httpx.ErrForbidden("must be an organization owner"))
		return
	}
	conns, err := h.repo.ListConnections(r.Context(), orgID)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, conns)
}

func (h *SSOHandler) DeleteConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := h.repo.GetConnection(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, httpx.ErrNotFound("connection not found"))
		return
	}
	if !h.requireOwner(r, conn.OrganizationID) {
		httpx.WriteError(w, httpx.ErrForbidden("must be an organization owner"))
		return
	}
	if err := h.repo.DeleteConnection(r.Context(), conn.ID, conn.OrganizationID); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]bool{"deleted": true})
}

// CreateSCIMToken mints a SCIM bearer token, returning the secret exactly once.
func (h *SSOHandler) CreateSCIMToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrganizationID string `json:"organization_id" validate:"required,uuid"`
		DisplayName    string `json:"display_name" validate:"max=255"`
	}
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	if !h.requireOwner(r, req.OrganizationID) {
		httpx.WriteError(w, httpx.ErrForbidden("must be an organization owner"))
		return
	}
	secret := "scim_" + auth.RandomToken()
	sum := sha256.Sum256([]byte(secret))
	tok := &models.SCIMToken{
		OrganizationID: req.OrganizationID, TokenHash: hex.EncodeToString(sum[:]),
		TokenPrefix: secret[:12], DisplayName: req.DisplayName,
	}
	if err := h.repo.CreateSCIMToken(r.Context(), tok); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusCreated, map[string]any{"id": tok.ID, "token": secret, "scim_base_url": "/scim/v2"})
}

func (h *SSOHandler) ListSCIMTokens(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("organization_id")
	if !h.requireOwner(r, orgID) {
		httpx.WriteError(w, httpx.ErrForbidden("must be an organization owner"))
		return
	}
	toks, err := h.repo.ListSCIMTokens(r.Context(), orgID)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, toks)
}
