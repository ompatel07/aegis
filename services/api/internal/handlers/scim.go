package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/repository"
	"github.com/aegis-platform/api/internal/services"
)

// SCIMHandler implements a pragmatic SCIM 2.0 Users endpoint. An IdP (Okta,
// Azure AD, …) uses a per-org bearer token to provision/deprovision users;
// provisioning = org membership, so deprovisioning immediately revokes access.
type SCIMHandler struct {
	repo  *repository.SSORepository
	users *repository.UserRepository
	orgs  *repository.OrganizationRepository
	auth  *services.AuthService
	log   zerolog.Logger
}

func NewSCIMHandler(repo *repository.SSORepository, users *repository.UserRepository, orgs *repository.OrganizationRepository, authSvc *services.AuthService, log zerolog.Logger) *SCIMHandler {
	return &SCIMHandler{repo: repo, users: users, orgs: orgs, auth: authSvc, log: log}
}

type scimCtxKey struct{}

// Authenticate is middleware that resolves the SCIM bearer token to an org.
func (h *SCIMHandler) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" || tok == r.Header.Get("Authorization") {
			scimError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		sum := sha256.Sum256([]byte(tok))
		rec, err := h.repo.GetSCIMTokenByHash(r.Context(), hex.EncodeToString(sum[:]))
		if err != nil {
			scimError(w, http.StatusUnauthorized, "invalid scim token")
			return
		}
		h.repo.TouchSCIMToken(r.Context(), rec.ID)
		ctx := context.WithValue(r.Context(), scimCtxKey{}, rec.OrganizationID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func scimOrg(r *http.Request) string {
	if v, ok := r.Context().Value(scimCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// ── SCIM resource shapes ─────────────────────────────────────────────────────

type scimName struct {
	Formatted string `json:"formatted,omitempty"`
}
type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}
type scimUser struct {
	Schemas    []string    `json:"schemas"`
	ID         string      `json:"id"`
	ExternalID string      `json:"externalId,omitempty"`
	UserName   string      `json:"userName"`
	Name       scimName    `json:"name,omitempty"`
	Emails     []scimEmail `json:"emails,omitempty"`
	Active     bool        `json:"active"`
	Meta       scimMeta    `json:"meta"`
}
type scimMeta struct {
	ResourceType string `json:"resourceType"`
}

func toSCIMUser(id, email, name, externalID string, active bool) scimUser {
	return scimUser{
		Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:      id, ExternalID: externalID, UserName: email,
		Name:   scimName{Formatted: name},
		Emails: []scimEmail{{Value: email, Primary: true}},
		Active: active, Meta: scimMeta{ResourceType: "User"},
	}
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// CreateUser: POST /scim/v2/Users — provision into the token's org.
func (h *SCIMHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	org := scimOrg(r)
	var in scimUser
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		scimError(w, http.StatusBadRequest, "invalid body")
		return
	}
	email := scimEmailOf(in)
	if email == "" {
		scimError(w, http.StatusBadRequest, "userName/email required")
		return
	}
	user, err := h.auth.ProvisionUser(r.Context(), email, in.Name.Formatted, true)
	if err != nil {
		scimError(w, http.StatusInternalServerError, "provision failed")
		return
	}
	if err := h.orgs.AddMember(r.Context(), org, user.ID, "member", ""); err != nil {
		scimError(w, http.StatusInternalServerError, "membership failed")
		return
	}
	writeSCIM(w, http.StatusCreated, toSCIMUser(user.ID, user.Email, user.Name, in.ExternalID, true))
}

// ListUsers: GET /scim/v2/Users?filter=userName eq "x" — org membership scoped.
func (h *SCIMHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	org := scimOrg(r)
	filterEmail := parseUserNameFilter(r.URL.Query().Get("filter"))
	var resources []scimUser
	members, err := h.orgs.Members(r.Context(), org)
	if err != nil {
		scimError(w, http.StatusInternalServerError, "list failed")
		return
	}
	for _, m := range members {
		if filterEmail != "" && !strings.EqualFold(m.Email, filterEmail) {
			continue
		}
		name := ""
		if m.Name != nil {
			name = *m.Name
		}
		resources = append(resources, toSCIMUser(m.UserID, m.Email, name, "", true))
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(resources),
		"startIndex":   1,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	})
}

// GetUser: GET /scim/v2/Users/{id}.
func (h *SCIMHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	org, id := scimOrg(r), chi.URLParam(r, "id")
	role, err := h.orgs.RoleOf(r.Context(), org, id)
	if err != nil || role == "" {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	u, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	writeSCIM(w, http.StatusOK, toSCIMUser(u.ID, u.Email, u.Name, "", true))
}

// PatchUser: PATCH /scim/v2/Users/{id} — the common active=false deprovision.
func (h *SCIMHandler) PatchUser(w http.ResponseWriter, r *http.Request) {
	org, id := scimOrg(r), chi.URLParam(r, "id")
	var patch struct {
		Operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		scimError(w, http.StatusBadRequest, "invalid patch")
		return
	}
	for _, op := range patch.Operations {
		if strings.EqualFold(op.Path, "active") || strings.Contains(strings.ToLower(string(op.Value)), "\"active\"") {
			active := strings.Contains(strings.ToLower(string(op.Value)), "true")
			if !active {
				_ = h.orgs.RemoveMember(r.Context(), org, id)
			} else {
				_ = h.orgs.AddMember(r.Context(), org, id, "member", "")
			}
		}
	}
	u, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		scimError(w, http.StatusNotFound, "user not found")
		return
	}
	role, _ := h.orgs.RoleOf(r.Context(), org, id)
	writeSCIM(w, http.StatusOK, toSCIMUser(u.ID, u.Email, u.Name, "", role != ""))
}

// DeleteUser: DELETE /scim/v2/Users/{id} — remove from the org.
func (h *SCIMHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	org, id := scimOrg(r), chi.URLParam(r, "id")
	_ = h.orgs.RemoveMember(r.Context(), org, id)
	w.WriteHeader(http.StatusNoContent)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func scimEmailOf(u scimUser) string {
	if u.UserName != "" {
		return strings.ToLower(u.UserName)
	}
	for _, e := range u.Emails {
		if e.Primary && e.Value != "" {
			return strings.ToLower(e.Value)
		}
	}
	if len(u.Emails) > 0 {
		return strings.ToLower(u.Emails[0].Value)
	}
	return ""
}

func parseUserNameFilter(filter string) string {
	// e.g.  userName eq "user@example.com"
	i := strings.Index(strings.ToLower(filter), "username eq")
	if i < 0 {
		return ""
	}
	rest := filter[i+len("username eq"):]
	return strings.Trim(strings.TrimSpace(rest), `"`)
}

func writeSCIM(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func scimError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":  detail, "status": status,
	})
}
