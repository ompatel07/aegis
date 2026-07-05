package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/services"
)

// OrganizationHandler serves /organizations routes.
type OrganizationHandler struct {
	orgs *services.OrganizationService
	log  zerolog.Logger
}

func NewOrganizationHandler(orgs *services.OrganizationService, log zerolog.Logger) *OrganizationHandler {
	return &OrganizationHandler{orgs: orgs, log: log}
}

// List: GET /organizations — orgs the user belongs to (with their role).
func (h *OrganizationHandler) List(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.orgs.List(r.Context(), middleware.UserID(r.Context()))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, orgs)
}

type orgRequest struct {
	Name         string  `json:"name" validate:"required,min=1,max=255"`
	BillingEmail *string `json:"billing_email" validate:"omitempty,email,max=320"`
}

// Create: POST /organizations.
func (h *OrganizationHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req orgRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	org, err := h.orgs.Create(r.Context(), middleware.UserID(r.Context()), req.Name, req.BillingEmail)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusCreated, org)
}

// Get: GET /organizations/{orgId}.
func (h *OrganizationHandler) Get(w http.ResponseWriter, r *http.Request) {
	org, err := h.orgs.Get(r.Context(), chi.URLParam(r, "orgId"), middleware.UserID(r.Context()))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, org)
}

// Update: PUT /organizations/{orgId} — settings (admin+).
func (h *OrganizationHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req orgRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	org, err := h.orgs.UpdateSettings(r.Context(), chi.URLParam(r, "orgId"),
		middleware.UserID(r.Context()), req.Name, req.BillingEmail)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, org)
}

// Members: GET /organizations/{orgId}/members.
func (h *OrganizationHandler) Members(w http.ResponseWriter, r *http.Request) {
	members, err := h.orgs.Members(r.Context(), chi.URLParam(r, "orgId"), middleware.UserID(r.Context()))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, members)
}

type inviteRequest struct {
	Email string `json:"email" validate:"required,email,max=320"`
	Role  string `json:"role" validate:"omitempty,oneof=owner admin member viewer"`
}

// Invite: POST /organizations/{orgId}/invitations (admin+).
func (h *OrganizationHandler) Invite(w http.ResponseWriter, r *http.Request) {
	var req inviteRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	inv, added, err := h.orgs.Invite(r.Context(), chi.URLParam(r, "orgId"),
		middleware.UserID(r.Context()), req.Email, req.Role)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	if added {
		httpx.WriteSuccess(w, http.StatusOK, map[string]any{"added": true})
		return
	}
	httpx.WriteSuccess(w, http.StatusCreated, inv)
}

// ListInvitations: GET /organizations/{orgId}/invitations (admin+).
func (h *OrganizationHandler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	invs, err := h.orgs.ListInvitations(r.Context(), chi.URLParam(r, "orgId"), middleware.UserID(r.Context()))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, invs)
}

// RevokeInvitation: DELETE /organizations/{orgId}/invitations/{invId}.
func (h *OrganizationHandler) RevokeInvitation(w http.ResponseWriter, r *http.Request) {
	err := h.orgs.RevokeInvitation(r.Context(), chi.URLParam(r, "orgId"),
		middleware.UserID(r.Context()), chi.URLParam(r, "invId"))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]string{"message": "invitation revoked"})
}

type acceptRequest struct {
	Token string `json:"token" validate:"required"`
}

// Accept: POST /invitations/accept — the current user joins via a token.
func (h *OrganizationHandler) Accept(w http.ResponseWriter, r *http.Request) {
	var req acceptRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	org, err := h.orgs.Accept(r.Context(), middleware.UserID(r.Context()), req.Token)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, org)
}

type roleRequest struct {
	Role string `json:"role" validate:"required,oneof=owner admin member viewer"`
}

// SetRole: PUT /organizations/{orgId}/members/{userId}.
func (h *OrganizationHandler) SetRole(w http.ResponseWriter, r *http.Request) {
	var req roleRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	err := h.orgs.SetMemberRole(r.Context(), chi.URLParam(r, "orgId"),
		middleware.UserID(r.Context()), chi.URLParam(r, "userId"), req.Role)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]string{"message": "role updated"})
}

// RemoveMember: DELETE /organizations/{orgId}/members/{userId}.
func (h *OrganizationHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	err := h.orgs.RemoveMember(r.Context(), chi.URLParam(r, "orgId"),
		middleware.UserID(r.Context()), chi.URLParam(r, "userId"))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]string{"message": "member removed"})
}
