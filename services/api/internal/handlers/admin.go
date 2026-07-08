package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/auth"
	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/middleware"
	"github.com/aegis-platform/api/internal/repository"
)

// AdminHandler serves the platform super-admin panel. All routes sit behind the
// RequireSuperAdmin middleware; every mutation writes to admin_audit_log.
type AdminHandler struct {
	admin  *repository.AdminRepository
	users  *repository.UserRepository
	tokens *auth.TokenManager
	log    zerolog.Logger
}

func NewAdminHandler(admin *repository.AdminRepository, users *repository.UserRepository, tokens *auth.TokenManager, log zerolog.Logger) *AdminHandler {
	return &AdminHandler{admin: admin, users: users, tokens: tokens, log: log}
}

func clientIP(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		return strings.TrimSpace(strings.SplitN(f, ",", 2)[0])
	}
	return strings.SplitN(r.RemoteAddr, ":", 2)[0]
}

func strptr(s string) *string { return &s }

// audit records an admin action (best-effort — never blocks the response).
func (h *AdminHandler) audit(r *http.Request, action string, targetType, targetID *string, details map[string]any) {
	_ = h.admin.InsertAudit(r.Context(), middleware.UserID(r.Context()), action, targetType, targetID, details, clientIP(r))
}

func qInt(r *http.Request, key string, def, min, max int) int { return httpx.QueryInt(r, key, def, min, max) }

// ── Overview + health ─────────────────────────────────────────────────────────

func (h *AdminHandler) Overview(w http.ResponseWriter, r *http.Request) {
	o, err := h.admin.Overview(r.Context())
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, o)
}

func (h *AdminHandler) Health(w http.ResponseWriter, r *http.Request) {
	httpx.WriteSuccess(w, http.StatusOK, h.admin.Health(r.Context()))
}

// ── Organizations ─────────────────────────────────────────────────────────────

func (h *AdminHandler) ListOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.admin.ListOrgs(r.Context(), r.URL.Query().Get("search"), qInt(r, "limit", 100, 1, 500))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, orgs)
}

func (h *AdminHandler) SuspendOrg(w http.ResponseWriter, r *http.Request) {
	var req struct{ Suspend bool `json:"suspend"` }
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	id := chi.URLParam(r, "orgId")
	if err := h.admin.SuspendOrg(r.Context(), id, req.Suspend); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	h.audit(r, "org.suspend", strptr("organization"), strptr(id), map[string]any{"suspend": req.Suspend})
	httpx.WriteSuccess(w, http.StatusOK, map[string]bool{"suspended": req.Suspend})
}

func (h *AdminHandler) SetOrgPlan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Plan string `json:"plan" validate:"required,oneof=free pro enterprise"`
	}
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	id := chi.URLParam(r, "orgId")
	if err := h.admin.SetOrgPlan(r.Context(), id, req.Plan); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	h.audit(r, "org.set_plan", strptr("organization"), strptr(id), map[string]any{"plan": req.Plan})
	httpx.WriteSuccess(w, http.StatusOK, map[string]string{"plan": req.Plan})
}

// ── Users ─────────────────────────────────────────────────────────────────────

func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.admin.ListUsers(r.Context(), r.URL.Query().Get("search"), qInt(r, "limit", 100, 1, 500))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, users)
}

func (h *AdminHandler) SetSuperAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Grant bool `json:"grant"` }
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	id := chi.URLParam(r, "userId")
	if err := h.admin.SetSuperAdmin(r.Context(), id, req.Grant); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	h.audit(r, "user.set_super_admin", strptr("user"), strptr(id), map[string]any{"grant": req.Grant})
	httpx.WriteSuccess(w, http.StatusOK, map[string]bool{"is_super_admin": req.Grant})
}

func (h *AdminHandler) SuspendUser(w http.ResponseWriter, r *http.Request) {
	var req struct{ Suspend bool `json:"suspend"` }
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	id := chi.URLParam(r, "userId")
	if err := h.admin.SuspendUser(r.Context(), id, req.Suspend); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	h.audit(r, "user.suspend", strptr("user"), strptr(id), map[string]any{"suspend": req.Suspend})
	httpx.WriteSuccess(w, http.StatusOK, map[string]bool{"suspended": req.Suspend})
}

// Impersonate issues a 1-hour access token for the target user so an operator can
// reproduce their view for support. Fully audited.
func (h *AdminHandler) Impersonate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "userId")
	target, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	tok, expiresIn, err := h.tokens.GenerateAccessToken(target.ID, target.Email, target.Role, time.Hour)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	h.audit(r, "user.impersonate", strptr("user"), strptr(id), map[string]any{
		"target_email": target.Email, "expires_in": expiresIn,
	})
	httpx.WriteSuccess(w, http.StatusOK, map[string]any{
		"access_token": tok, "expires_in": expiresIn, "user": map[string]string{"id": target.ID, "email": target.Email},
	})
}

// ── Scans + audit ─────────────────────────────────────────────────────────────

func (h *AdminHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	scans, err := h.admin.ListScans(r.Context(), r.URL.Query().Get("status"), qInt(r, "limit", 100, 1, 500))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, scans)
}

func (h *AdminHandler) ListAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := h.admin.ListAudit(r.Context(), r.URL.Query().Get("action"), qInt(r, "limit", 200, 1, 1000))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, entries)
}

// ── Feature flags ─────────────────────────────────────────────────────────────

func (h *AdminHandler) ListFlags(w http.ResponseWriter, r *http.Request) {
	flags, err := h.admin.ListFlags(r.Context())
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, flags)
}

func (h *AdminHandler) CreateFlag(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key         string  `json:"key" validate:"required,max=64"`
		Description *string `json:"description"`
	}
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	f, err := h.admin.CreateFlag(r.Context(), req.Key, req.Description)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	h.audit(r, "flag.create", strptr("feature_flag"), strptr(f.ID), map[string]any{"key": req.Key})
	httpx.WriteSuccess(w, http.StatusCreated, f)
}

func (h *AdminHandler) UpdateFlag(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled     bool     `json:"enabled"`
		RolloutPct  int      `json:"rollout_pct" validate:"min=0,max=100"`
		EnabledOrgs []string `json:"enabled_orgs"`
	}
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	id := chi.URLParam(r, "flagId")
	if err := h.admin.UpdateFlag(r.Context(), id, req.Enabled, req.RolloutPct, req.EnabledOrgs); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	h.audit(r, "flag.update", strptr("feature_flag"), strptr(id), map[string]any{"enabled": req.Enabled, "rollout_pct": req.RolloutPct})
	httpx.WriteSuccess(w, http.StatusOK, map[string]string{"message": "updated"})
}

func (h *AdminHandler) DeleteFlag(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "flagId")
	if err := h.admin.DeleteFlag(r.Context(), id); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	h.audit(r, "flag.delete", strptr("feature_flag"), strptr(id), nil)
	httpx.WriteSuccess(w, http.StatusOK, map[string]string{"message": "deleted"})
}

// ── Beta invitations ──────────────────────────────────────────────────────────

func (h *AdminHandler) ListBeta(w http.ResponseWriter, r *http.Request) {
	list, err := h.admin.ListBeta(r.Context(), qInt(r, "limit", 200, 1, 1000))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	sent, accepted, _ := h.admin.BetaConversions(r.Context())
	httpx.WriteSuccess(w, http.StatusOK, map[string]any{"invitations": list, "sent": sent, "accepted": accepted})
}

func (h *AdminHandler) CreateBeta(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Emails         []string `json:"emails" validate:"required,min=1,dive,email"`
		WelcomeMessage string   `json:"welcome_message"`
	}
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	adminID := middleware.UserID(r.Context())
	created := 0
	for _, email := range req.Emails {
		if _, err := h.admin.CreateBeta(r.Context(), email, req.WelcomeMessage, auth.RandomToken(), adminID, time.Now().Add(14*24*time.Hour)); err == nil {
			created++
		}
	}
	h.audit(r, "beta.invite", strptr("beta"), nil, map[string]any{"count": created})
	httpx.WriteSuccess(w, http.StatusCreated, map[string]int{"created": created})
}

func (h *AdminHandler) RevokeBeta(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "betaId")
	if err := h.admin.SetBetaStatus(r.Context(), id, "revoked"); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	h.audit(r, "beta.revoke", strptr("beta"), strptr(id), nil)
	httpx.WriteSuccess(w, http.StatusOK, map[string]string{"message": "revoked"})
}

// ── Support tickets ───────────────────────────────────────────────────────────

func (h *AdminHandler) ListTickets(w http.ResponseWriter, r *http.Request) {
	tickets, err := h.admin.ListTickets(r.Context(), r.URL.Query().Get("status"), qInt(r, "limit", 200, 1, 1000))
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, tickets)
}

func (h *AdminHandler) ReplyTicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reply  string `json:"reply" validate:"required"`
		Status string `json:"status" validate:"required,oneof=new in_progress resolved"`
	}
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	id := chi.URLParam(r, "ticketId")
	if err := h.admin.ReplyTicket(r.Context(), id, req.Reply, req.Status); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	h.audit(r, "support.reply", strptr("ticket"), strptr(id), map[string]any{"status": req.Status})
	httpx.WriteSuccess(w, http.StatusOK, map[string]string{"message": "replied"})
}

// ── Public (authenticated, non-admin) widgets ─────────────────────────────────

// SubmitTicket lets any signed-in user open a support ticket (the "?" widget).
func (h *AdminHandler) SubmitTicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subject string `json:"subject" validate:"required,max=255"`
		Message string `json:"message" validate:"required,max=5000"`
	}
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	userID := middleware.UserID(r.Context())
	email := ""
	if u, err := h.users.GetByID(r.Context(), userID); err == nil {
		email = u.Email
	}
	if err := h.admin.CreateTicket(r.Context(), userID, email, req.Subject, req.Message); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusCreated, map[string]string{"message": "received"})
}

// SubmitScanRating stores a thumbs up/down on a scan (feedback widget).
func (h *AdminHandler) SubmitScanRating(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rating  string `json:"rating" validate:"required,oneof=up down"`
		Comment string `json:"comment" validate:"max=2000"`
	}
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}
	if err := h.admin.CreateScanRating(r.Context(), chi.URLParam(r, "scanId"), middleware.UserID(r.Context()), req.Rating, req.Comment); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusCreated, map[string]string{"message": "thanks"})
}
