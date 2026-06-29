package handlers

import (
	"net/http"

	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/auth"
	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/services"
)

// AuthHandler serves the /auth routes.
type AuthHandler struct {
	auth *services.AuthService
	log  zerolog.Logger
}

func NewAuthHandler(authSvc *services.AuthService, log zerolog.Logger) *AuthHandler {
	return &AuthHandler{auth: authSvc, log: log}
}

// ── Request DTOs ─────────────────────────────────────────────────────────────

type registerRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=128"`
	Name     string `json:"name" validate:"required,min=1,max=255"`
}

type loginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// authResponse bundles the user and freshly issued tokens.
type authResponse struct {
	User   *models.User    `json:"user"`
	Tokens *auth.TokenPair `json:"tokens"`
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// Register handles POST /api/v1/auth/register.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}

	user, pair, err := h.auth.Register(r.Context(), services.RegisterInput{
		Email: req.Email, Password: req.Password, Name: req.Name,
	})
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusCreated, authResponse{User: user, Tokens: pair})
}

// Login handles POST /api/v1/auth/login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}

	user, pair, err := h.auth.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, authResponse{User: user, Tokens: pair})
}

// Refresh handles POST /api/v1/auth/refresh.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}

	pair, err := h.auth.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, pair)
}

// Logout handles POST /api/v1/auth/logout.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if apiErr := httpx.DecodeAndValidate(w, r, &req); apiErr != nil {
		httpx.WriteError(w, apiErr)
		return
	}

	if err := h.auth.Logout(r.Context(), req.RefreshToken); err != nil {
		writeServiceError(w, h.log, err)
		return
	}
	httpx.WriteSuccess(w, http.StatusOK, map[string]string{"message": "logged out"})
}
