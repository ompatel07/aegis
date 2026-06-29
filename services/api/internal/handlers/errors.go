// Package handlers contains the HTTP handlers wired to API routes.
package handlers

import (
	"errors"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
	"github.com/aegis-platform/api/internal/repository"
	"github.com/aegis-platform/api/internal/services"
)

// writeServiceError maps domain/repository errors onto the HTTP error envelope.
// Unknown errors are logged and surface as a generic 500 (no internal leakage).
func writeServiceError(w http.ResponseWriter, log zerolog.Logger, err error) {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		httpx.WriteError(w, httpx.ErrNotFound(""))
	case errors.Is(err, repository.ErrConflict):
		httpx.WriteError(w, httpx.ErrConflict("resource already exists"))
	case errors.Is(err, services.ErrEmailTaken):
		httpx.WriteError(w, httpx.ErrConflict("email is already registered"))
	case errors.Is(err, services.ErrInvalidCredentials):
		httpx.WriteError(w, httpx.ErrUnauthorized("invalid email or password"))
	case errors.Is(err, services.ErrInvalidRefresh):
		httpx.WriteError(w, httpx.ErrUnauthorized("invalid or expired refresh token"))
	case errors.Is(err, services.ErrProjectHasNoRepo):
		httpx.WriteError(w, httpx.ErrBadRequest("project has no repository configured to scan"))
	default:
		log.Error().Err(err).Msg("unhandled service error")
		httpx.WriteError(w, httpx.ErrInternal())
	}
}
