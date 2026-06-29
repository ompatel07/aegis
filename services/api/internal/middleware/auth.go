package middleware

import (
	"net/http"
	"strings"

	"github.com/aegis-platform/api/internal/auth"
	"github.com/aegis-platform/api/internal/httpx"
)

// Authenticator returns middleware that requires a valid Bearer access token.
// On success the user's id + role are stored in the request context.
func Authenticator(tokens *auth.TokenManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerToken(r)
			if raw == "" {
				httpx.WriteError(w, httpx.ErrUnauthorized("missing bearer token"))
				return
			}
			claims, err := tokens.ParseAccess(raw)
			if err != nil {
				httpx.WriteError(w, httpx.ErrUnauthorized("invalid or expired token"))
				return
			}
			ctx := WithUser(r.Context(), claims.Subject, claims.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin gates a route to admin users. Must run after Authenticator.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if UserRole(r.Context()) != "admin" {
			httpx.WriteError(w, httpx.ErrForbidden("admin role required"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
