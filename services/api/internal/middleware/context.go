// Package middleware contains Chi-compatible HTTP middleware: auth, request
// logging, rate limiting, and panic recovery.
package middleware

import "context"

type contextKey string

const (
	userIDKey   contextKey = "userID"
	userRoleKey contextKey = "userRole"
)

// WithUser returns a context carrying the authenticated user's id and role.
func WithUser(ctx context.Context, userID, role string) context.Context {
	ctx = context.WithValue(ctx, userIDKey, userID)
	return context.WithValue(ctx, userRoleKey, role)
}

// UserID extracts the authenticated user's id (empty if unauthenticated).
func UserID(ctx context.Context) string {
	if v, ok := ctx.Value(userIDKey).(string); ok {
		return v
	}
	return ""
}

// UserRole extracts the authenticated user's role.
func UserRole(ctx context.Context) string {
	if v, ok := ctx.Value(userRoleKey).(string); ok {
		return v
	}
	return ""
}
