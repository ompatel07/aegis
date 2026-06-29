// Package services holds business logic, sitting between handlers and repositories.
package services

import "errors"

// Domain-level sentinel errors. Handlers translate these into HTTP responses.
var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrEmailTaken         = errors.New("email is already registered")
	ErrInvalidRefresh     = errors.New("invalid or expired refresh token")
	ErrProjectHasNoRepo   = errors.New("project has no repository configured to scan")
)
