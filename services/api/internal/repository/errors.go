// Package repository contains the data-access layer: typed methods over sqlx.
package repository

import "errors"

// ErrNotFound is returned when a row does not exist. Services translate this
// into an httpx 404. ErrConflict signals a unique-constraint violation.
var (
	ErrNotFound = errors.New("resource not found")
	ErrConflict = errors.New("resource already exists")
)
