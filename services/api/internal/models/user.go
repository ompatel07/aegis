package models

import "time"

// Role and plan enumerations (mirrors DB CHECK constraints).
const (
	RoleUser  = "user"
	RoleAdmin = "admin"

	PlanFree       = "free"
	PlanPro        = "pro"
	PlanEnterprise = "enterprise"
)

// User is a registered account. PasswordHash is never serialized to clients.
type User struct {
	ID           string     `db:"id" json:"id"`
	Email        string     `db:"email" json:"email"`
	PasswordHash string     `db:"password_hash" json:"-"`
	Name         string     `db:"name" json:"name"`
	Role         string     `db:"role" json:"role"`
	Plan         string     `db:"plan" json:"plan"`
	IsSuperAdmin bool       `db:"is_super_admin" json:"is_super_admin"`
	SuspendedAt  *time.Time `db:"suspended_at" json:"suspended_at,omitempty"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at" json:"updated_at"`
}
