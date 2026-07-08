package models

import "time"

// Organization roles (mirror DB CHECK constraint), ordered most→least privileged.
// Namespaced OrgRole* to avoid collision with the user-level RoleAdmin.
const (
	OrgRoleOwner  = "owner"  // full control incl. billing + delete org
	OrgRoleAdmin  = "admin"  // manage members, projects, settings
	OrgRoleMember = "member" // create/manage projects, view all findings
	OrgRoleViewer = "viewer" // read-only
)

// roleRank orders roles for privilege comparisons (lower = more privileged).
var roleRank = map[string]int{OrgRoleOwner: 0, OrgRoleAdmin: 1, OrgRoleMember: 2, OrgRoleViewer: 3}

// RoleAtLeast reports whether have is at least as privileged as want.
func RoleAtLeast(have, want string) bool {
	h, ok1 := roleRank[have]
	w, ok2 := roleRank[want]
	return ok1 && ok2 && h <= w
}

// Organization is a team/workspace that owns projects.
type Organization struct {
	ID           string    `db:"id" json:"id"`
	Name         string    `db:"name" json:"name"`
	Slug         string    `db:"slug" json:"slug"`
	BillingEmail *string   `db:"billing_email" json:"billing_email,omitempty"`
	Plan         string     `db:"plan" json:"plan"`
	IsPersonal   bool       `db:"is_personal" json:"is_personal"`
	SuspendedAt  *time.Time `db:"suspended_at" json:"suspended_at,omitempty"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at" json:"updated_at"`
}

// OrgMembership is an organization plus the requesting user's role in it (for
// the org switcher / list).
type OrgMembership struct {
	Organization
	Role string `db:"role" json:"role"`
}

// OrgMember is one member row with the user's identity, for the members page.
type OrgMember struct {
	UserID   string    `db:"user_id" json:"user_id"`
	Email    string    `db:"email" json:"email"`
	Name     *string   `db:"name" json:"name,omitempty"`
	Role     string    `db:"role" json:"role"`
	JoinedAt time.Time `db:"joined_at" json:"joined_at"`
}

// OrgInvitation is a pending invite.
type OrgInvitation struct {
	ID         string     `db:"id" json:"id"`
	OrgID      string     `db:"org_id" json:"org_id"`
	Email      string     `db:"email" json:"email"`
	Role       string     `db:"role" json:"role"`
	Token      string     `db:"token" json:"token"`
	InvitedBy  *string    `db:"invited_by" json:"invited_by,omitempty"`
	ExpiresAt  time.Time  `db:"expires_at" json:"expires_at"`
	AcceptedAt *time.Time `db:"accepted_at" json:"accepted_at,omitempty"`
	CreatedAt  time.Time  `db:"created_at" json:"created_at"`
}
