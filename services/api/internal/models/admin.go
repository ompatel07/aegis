package models

import "time"

// AdminAuditEntry is one append-only record of a super-admin action.
type AdminAuditEntry struct {
	ID          string    `db:"id" json:"id"`
	AdminUserID *string   `db:"admin_user_id" json:"admin_user_id,omitempty"`
	AdminEmail  *string   `db:"admin_email" json:"admin_email,omitempty"`
	Action      string    `db:"action" json:"action"`
	TargetType  *string   `db:"target_type" json:"target_type,omitempty"`
	TargetID    *string   `db:"target_id" json:"target_id,omitempty"`
	Details     JSONB     `db:"details" json:"details,omitempty"`
	IP          *string   `db:"ip" json:"ip,omitempty"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

// FeatureFlag toggles platform capabilities globally, by org, or by rollout %.
type FeatureFlag struct {
	ID          string    `db:"id" json:"id"`
	Key         string    `db:"key" json:"key"`
	Description *string   `db:"description" json:"description,omitempty"`
	Enabled     bool      `db:"enabled" json:"enabled"`
	RolloutPct  int       `db:"rollout_pct" json:"rollout_pct"`
	EnabledOrgs JSONB     `db:"enabled_orgs" json:"enabled_orgs"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

// BetaInvitation tracks a platform beta invite through its lifecycle.
type BetaInvitation struct {
	ID             string     `db:"id" json:"id"`
	Email          string     `db:"email" json:"email"`
	WelcomeMessage *string    `db:"welcome_message" json:"welcome_message,omitempty"`
	Token          string     `db:"token" json:"token"`
	Status         string     `db:"status" json:"status"`
	InvitedBy      *string    `db:"invited_by" json:"invited_by,omitempty"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
	AcceptedAt     *time.Time `db:"accepted_at" json:"accepted_at,omitempty"`
	ExpiresAt      time.Time  `db:"expires_at" json:"expires_at"`
}

// SupportTicket is a user-submitted message routed to the admin inbox.
type SupportTicket struct {
	ID         string    `db:"id" json:"id"`
	UserID     *string   `db:"user_id" json:"user_id,omitempty"`
	Email      *string   `db:"email" json:"email,omitempty"`
	Subject    string    `db:"subject" json:"subject"`
	Message    string    `db:"message" json:"message"`
	Status     string    `db:"status" json:"status"`
	AdminReply *string   `db:"admin_reply" json:"admin_reply,omitempty"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`
}

// ── Admin projections (read-only views assembled for the panel) ───────────────

type AdminOverview struct {
	Organizations  int            `json:"organizations"`
	Users          int            `json:"users"`
	Projects       int            `json:"projects"`
	ScansTotal     int            `json:"scans_total"`
	Scans7d        int            `json:"scans_7d"`
	Scans30d       int            `json:"scans_30d"`
	ActiveScans    int            `json:"active_scans"`
	Signups7d      int            `json:"signups_7d"`
	OpenTickets    int            `json:"open_tickets"`
	FindingsBySev  map[string]int `json:"findings_by_severity"`
}

type AdminOrgRow struct {
	ID          string     `db:"id" json:"id"`
	Name        string     `db:"name" json:"name"`
	Slug        string     `db:"slug" json:"slug"`
	Plan        string     `db:"plan" json:"plan"`
	IsPersonal  bool       `db:"is_personal" json:"is_personal"`
	SuspendedAt *time.Time `db:"suspended_at" json:"suspended_at,omitempty"`
	Members     int        `db:"members" json:"members"`
	Projects    int        `db:"projects" json:"projects"`
	Scans       int        `db:"scans" json:"scans"`
	CreatedAt   time.Time  `db:"created_at" json:"created_at"`
	LastActivity *time.Time `db:"last_activity" json:"last_activity,omitempty"`
}

type AdminUserRow struct {
	ID           string     `db:"id" json:"id"`
	Email        string     `db:"email" json:"email"`
	Name         string     `db:"name" json:"name"`
	IsSuperAdmin bool       `db:"is_super_admin" json:"is_super_admin"`
	SuspendedAt  *time.Time `db:"suspended_at" json:"suspended_at,omitempty"`
	Orgs         int        `db:"orgs" json:"orgs"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
}

type AdminScanRow struct {
	ID           string     `db:"id" json:"id"`
	ProjectID    string     `db:"project_id" json:"project_id"`
	ProjectName  string     `db:"project_name" json:"project_name"`
	Status       string     `db:"status" json:"status"`
	OverallGrade *string    `db:"overall_grade" json:"overall_grade,omitempty"`
	Duration     *int       `db:"duration_seconds" json:"duration_seconds,omitempty"`
	ErrorMessage *string    `db:"error_message" json:"error_message,omitempty"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
}
