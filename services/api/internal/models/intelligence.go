package models

import "time"

// SyncStatus is the most recent sync for one intelligence source.
type SyncStatus struct {
	Source          string     `db:"source" json:"source"`
	LastStartedAt   *time.Time `db:"last_started_at" json:"last_started_at,omitempty"`
	LastCompletedAt *time.Time `db:"last_completed_at" json:"last_completed_at,omitempty"`
	LastStatus      *string    `db:"last_status" json:"last_status,omitempty"`
	RecordsAdded    int        `db:"records_added" json:"records_added"`
	RecordsUpdated  int        `db:"records_updated" json:"records_updated"`
}

// Notification is an in-app alert for a user (e.g. a new CVE affecting a scan).
type Notification struct {
	ID        string    `db:"id" json:"id"`
	ProjectID *string   `db:"project_id" json:"project_id,omitempty"`
	Kind      string    `db:"kind" json:"kind"`
	Title     string    `db:"title" json:"title"`
	Body      *string   `db:"body" json:"body,omitempty"`
	IsRead    bool      `db:"is_read" json:"is_read"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}
