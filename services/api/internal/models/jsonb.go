package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

// JSONB is a NULL-safe wrapper around raw JSON for jsonb columns. It implements
// sql.Scanner (tolerating SQL NULL) and driver.Valuer, and round-trips as raw
// JSON in API responses.
type JSONB json.RawMessage

// Scan implements sql.Scanner. A NULL column yields a nil JSONB.
func (j *JSONB) Scan(src any) error {
	if src == nil {
		*j = nil
		return nil
	}
	switch v := src.(type) {
	case []byte:
		b := make([]byte, len(v))
		copy(b, v)
		*j = b
	case string:
		*j = []byte(v)
	default:
		return errors.New("models.JSONB: unsupported Scan source type")
	}
	return nil
}

// Value implements driver.Valuer.
func (j JSONB) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	return []byte(j), nil
}

// MarshalJSON renders the raw JSON as-is (or null when empty).
func (j JSONB) MarshalJSON() ([]byte, error) {
	if len(j) == 0 {
		return []byte("null"), nil
	}
	return j, nil
}

// UnmarshalJSON stores the raw bytes verbatim.
func (j *JSONB) UnmarshalJSON(data []byte) error {
	*j = append((*j)[0:0], data...)
	return nil
}
