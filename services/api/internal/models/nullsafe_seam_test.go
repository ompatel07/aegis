package models

import (
	"database/sql"
	"encoding/json"
	"reflect"
	"testing"
)

// Seam: every DB-scanned field must be able to hold SQL NULL.
//
// T2 shipped a P0 (b27b0b0): migration 000029 added `excluded_bundled JSONB`
// NULLABLE, but models.Scan typed it `json.RawMessage`, which does NOT implement
// sql.Scanner and therefore cannot scan NULL. Every scan-scoped read endpoint —
// /scans/{id}, /findings, /report, /report/executive, /report/compliance,
// /export/sarif, /export/sbom, /policy and /projects/{id}/scans — returned 500 for
// any repo with no bundled JS, i.e. the majority case. 150 passing scanner tests, a
// clean go build and a clean typecheck all missed it because nothing read a scan
// back with that column NULL.
//
// These tests are the type-level guard. They need no database, so they run on every
// `go test ./...`, and they fail the moment a jsonb column is typed json.RawMessage
// again. The HTTP-level counterpart (all nine endpoints against a genuinely
// all-NULL scan row) lives in internal/apiseam.

// modelsUnderTest are the structs sqlx scans database rows into.
func modelsUnderTest() map[string]any {
	return map[string]any{
		"Scan":         Scan{},
		"Finding":      Finding{},
		"Project":      Project{},
		"User":         User{},
		"Organization": Organization{},
		"Policy":       Policy{},
	}
}

// TestNoRawMessageOnDBScannedFields bans json.RawMessage from any field carrying a
// `db` tag. json.RawMessage is a []byte alias with no Scan method: a NULL column
// makes sqlx fail the whole row. models.JSONB is the NULL-safe equivalent and must
// be used instead — it keeps NULL distinguishable from an empty object, which is
// the honest-states distinction we are not willing to flatten away.
func TestNoRawMessageOnDBScannedFields(t *testing.T) {
	rawMessageType := reflect.TypeOf(json.RawMessage{})

	for name, model := range modelsUnderTest() {
		typ := reflect.TypeOf(model)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.Tag.Get("db") == "" {
				continue // not scanned from the database
			}
			if f.Type == rawMessageType {
				t.Errorf(
					"%s.%s (db:%q) is json.RawMessage, which cannot scan SQL NULL — "+
						"use models.JSONB instead. This is the T2 P0 (b27b0b0) that 500'd "+
						"every scan-scoped read endpoint.",
					name, f.Name, f.Tag.Get("db"))
			}
		}
	}
}

// TestJSONBIsNullSafe pins the contract the fix depends on: *JSONB implements
// sql.Scanner and a NULL source yields a nil value that marshals to JSON null —
// so "nothing was excluded" stays distinguishable from "an empty exclusion".
func TestJSONBIsNullSafe(t *testing.T) {
	var j JSONB
	if _, ok := any(&j).(sql.Scanner); !ok {
		t.Fatal("*JSONB must implement sql.Scanner so nullable jsonb columns can scan")
	}

	if err := (&j).Scan(nil); err != nil {
		t.Fatalf("scanning SQL NULL must succeed, got %v", err)
	}
	if j != nil {
		t.Errorf("SQL NULL must yield a nil JSONB, got %q", string(j))
	}
	b, err := json.Marshal(j)
	if err != nil {
		t.Fatalf("marshalling a nil JSONB: %v", err)
	}
	if string(b) != "null" {
		t.Errorf("a NULL column must render as JSON null (not {} — that would fabricate "+
			"an empty exclusion), got %s", string(b))
	}

	// A real value must round-trip untouched.
	if err := (&j).Scan([]byte(`{"files":3}`)); err != nil {
		t.Fatalf("scanning a real value: %v", err)
	}
	if string(j) != `{"files":3}` {
		t.Errorf("value round-trip corrupted: %s", string(j))
	}
}

// TestScanJSONBFieldsAreNullSafe names the three scan jsonb columns explicitly, so
// the guard is legible at the point of the incident even if modelsUnderTest changes.
func TestScanJSONBFieldsAreNullSafe(t *testing.T) {
	typ := reflect.TypeOf(Scan{})
	jsonbType := reflect.TypeOf(JSONB{})

	for _, col := range []string{"engines_degraded", "filtered_secrets", "excluded_bundled"} {
		var found bool
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.Tag.Get("db") != col {
				continue
			}
			found = true
			if f.Type != jsonbType {
				t.Errorf("Scan.%s (db:%q) must be models.JSONB to tolerate SQL NULL, got %s",
					f.Name, col, f.Type)
			}
		}
		if !found {
			t.Errorf("no field on models.Scan maps to db column %q", col)
		}
	}
}
