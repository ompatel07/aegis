package apiseam

import (
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"

	// Register the pgx stdlib driver under the name "pgx".
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Seam: every column on a table we read with SELECT * must have a field on the
// struct we scan into.
//
// J4 added `code_key` to `findings` for rename-aware lifecycle and did not add it
// to models.Finding. FindingRepository then read with `SELECT * FROM findings`, so
// sqlx failed with "missing destination name code_key" and EVERY scan-read
// endpoint returned 500 — SARIF export, findings list, compliance report. Exactly
// the shape of the T2 excluded_bundled P0 that F1 caught, reproduced by adding a
// column.
//
// `go build`, `go vet` and the whole unit suite were green throughout, because
// nothing in them scans a findings row into the struct. Only running the real
// endpoint surfaced it. This test is that check, made cheap.
//
// Requires a live database:
//
//	AEGIS_SEAM_DB_URL=postgres://... go test ./internal/apiseam/...
//
// Skips (does not fail) when unset, so `go test ./...` stays runnable without
// Docker.
func TestSeamSelectStarTablesMatchTheirStructs(t *testing.T) {
	_, dbURL := requireSeamEnv(t, false)
	db, err := sqlx.Connect("pgx", dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = db.Close() }()

	// K2 converted `findings` to an explicit column list, so the assertion for it
	// changed direction. Under SELECT * the risk was a column the struct did not
	// declare; with an explicit list that is harmless by design — the query simply
	// does not ask for it. The remaining risk is the opposite one: the binary
	// asking for a column the schema does not have, which is an immediate SQL
	// error rather than a silent mismatch.
	//
	// So this runs the repository's REAL query fragment. It fails if any db tag on
	// models.Finding has no column behind it.
	//
	// `scans` is not listed for the same reason it never was: repository/scan.go
	// has always enumerated its columns, deliberately, so raw_semgrep_output and
	// friends need not exist on the struct.
	//
	// LIMIT 1 is enough: the column set is resolved before any row is touched, so
	// this fails on a mismatch even against an empty table.
	cases := []struct {
		name string
		dest any
		q    string
	}{
		{"findings (explicit list)", &[]models.Finding{},
			"SELECT " + repository.FindingColumns + " FROM findings LIMIT 1"},
		{"projects (explicit list)", &[]models.Project{},
			"SELECT " + repository.ProjectColumns + " FROM projects LIMIT 1"},
		{"users (explicit list)", &[]models.User{},
			"SELECT " + repository.UserColumns + " FROM users LIMIT 1"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := db.Select(c.dest, c.q); err != nil {
				t.Fatalf("%s: %v\n\n"+
					"A column exists on the table with no matching `db:` tag on the struct. "+
					"Every scan-read endpoint 500s in this state. Add the field to the model "+
					"(json:\"-\" is fine if the API never exposes it).", c.name, err)
			}
		})
	}
}
