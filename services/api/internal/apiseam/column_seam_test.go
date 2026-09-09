package apiseam

import (
	"os"
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"

	// Register the pgx stdlib driver under the name "pgx".
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Seam: every column on a table we read with SELECT * must have a field on the
// struct we scan into.
//
// J4 added `code_key` to `findings` for rename-aware lifecycle and did not add it
// to models.Finding. FindingRepository reads with `SELECT * FROM findings`, so
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
	dbURL := os.Getenv("AEGIS_SEAM_DB_URL")
	if dbURL == "" {
		t.Skip("set AEGIS_SEAM_DB_URL to run the SELECT * column seam")
	}
	db, err := sqlx.Connect("pgx", dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Only tables genuinely read with SELECT * belong here. `scans` deliberately
	// does not: repository/scan.go enumerates its columns precisely so that
	// raw_semgrep_output and friends never have to exist on the struct. That is
	// the safer pattern, and adding it to this table would assert something the
	// code does not do.
	//
	// LIMIT 1 is enough: sqlx resolves the full column set before it touches a
	// row, so this fails on a schema/struct mismatch even on an empty table.
	cases := []struct {
		name string
		dest any
		q    string
	}{
		{"findings", &[]models.Finding{}, "SELECT * FROM findings LIMIT 1"},
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
