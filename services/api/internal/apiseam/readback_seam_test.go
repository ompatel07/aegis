// Package apiseam holds end-to-end seam tests that exercise the API over real HTTP
// against a real database — the joint that per-package unit tests cannot see.
package apiseam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	// Register the pgx stdlib driver under the name "pgx".
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Seam: a scan whose every nullable column is NULL must still be readable through
// EVERY scan-scoped endpoint.
//
// T2 (b27b0b0) added `excluded_bundled JSONB` NULLABLE while models.Scan typed it
// json.RawMessage, which cannot scan NULL. All nine endpoints below returned 500 for
// any repo without bundled JS — the majority case. Unit tests, `go build` and the
// web typecheck were all green throughout, because nothing read a scan back with
// that column NULL.
//
// The endpoint list is a table on purpose: a new scan-scoped route added to
// scanEndpoints is covered by this seam automatically.
//
// Requires a live stack:
//
//	AEGIS_SEAM_API_URL=http://localhost:8080  AEGIS_SEAM_DB_URL=postgres://... go test ./internal/apiseam/...
//
// Skips (does not fail) when either is unset, so `go test ./...` stays runnable
// without Docker. The always-on type-level guard for the same defect lives in
// internal/models/nullsafe_seam_test.go.

// scanEndpoints is every scan-scoped read path. Add new ones here.
var scanEndpoints = []struct {
	name string
	path string // %s = scan id
}{
	{"scan detail", "/api/v1/scans/%s"},
	{"findings", "/api/v1/scans/%s/findings"},
	{"report", "/api/v1/scans/%s/report"},
	{"executive report", "/api/v1/scans/%s/report/executive"},
	{"compliance report", "/api/v1/scans/%s/report/compliance"},
	{"SARIF export", "/api/v1/scans/%s/export/sarif"},
	{"SBOM export", "/api/v1/scans/%s/export/sbom"},
	{"policy evaluation", "/api/v1/scans/%s/policy"},
}

type seamEnv struct {
	apiURL string
	db     *sqlx.DB
	token  string
	userID string
	projID string
}

func setup(t *testing.T) *seamEnv {
	t.Helper()
	apiURL, dbURL := os.Getenv("AEGIS_SEAM_API_URL"), os.Getenv("AEGIS_SEAM_DB_URL")
	if apiURL == "" || dbURL == "" {
		t.Skip("set AEGIS_SEAM_API_URL and AEGIS_SEAM_DB_URL to run the API read-back seam")
	}
	db, err := sqlx.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	env := &seamEnv{apiURL: apiURL, db: db}
	t.Cleanup(func() { db.Close() })

	// A dedicated tenant, so the seam never collides with real data.
	email := fmt.Sprintf("seam-%d@example.com", time.Now().UnixNano())
	body := map[string]string{"email": email, "password": "SeamPassw0rd!x", "name": "Seam Tester"}
	var reg struct {
		Data struct {
			User   struct{ ID string } `json:"user"`
			Tokens struct {
				AccessToken string `json:"access_token"`
			} `json:"tokens"`
		} `json:"data"`
	}
	env.post(t, "/api/v1/auth/register", "", body, &reg)
	env.token, env.userID = reg.Data.Tokens.AccessToken, reg.Data.User.ID
	if env.token == "" {
		t.Fatal("registration returned no access token")
	}

	var proj struct {
		Data struct{ ID string } `json:"data"`
	}
	env.post(t, "/api/v1/projects", env.token, map[string]any{
		"name": "seam-nullscan", "repo_url": "https://github.com/example/seam",
		"repo_type": "github", "default_branch": "main",
	}, &proj)
	env.projID = proj.Data.ID
	if env.projID == "" {
		t.Fatal("project creation returned no id")
	}
	return env
}

func (e *seamEnv) post(t *testing.T, path, token string, body, out any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, e.apiURL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("POST %s -> %d: %s", path, resp.StatusCode, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("POST %s decode: %v (%s)", path, err, raw)
		}
	}
}

// insertAllNullScan writes a completed scan in which EVERY nullable column is
// explicitly NULL. Only the NOT NULL columns are given values.
func (e *seamEnv) insertAllNullScan(t *testing.T) string {
	t.Helper()
	var id string
	err := e.db.QueryRow(`
		INSERT INTO scans (
			project_id, trigger, status,
			branch, commit_sha,
			quality_score, security_score, deployment_score, overall_score, overall_grade,
			started_at, completed_at, duration_seconds,
			raw_semgrep_output, raw_trivy_output, raw_gitleaks_output, raw_quality_output,
			error_message, reeval_reason, rule_pack_version, stage, notified_at,
			reliability_rating, security_rating, maintainability_rating,
			excluded_bundled
		) VALUES (
			$1, 'manual', 'completed',
			NULL, NULL,
			NULL, NULL, NULL, NULL, NULL,
			NULL, NULL, NULL,
			NULL, NULL, NULL, NULL,
			NULL, NULL, NULL, NULL, NULL,
			NULL, NULL, NULL,
			NULL
		) RETURNING id`, e.projID).Scan(&id)
	if err != nil {
		t.Fatalf("insert all-NULL scan: %v", err)
	}
	t.Cleanup(func() { e.db.Exec(`DELETE FROM scans WHERE id = $1`, id) })

	// Prove the premise: the row really does have those columns NULL.
	var nulls int
	if err := e.db.Get(&nulls, `
		SELECT (excluded_bundled IS NULL)::int + (security_score IS NULL)::int
		     + (security_rating IS NULL)::int + (overall_grade IS NULL)::int
		     + (rule_pack_version IS NULL)::int
		FROM scans WHERE id = $1`, id); err != nil {
		t.Fatalf("verify nulls: %v", err)
	}
	if nulls != 5 {
		t.Fatalf("expected 5 NULL columns on the fixture scan, got %d", nulls)
	}

	// The SBOM lives in its own table, so give the fixture one. Without it the export
	// honestly 404s ("no SBOM for this scan") and would not prove the endpoint can read
	// an all-NULL scan row — which it must, since it loads the scan before the SBOM.
	if _, err := e.db.Exec(
		`INSERT INTO scan_sboms (scan_id, cyclonedx) VALUES ($1, $2)`,
		id, `{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"components":[]}`,
	); err != nil {
		t.Fatalf("insert fixture sbom: %v", err)
	}
	return id
}

func (e *seamEnv) get(t *testing.T, path string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.apiURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+e.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// TestSeamAllNullScanIsReadableEverywhere is the regression test for the T2 P0.
// Reverting models.Scan.ExcludedBundled to json.RawMessage makes every subtest 500.
func TestSeamAllNullScanIsReadableEverywhere(t *testing.T) {
	env := setup(t)
	scanID := env.insertAllNullScan(t)

	for _, ep := range scanEndpoints {
		ep := ep
		t.Run(ep.name, func(t *testing.T) {
			path := fmt.Sprintf(ep.path, scanID)
			code, body := env.get(t, path)
			if code != http.StatusOK {
				t.Fatalf("GET %s -> %d (want 200)\nbody: %s", path, code, truncate(body))
			}
			if len(bytes.TrimSpace(body)) == 0 {
				t.Fatalf("GET %s -> 200 with an empty body", path)
			}
			// Well-formed: the body must parse as JSON and must not be an error envelope.
			var probe map[string]any
			if err := json.Unmarshal(body, &probe); err != nil {
				t.Fatalf("GET %s -> 200 but body is not JSON: %v\n%s", path, err, truncate(body))
			}
			if _, isErr := probe["error"]; isErr {
				t.Fatalf("GET %s -> 200 with an error envelope: %s", path, truncate(body))
			}
		})
	}

	// The list endpoint reads the same columns for many rows at once.
	t.Run("project scan list", func(t *testing.T) {
		path := fmt.Sprintf("/api/v1/projects/%s/scans", env.projID)
		code, body := env.get(t, path)
		if code != http.StatusOK {
			t.Fatalf("GET %s -> %d (want 200)\nbody: %s", path, code, truncate(body))
		}
		if !bytes.Contains(body, []byte(scanID)) {
			t.Fatalf("GET %s -> 200 but the all-NULL scan is missing from the list: %s",
				path, truncate(body))
		}
	})
}

// TestSeamNullColumnsRenderHonestly pins that a NULL is absent or null in the JSON —
// never a fabricated 0, "A", "-" or "".
func TestSeamNullColumnsRenderHonestly(t *testing.T) {
	env := setup(t)
	scanID := env.insertAllNullScan(t)

	code, body := env.get(t, fmt.Sprintf("/api/v1/scans/%s", scanID))
	if code != http.StatusOK {
		t.Fatalf("scan detail -> %d: %s", code, truncate(body))
	}
	var env2 struct {
		Data struct {
			Scan map[string]any `json:"scan"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	scan := env2.Data.Scan
	if scan == nil {
		t.Fatalf("no scan object in response: %s", truncate(body))
	}
	// A not-measured pillar must be omitted or null — never a made-up value.
	for _, k := range []string{
		"security_score", "quality_score", "deployment_score", "overall_score",
		"overall_grade", "security_rating", "reliability_rating", "maintainability_rating",
	} {
		v, present := scan[k]
		if !present || v == nil {
			continue // omitted or explicit null — both honest
		}
		t.Errorf("%s is NULL in the database but rendered as %#v — a NULL must never "+
			"become a measured-looking value", k, v)
	}
}

func truncate(b []byte) string {
	const max = 400
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}
