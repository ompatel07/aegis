package store

import (
	"context"
	"os"
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// ── Pure: what does a finding's absence prove? ──────────────────────────────

func TestAbsenceVerdict(t *testing.T) {
	set := func(ids ...string) map[string]bool {
		m := map[string]bool{}
		for _, id := range ids {
			m[id] = true
		}
		return m
	}
	ev := types.LifecycleEvidence{
		Completed:     map[string]bool{"semgrep": true, "quality": true, "ruff": true},
		RulesExecuted: map[string]map[string]bool{"semgrep": set("aegis-php-sql-injection")},
		RulesShipped:  map[string]map[string]bool{"semgrep": set("aegis-php-sql-injection", "ajinabraham.njsscan.x")},
	}
	cases := []struct {
		name, engine, rule, want string
	}{
		{"rule ran and did not fire -> fixed", "semgrep", "aegis-php-sql-injection", statusResolved},
		{"rule no longer ships (N1) -> retired, NOT fixed", "semgrep", "php.lang.security.exec-use.exec-use", statusRetired},
		{"rule ships but did not run (JS not detected) -> unchanged", "semgrep", "ajinabraham.njsscan.x", ""},
		{"engine failed / timed out -> unchanged", "trivy", "CVE-2024-0001", ""},
		{"engine with no per-rule set completed -> fixed", "quality", "quality/duplicated-code", statusResolved},
		{"ruff rides the quality result", "ruff", "S608", statusResolved},
	}
	for _, c := range cases {
		if got := absenceVerdict(ev, c.engine, c.rule); got != c.want {
			t.Errorf("%s: absenceVerdict(%s, %s) = %q, want %q", c.name, c.engine, c.rule, got, c.want)
		}
	}
	// A scan result from a pre-N1 scanner carries no evidence: keep the old behaviour
	// rather than freezing every project's lifecycle.
	if got := absenceVerdict(types.LifecycleEvidence{}, "semgrep", "anything"); got != statusResolved {
		t.Errorf("no evidence: got %q, want the pre-N1 %q", got, statusResolved)
	}
}

// ── Seam: the real SQL, against the migrated schema ─────────────────────────

// requireSeamDB mirrors apiseam.requireSeamEnv (K1): skipping locally is fine,
// skipping in CI is the bug.
func requireSeamDB(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("AEGIS_SEAM_DB_URL")
	if dsn != "" {
		return dsn
	}
	if os.Getenv("CI") != "" {
		t.Fatalf("AEGIS_SEAM_DB_URL is not set in CI; this test proves lifecycle never records " +
			"\"stopped looking\" as \"fixed\" and must not silently skip there")
	}
	t.Skip("set AEGIS_SEAM_DB_URL to run the lifecycle seam locally")
	return ""
}

func TestLifecycleNeverResolvesWhatDidNotRun(t *testing.T) {
	dsn := requireSeamDB(t)
	ctx := context.Background()
	db, err := sqlx.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }() // leave nothing behind

	var projectID string
	if err := tx.GetContext(ctx, &projectID, `
		WITH u AS (INSERT INTO users (email, password_hash, name)
		           VALUES ('n1-lifecycle@test.invalid', 'x', 'n1') RETURNING id)
		INSERT INTO projects (user_id, name, slug) SELECT id, 'n1-lifecycle', 'n1-lifecycle' FROM u
		RETURNING id`); err != nil {
		t.Fatal(err)
	}
	newScan := func() string {
		var id string
		if err := tx.GetContext(ctx, &id, `SELECT gen_random_uuid()::text`); err != nil {
			t.Fatal(err)
		}
		return id
	}
	finding := func(engine, rule, fp string) types.Finding {
		return types.Finding{Engine: engine, RuleID: rule, Fingerprint: fp, FilePath: "a.php", Severity: "high", Title: rule}
	}
	kept := finding("semgrep", "aegis-php-sql-injection", "fp-kept")        // rule still ships
	removed := finding("semgrep", "php.lang.security.exec-use.exec-use", "fp-removed") // N1 removed it
	cve := finding("trivy", "CVE-2024-0001", "fp-cve")                      // engine will fail
	status := func(fp string) string {
		var s string
		if err := tx.GetContext(ctx, &s,
			`SELECT status FROM project_finding_states WHERE project_id = $1 AND fingerprint = $2`,
			projectID, fp); err != nil {
			t.Fatalf("%s: %v", fp, err)
		}
		return s
	}
	shipped := map[string]bool{"aegis-php-sql-injection": true}

	// Scan 1 (baseline, pre-cut rule set): all three present.
	if err := applyLifecycle(ctx, tx, projectID, newScan(),
		[]types.Finding{kept, removed, cve}, types.LifecycleEvidence{}); err != nil {
		t.Fatal(err)
	}

	// Scan 2 (after N1): nothing fires. semgrep completed with the sovereign rule
	// set; trivy failed (a timeout, say).
	ev := types.LifecycleEvidence{
		Completed:     map[string]bool{"semgrep": true},
		RulesExecuted: map[string]map[string]bool{"semgrep": shipped},
		RulesShipped:  map[string]map[string]bool{"semgrep": shipped},
	}
	if err := applyLifecycle(ctx, tx, projectID, newScan(), nil, ev); err != nil {
		t.Fatal(err)
	}
	if got := status("fp-kept"); got != statusResolved {
		t.Errorf("a finding whose rule ran and did not fire must be resolved; got %q", got)
	}
	if got := status("fp-removed"); got != statusRetired {
		t.Errorf("a finding whose rule no longer ships must be RETIRED, never resolved "+
			"(it would appear as remediation evidence); got %q", got)
	}
	if got := status("fp-cve"); got != statusExisting {
		t.Errorf("a finding from an engine that failed must be left open; got %q", got)
	}
	var resolvedScan *string
	if err := tx.GetContext(ctx, &resolvedScan,
		`SELECT resolved_scan_id::text FROM project_finding_states WHERE project_id=$1 AND fingerprint='fp-removed'`,
		projectID); err != nil {
		t.Fatal(err)
	}
	if resolvedScan != nil {
		t.Errorf("a retired finding must carry no resolved_scan_id; got %s", *resolvedScan)
	}

	// Scan 3: the removed rule comes back and fires again. It was never fixed, so it
	// is EXISTING -- not a regression and not new.
	findings := []types.Finding{removed}
	if err := applyLifecycle(ctx, tx, projectID, newScan(), findings, types.LifecycleEvidence{}); err != nil {
		t.Fatal(err)
	}
	if got := status("fp-removed"); got != statusExisting {
		t.Errorf("a retired finding seen again must be existing; got %q", got)
	}
	if findings[0].IsNew {
		t.Error("a retired finding seen again must not be flagged new")
	}
}
