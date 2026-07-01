package pipeline

import (
	"testing"

	"github.com/aegis-platform/orchestrator/internal/types"
)

func ptr(i int) *int { return &i }

func secResult(engine string, fs ...types.Finding) *types.EngineResult {
	return &types.EngineResult{Engine: engine, Pillar: types.PillarSecurity, Status: "completed", Findings: fs}
}

func TestMergeDeepDedupesSameVuln(t *testing.T) {
	fast := []*types.EngineResult{
		secResult("semgrep",
			types.Finding{Engine: "semgrep", Pillar: types.PillarSecurity, CWEID: "CWE-89", FilePath: "app/x.js", LineStart: ptr(42)},
			types.Finding{Engine: "semgrep", Pillar: types.PillarSecurity, CWEID: "CWE-79", FilePath: "app/y.js", LineStart: ptr(10)},
		),
	}
	deep := secResult("joern",
		// Same CWE + file, line 43 within the ±2 window of the fast finding at 42.
		types.Finding{Engine: "joern", Pillar: types.PillarSecurity, CWEID: "CWE-89", FilePath: "app/x.js", LineStart: ptr(43)},
	)

	merged := MergeDeep(fast, deep)

	if got := len(fast[0].Findings); got != 1 {
		t.Fatalf("fast findings after dedupe = %d, want 1 (SQLi removed)", got)
	}
	if fast[0].Findings[0].CWEID != "CWE-79" {
		t.Fatalf("wrong fast finding kept: %s", fast[0].Findings[0].CWEID)
	}
	if len(merged) != 2 {
		t.Fatalf("merged results = %d, want 2 (fast + deep)", len(merged))
	}
	cb, _ := deep.Findings[0].Metadata["corroborated_by"].([]string)
	if len(cb) != 1 || cb[0] != "semgrep" {
		t.Fatalf("deep finding not marked corroborated: %v", deep.Findings[0].Metadata)
	}
}

func TestMergeDeepKeepsDistinctFindings(t *testing.T) {
	fast := []*types.EngineResult{
		secResult("semgrep", types.Finding{CWEID: "CWE-89", FilePath: "app/x.js", LineStart: ptr(42)}),
	}
	deep := secResult("joern", types.Finding{CWEID: "CWE-78", FilePath: "app/z.js", LineStart: ptr(5)})

	MergeDeep(fast, deep)

	if len(fast[0].Findings) != 1 {
		t.Fatalf("a distinct fast finding was wrongly deduped")
	}
}

func TestMergeDeepSkippedAppendsWithoutDedupe(t *testing.T) {
	fast := []*types.EngineResult{
		secResult("semgrep", types.Finding{CWEID: "CWE-89", FilePath: "app/x.js", LineStart: ptr(42)}),
	}
	deep := &types.EngineResult{Engine: "joern", Pillar: types.PillarSecurity, Status: "skipped"}

	merged := MergeDeep(fast, deep)

	if len(fast[0].Findings) != 1 {
		t.Fatalf("skipped deep scan changed fast findings")
	}
	if len(merged) != 2 {
		t.Fatalf("skipped deep result was not appended for the record")
	}
}

func TestMergeDeepNilIsNoop(t *testing.T) {
	fast := []*types.EngineResult{secResult("semgrep")}
	if got := len(MergeDeep(fast, nil)); got != 1 {
		t.Fatalf("nil deep changed results length: %d", got)
	}
}
