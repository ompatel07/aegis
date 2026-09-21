package pipeline

import (
	"testing"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// N1: the evidence lifecycle uses to decide what a finding's absence proves.
func TestLifecycleEvidenceFromEngineResults(t *testing.T) {
	semgrep := er("semgrep", "completed")
	semgrep.RulesExecuted = []string{"aegis-php-sql-injection"}
	semgrep.RulesShipped = []string{"aegis-php-sql-injection", "ajinabraham.njsscan.x"}

	degradedNoRules := er("gitleaks", "completed")
	degradedNoRules.Degraded = true // partial coverage, and nothing says which part

	ev := Aggregate([]*types.EngineResult{
		semgrep,
		er("trivy", "failed"),
		er("quality", "completed"),
		er("deployment", "skipped"),
		degradedNoRules,
	}).Evidence

	for engine, want := range map[string]bool{
		"semgrep":    true,
		"quality":    true,
		"ruff":       true, // ruff's findings ride the quality result
		"trivy":      false,
		"deployment": false,
		"gitleaks":   false,
	} {
		if ev.Completed[engine] != want {
			t.Errorf("Completed[%s] = %v, want %v", engine, ev.Completed[engine], want)
		}
	}
	if !ev.RulesExecuted["semgrep"]["aegis-php-sql-injection"] || ev.RulesExecuted["semgrep"]["ajinabraham.njsscan.x"] {
		t.Errorf("semgrep executed set wrong: %v", ev.RulesExecuted["semgrep"])
	}
	if !ev.RulesShipped["semgrep"]["ajinabraham.njsscan.x"] {
		t.Errorf("semgrep shipped set wrong: %v", ev.RulesShipped["semgrep"])
	}
	if _, ok := ev.RulesExecuted["quality"]; ok {
		t.Error("quality reports no per-rule set; it must not appear in RulesExecuted")
	}

	// A degraded semgrep that DOES report what ran is still usable evidence.
	degradedSemgrep := er("semgrep", "completed")
	degradedSemgrep.Degraded = true
	degradedSemgrep.RulesExecuted = []string{"ajinabraham.njsscan.x"}
	degradedSemgrep.RulesShipped = []string{"aegis-php-sql-injection", "ajinabraham.njsscan.x"}
	ev = Aggregate([]*types.EngineResult{degradedSemgrep}).Evidence
	if !ev.Completed["semgrep"] || ev.RulesExecuted["semgrep"]["aegis-php-sql-injection"] {
		t.Errorf("degraded semgrep with a rule list: completed=%v executed=%v",
			ev.Completed["semgrep"], ev.RulesExecuted["semgrep"])
	}
}
