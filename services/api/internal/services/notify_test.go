package services

import (
	"testing"

	"github.com/aegis-platform/api/internal/models"
)

func nf(sev string, isNew bool) models.Finding {
	return models.Finding{Severity: sev, IsNew: isNew}
}

func TestNewCriticalFindings(t *testing.T) {
	findings := []models.Finding{
		nf("critical", true),  // counted
		nf("critical", false), // existing → not counted
		nf("high", true),      // not critical
	}
	got := newCriticalFindings(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 new critical, got %d", len(got))
	}
	// Suppressed criticals are ignored.
	sup := nf("critical", true)
	sup.IsSuppressed = true
	if len(newCriticalFindings([]models.Finding{sup})) != 0 {
		t.Fatal("suppressed critical must be ignored")
	}
}

func TestSeverityMeets(t *testing.T) {
	f := []models.Finding{nf("medium", false)}
	if !severityMeets(f, "medium") {
		t.Fatal("medium finding should meet a medium threshold")
	}
	if severityMeets(f, "high") {
		t.Fatal("medium finding should NOT meet a high threshold")
	}
	if !severityMeets(f, "all") {
		t.Fatal("'all' threshold should match any finding")
	}
	if severityMeets([]models.Finding{}, "all") {
		t.Fatal("no findings → nothing to notify")
	}
}
