package services

import (
	"testing"

	"github.com/aegis-platform/api/internal/models"
)

func scanWith(sec, qual, aiSafety int, aiPct float64) *models.Scan {
	return &models.Scan{
		SecurityScore: &sec, QualityScore: &qual,
		AICodeSafetyScore: &aiSafety, AIGeneratedPct: &aiPct,
	}
}

func find(sev string, isNew bool) models.Finding {
	return models.Finding{Severity: sev, IsNew: isNew}
}

func checkByRule(checks []models.PolicyCheck, rule string) *models.PolicyCheck {
	for i := range checks {
		if checks[i].Rule == rule {
			return &checks[i]
		}
	}
	return nil
}

func TestEnterprisePolicyFailsOnNewFindingsAndLowScore(t *testing.T) {
	cfg := models.PolicyTemplates["enterprise"] // block_new_findings, min_sec 80, min_ai_safety 60
	scan := scanWith(55, 90, 40, 10)
	findings := []models.Finding{find("high", true), find("low", false)}

	passed, checks := evaluatePolicy(cfg, scan, findings)
	if passed {
		t.Fatal("expected FAIL")
	}
	if c := checkByRule(checks, "block_new_findings"); c == nil || c.Passed {
		t.Fatalf("block_new_findings should fail: %+v", c)
	}
	if c := checkByRule(checks, "min_security_score"); c == nil || c.Passed {
		t.Fatalf("min_security_score should fail (55<80): %+v", c)
	}
	if c := checkByRule(checks, "min_ai_safety_score"); c == nil || c.Passed {
		t.Fatalf("min_ai_safety_score should fail (40<60): %+v", c)
	}
}

func TestEnterprisePolicyPassesOnCleanScan(t *testing.T) {
	cfg := models.PolicyTemplates["enterprise"]
	scan := scanWith(85, 90, 75, 5)
	findings := []models.Finding{find("low", false), find("medium", false)} // none new
	passed, _ := evaluatePolicy(cfg, scan, findings)
	if !passed {
		t.Fatal("expected PASS on clean scan")
	}
}

func TestStartupPolicyOnlyBlocksNewCritical(t *testing.T) {
	cfg := models.PolicyTemplates["startup"] // block_new_severity: critical
	scan := scanWith(30, 30, 20, 90)

	// A new HIGH is allowed (below the critical gate).
	if passed, _ := evaluatePolicy(cfg, scan, []models.Finding{find("high", true)}); !passed {
		t.Fatal("startup should pass with a new high (only blocks new critical)")
	}
	// A new CRITICAL fails.
	if passed, _ := evaluatePolicy(cfg, scan, []models.Finding{find("critical", true)}); passed {
		t.Fatal("startup should fail with a new critical")
	}
	// An EXISTING critical (not new) is allowed under startup.
	if passed, _ := evaluatePolicy(cfg, scan, []models.Finding{find("critical", false)}); !passed {
		t.Fatal("startup should pass with an existing (grandfathered) critical")
	}
}

func TestSuppressedFindingsIgnored(t *testing.T) {
	cfg := models.PolicyConfig{MaxSeverity: models.SeverityHigh}
	scan := scanWith(90, 90, 90, 0)
	f := find("critical", false)
	f.IsSuppressed = true
	passed, _ := evaluatePolicy(cfg, scan, []models.Finding{f})
	if !passed {
		t.Fatal("suppressed critical must not trip the max_severity gate")
	}
}
