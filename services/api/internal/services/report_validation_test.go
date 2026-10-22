package services

import (
	"strings"
	"testing"

	"github.com/aegis-platform/api/internal/models"
)

// N4: a finding from a SILENT-CLEAN rule is real but its rule's recall is
// unvalidated. Reports must keep it (it is a true finding) and label it, so a
// reader can tell proven detection from a rule that has never been seen to fire
// on real code.
func TestSilentCleanFindingsAreLabelledInReports(t *testing.T) {
	findings := []models.Finding{
		{Title: "DES cipher", Severity: models.SeverityHigh, FilePath: "a/Crypto.java",
			Metadata: models.JSONB(`{"ruleset":"aegis-custom","validation":"silent-clean","recall_unvalidated":true}`)},
		{Title: "SQL injection", Severity: models.SeverityHigh, FilePath: "a/Dao.java",
			Metadata: models.JSONB(`{"ruleset":"aegis-custom"}`)},
		{Title: "no metadata", Severity: models.SeverityHigh, FilePath: "a/X.java"},
	}
	risks := topRisks(findings, 10)
	if len(risks) != 3 {
		t.Fatalf("a silent-clean finding must not be dropped: got %d risks", len(risks))
	}
	if !risks[0].RecallUnvalidated || risks[1].RecallUnvalidated || risks[2].RecallUnvalidated {
		t.Errorf("only the silent-clean finding is labelled: %+v", risks)
	}

	digest := metadataDigest("acme", &models.Scan{OverallGrade: sp3("B")}, findings)
	if !strings.Contains(digest, "DES cipher | high | rule recall unvalidated") {
		t.Errorf("AI digest must carry the label:\n%s", digest)
	}
	if strings.Contains(digest, "SQL injection | high | rule recall unvalidated") {
		t.Errorf("a proven finding must not be labelled:\n%s", digest)
	}
}

func TestRecallUnvalidatedToleratesBadMetadata(t *testing.T) {
	if recallUnvalidated(models.JSONB(`not json`)) {
		t.Error("unreadable metadata must read as a proven rule, not as a label")
	}
	if recallUnvalidated(nil) {
		t.Error("absent metadata is a proven rule")
	}
}
