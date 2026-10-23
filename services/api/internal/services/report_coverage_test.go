package services

import (
	"strings"
	"testing"

	"github.com/aegis-platform/api/internal/models"
)

const javaOnlyCoverage = `{"total_code_lines":5000,"strong_fraction":0,"limited_fraction":1,
 "uncovered_fraction":0,"confident":false,"threshold":0.5,"summary":"Java limited",
 "gap":"most of this repository is in languages Aegis covers thinly or not at all (Java 100% (7 rules)), so an absence of findings is not evidence of safety",
 "languages":[{"language":"java","tier":"limited","loc":5000,"share":1,"rules":7,"cwe_classes":7}]}`

const phpCoverage = `{"total_code_lines":11000,"strong_fraction":1,"limited_fraction":0,
 "uncovered_fraction":0,"confident":true,"threshold":0.5,"summary":"PHP strong","gap":null,
 "languages":[{"language":"php","tier":"strong","loc":11000,"share":1,"rules":5,"cwe_classes":5}]}`

// N2: an executive summary is read as prose. A scan of a repository we can barely
// read must say so in the first paragraph -- "0 security issues" on a language with
// seven rules is not a good result, and presenting it as one is the lie this fixes.
func TestExecutiveSummaryCaveatsThinCoverage(t *testing.T) {
	scan := &models.Scan{
		OverallGrade:        sp3("A"),
		QualityScore:        ip2(88),
		SecurityIssuesTotal: 0,
		SecurityCoverage:    models.JSONB(javaOnlyCoverage),
	}
	summary := templateSummary("acme-java", scan, nil)
	if !strings.Contains(summary, "NOT MEASURED") {
		t.Errorf("summary does not say the security score is not measured:\n%s", summary)
	}
	if !strings.Contains(summary, "Java limited") {
		t.Errorf("summary does not name the coverage gap:\n%s", summary)
	}
	// The things that DID run must not be written off with it.
	if !strings.Contains(summary, "Dependency CVEs") {
		t.Errorf("summary must still credit the engines that ran:\n%s", summary)
	}
}

func TestExecutiveSummaryUnchangedOnStrongCoverage(t *testing.T) {
	scan := &models.Scan{
		OverallGrade: sp3("B"), QualityScore: ip2(74), SecurityScore: ip2(80),
		SecurityCoverage: models.JSONB(phpCoverage),
	}
	summary := templateSummary("acme-php", scan, nil)
	if strings.Contains(summary, "NOT MEASURED") {
		t.Errorf("a strongly-covered scan must not be caveated:\n%s", summary)
	}
}

// A scan from before N2 carries no coverage. Its prose must be untouched rather than
// caveated, which would retroactively cast doubt on every historical report.
func TestExecutiveSummaryUnchangedWithoutCoverage(t *testing.T) {
	scan := &models.Scan{OverallGrade: sp3("B"), QualityScore: ip2(74), SecurityScore: ip2(80)}
	if strings.Contains(templateSummary("legacy", scan, nil), "NOT MEASURED") {
		t.Error("a pre-N2 scan must keep its original summary")
	}
	if sastCoverageSentence(nil) != "" {
		t.Error("absent coverage must produce no sentence, not a claim of full coverage")
	}
	if !coverageConfident(nil) {
		t.Error("absent coverage must not withhold historical scores")
	}
}

// The AI backend receives only this digest. If coverage is missing from it, the model
// writes "no security issues were found" about a codebase we never read.
func TestAIDigestCarriesCoverage(t *testing.T) {
	scan := &models.Scan{
		OverallGrade: sp3("A"), SecurityIssuesTotal: 0,
		SecurityCoverage: models.JSONB(javaOnlyCoverage),
	}
	digest := metadataDigest("acme-java", scan, nil)
	if !strings.Contains(digest, "SAST coverage") || !strings.Contains(digest, "Java limited") {
		t.Errorf("AI digest omits coverage; the model will write a false clean summary:\n%s", digest)
	}
}

func TestCoverageSentenceIsRobustToJunk(t *testing.T) {
	// Malformed or partial JSON must degrade to silence, never to a fabricated claim
	// and never to a panic on a customer's report.
	for _, j := range []string{"", "null", "{}", "not json", `{"confident":true}`, `{"summary":""}`} {
		if got := sastCoverageSentence(models.JSONB(j)); got != "" {
			t.Errorf("input %q produced %q; expected silence", j, got)
		}
	}
}

// N6: the report says which claim is certified, never "measured" for half a result.
func TestCoverageSentenceNamesTheCertifiedClaim(t *testing.T) {
	problem := `{"summary":"Java — limited · 15% held-out recall on 2 corpora","confident":false,
 "quadrant":"problem-only","clean_label":"No issues found in what we check · Java 15% held-out recall"}`
	got := sastCoverageSentence(models.JSONB(problem))
	if !strings.Contains(got, "certified") || !strings.Contains(got, "No issues found in what we check") ||
		strings.Contains(got, "measured one") {
		t.Errorf("problem-only sentence: %s", got)
	}
	clean := `{"summary":"PHP — limited · 42% held-out recall on 3 corpora","confident":false,
 "quadrant":"clean-only","precision_caveat":"findings are not certified: PHP 27% precise"}`
	got = sastCoverageSentence(models.JSONB(clean))
	if !strings.Contains(got, "not certified") || !strings.Contains(got, "no unfavourable grade") {
		t.Errorf("clean-only sentence: %s", got)
	}
	if coverageConfident(models.JSONB(clean)) || coverageConfident(models.JSONB(problem)) {
		t.Error("a half-certified scan must carry the caveat in the summary's first paragraph")
	}
	full := `{"summary":"PHP strong","confident":true,"quadrant":"full","strong_fraction":1}`
	if !coverageConfident(models.JSONB(full)) {
		t.Error("full quadrant is confident")
	}
}
