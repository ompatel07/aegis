package sarif

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/aegis-platform/api/internal/models"
)

func strp(s string) *string { return &s }
func intp(i int) *int       { return &i }

func sampleFindings() []models.Finding {
	deepMeta := json.RawMessage(`{"deep_scan":true,"dataflow":[
		{"file":"app/routes/x.js","line":10,"message":"req.query.id"},
		{"file":"app/data/dao.js","line":30,"message":"db.query(sql)"}]}`)
	return []models.Finding{
		{
			RuleID: "aegis-js-sql-injection", RuleName: "SQL injection", Pillar: models.PillarSecurity,
			Engine: "semgrep", Severity: models.SeverityCritical, Title: "SQLi in handler",
			Description: strp("Untrusted request data reaches a SQL sink."),
			FilePath:    "app/routes/x.js", LineStart: intp(42), LineEnd: intp(42),
			ColumnStart: intp(5), ColumnEnd: intp(40),
			CWEID: strp("CWE-89"), OWASPCategory: strp("A03:2021 - Injection"),
		},
		{
			RuleID: "joern/sql-injection", RuleName: "SQL injection (dataflow)", Pillar: models.PillarSecurity,
			Engine: "joern", Severity: models.SeverityCritical, Title: "SQLi taint flow",
			FilePath: "app/data/dao.js", LineStart: intp(30), CWEID: strp("CWE-89"),
			Metadata: models.JSONB(deepMeta),
		},
		{
			RuleID: "quality/duplicated-code", RuleName: "Duplicated code", Pillar: models.PillarQuality,
			Engine: "quality", Severity: models.SeverityLow, Title: "Duplicated block",
			FilePath: "app/data/dao.js", LineStart: intp(15), LineEnd: intp(30),
		},
		{
			RuleID: "quality/tech-debt-marker", RuleName: "TODO marker", Pillar: models.PillarQuality,
			Engine: "quality", Severity: models.SeverityLow, Title: "TODO markers",
			FilePath: "app/routes/x.js", // no line -> location without a region
		},
	}
}

func TestBuildValidatesAgainstSarif210Schema(t *testing.T) {
	scan := &models.Scan{Branch: strp("main"), CommitSHA: strp("abc123def456")}
	log := Build(scan, sampleFindings(), "https://github.com/acme/app")

	data, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	schemaBytes, err := os.ReadFile("testdata/sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatalf("read bundled schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("sarif-2.1.0.json", bytes.NewReader(schemaBytes)); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	schema, err := compiler.Compile("sarif-2.1.0.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal generated sarif: %v", err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Fatalf("generated SARIF does not validate against the SARIF 2.1.0 schema:\n%v", err)
	}
}

func TestBuildStructure(t *testing.T) {
	log := Build(nil, sampleFindings(), "")

	if log.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "Aegis" {
		t.Fatalf("driver name = %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 4 {
		t.Fatalf("rules = %d, want 4 distinct", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 4 {
		t.Fatalf("results = %d, want 4", len(run.Results))
	}

	for _, r := range run.Results {
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Fatalf("ruleIndex %d does not point to rule %q", r.RuleIndex, r.RuleID)
		}
	}

	byRule := map[string]Result{}
	for _, r := range run.Results {
		byRule[r.RuleID] = r
	}

	// Deep finding preserves its dataflow as SARIF codeFlows.
	deep := byRule["joern/sql-injection"]
	if len(deep.CodeFlows) != 1 || len(deep.CodeFlows[0].ThreadFlows[0].Locations) != 2 {
		t.Fatalf("deep finding missing 2-step codeFlows: %+v", deep.CodeFlows)
	}

	// Severity -> level mapping.
	if byRule["aegis-js-sql-injection"].Level != "error" {
		t.Fatalf("critical should map to error")
	}
	if byRule["quality/duplicated-code"].Level != "note" {
		t.Fatalf("low should map to note")
	}

	// security-severity present for security rules, absent for quality rules.
	rulesByID := map[string]Rule{}
	for _, r := range run.Tool.Driver.Rules {
		rulesByID[r.ID] = r
	}
	if _, ok := rulesByID["aegis-js-sql-injection"].Properties["security-severity"]; !ok {
		t.Fatalf("security rule missing security-severity")
	}
	if _, ok := rulesByID["quality/duplicated-code"].Properties["security-severity"]; ok {
		t.Fatalf("quality rule should not carry security-severity")
	}

	// A finding without a line still yields a location (no region).
	td := byRule["quality/tech-debt-marker"]
	if len(td.Locations) != 1 || td.Locations[0].PhysicalLocation.Region != nil {
		t.Fatalf("no-line finding should have a location without a region")
	}
}
