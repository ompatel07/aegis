// Package sarif builds SARIF 2.1.0 documents from Aegis findings so results can
// be uploaded to GitHub code scanning or any SARIF-consuming tool. The output is
// validated against the official SARIF 2.1.0 JSON schema in sarif_test.go.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/aegis-platform/api/internal/models"
)

const (
	schemaURI  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	toolName   = "Aegis"
	toolURI    = "https://github.com/aegis-platform/aegis"
	toolVer    = "1.0.0"
	maxMsgLen  = 3000
	maxDescLen = 4000
)

// ── SARIF 2.1.0 types (only the subset we emit) ───────────────────────────────

type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool                     Tool             `json:"tool"`
	Results                  []Result         `json:"results"`
	VersionControlProvenance []VersionControl `json:"versionControlProvenance,omitempty"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     *Message       `json:"shortDescription,omitempty"`
	FullDescription      *Message       `json:"fullDescription,omitempty"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration *Configuration `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type Configuration struct {
	Level string `json:"level,omitempty"`
}

type Message struct {
	Text string `json:"text"`
}

type Result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations,omitempty"`
	CodeFlows           []CodeFlow        `json:"codeFlows,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	Message          *Message          `json:"message,omitempty"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type CodeFlow struct {
	ThreadFlows []ThreadFlow `json:"threadFlows"`
}

type ThreadFlow struct {
	Locations []ThreadFlowLocation `json:"locations"`
}

type ThreadFlowLocation struct {
	Location Location `json:"location"`
}

type VersionControl struct {
	RepositoryURI string `json:"repositoryUri"`
	RevisionID    string `json:"revisionId,omitempty"`
	Branch        string `json:"branch,omitempty"`
}

// ── Builder ───────────────────────────────────────────────────────────────────

// Build assembles a SARIF log from a scan's findings. `repoURL` may be empty.
func Build(scan *models.Scan, findings []models.Finding, repoURL string) *Log {
	ruleIndex := map[string]int{}
	rules := make([]Rule, 0)
	results := make([]Result, 0, len(findings))

	for _, f := range findings {
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			idx = len(rules)
			ruleIndex[f.RuleID] = idx
			rules = append(rules, buildRule(f))
		}
		results = append(results, buildResult(f, idx))
	}

	run := Run{
		Tool: Tool{Driver: Driver{
			Name: toolName, Version: toolVer, InformationURI: toolURI, Rules: rules,
		}},
		Results: results,
	}
	if repoURL != "" {
		vc := VersionControl{RepositoryURI: repoURL}
		if scan != nil {
			if scan.CommitSHA != nil {
				vc.RevisionID = *scan.CommitSHA
			}
			if scan.Branch != nil {
				vc.Branch = *scan.Branch
			}
		}
		run.VersionControlProvenance = []VersionControl{vc}
	}

	return &Log{Schema: schemaURI, Version: "2.1.0", Runs: []Run{run}}
}

func buildRule(f models.Finding) Rule {
	r := Rule{
		ID:                   f.RuleID,
		Name:                 f.RuleName,
		ShortDescription:     &Message{Text: truncate(fallback(f.Title, f.RuleName, f.RuleID), 400)},
		DefaultConfiguration: &Configuration{Level: level(f.Severity)},
		Properties:           map[string]any{},
	}
	if f.Description != nil && *f.Description != "" {
		r.FullDescription = &Message{Text: truncate(*f.Description, maxDescLen)}
	}
	tags := []string{f.Pillar}
	if f.CWEID != nil && *f.CWEID != "" {
		tags = append(tags, "external/cwe/"+cweSlug(*f.CWEID))
	}
	if f.OWASPCategory != nil && *f.OWASPCategory != "" {
		tags = append(tags, "owasp")
	}
	r.Properties["tags"] = tags
	// security-severity drives GitHub's security-alert categorization; only
	// meaningful for security-pillar findings.
	if f.Pillar == models.PillarSecurity {
		r.Properties["security-severity"] = securitySeverity(f.Severity)
	}
	return r
}

func buildResult(f models.Finding, ruleIdx int) Result {
	res := Result{
		RuleID:              f.RuleID,
		RuleIndex:           ruleIdx,
		Level:               level(f.Severity),
		Message:             Message{Text: truncate(messageText(f), maxMsgLen)},
		PartialFingerprints: map[string]string{"aegis/v1": fingerprint(f)},
		Properties: map[string]any{
			"pillar":   f.Pillar,
			"engine":   f.Engine,
			"severity": f.Severity,
		},
	}
	if loc, ok := physicalLocation(f.FilePath, f.LineStart, f.LineEnd, f.ColumnStart, f.ColumnEnd); ok {
		res.Locations = []Location{loc}
	}
	if cf := codeFlows(f); len(cf) > 0 {
		res.CodeFlows = cf
	}
	return res
}

// codeFlows converts a deep-scan finding's metadata.dataflow into SARIF
// codeFlows, preserving the interprocedural taint path (source -> sink).
func codeFlows(f models.Finding) []CodeFlow {
	if len(f.Metadata) == 0 {
		return nil
	}
	var meta struct {
		Dataflow []struct {
			File    string `json:"file"`
			Line    *int   `json:"line"`
			Message string `json:"message"`
		} `json:"dataflow"`
	}
	if err := json.Unmarshal(f.Metadata, &meta); err != nil || len(meta.Dataflow) == 0 {
		return nil
	}
	tfls := make([]ThreadFlowLocation, 0, len(meta.Dataflow))
	for _, step := range meta.Dataflow {
		loc, ok := physicalLocation(step.File, step.Line, nil, nil, nil)
		if !ok {
			continue
		}
		if step.Message != "" {
			loc.Message = &Message{Text: truncate(step.Message, 600)}
		}
		tfls = append(tfls, ThreadFlowLocation{Location: loc})
	}
	if len(tfls) == 0 {
		return nil
	}
	return []CodeFlow{{ThreadFlows: []ThreadFlow{{Locations: tfls}}}}
}

func physicalLocation(file string, lineStart, lineEnd, colStart, colEnd *int) (Location, bool) {
	if file == "" {
		return Location{}, false
	}
	pl := &PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: file}}
	if lineStart != nil && *lineStart >= 1 {
		reg := &Region{StartLine: *lineStart}
		if lineEnd != nil && *lineEnd >= *lineStart {
			reg.EndLine = *lineEnd
		}
		if colStart != nil && *colStart >= 1 {
			reg.StartColumn = *colStart
		}
		if colEnd != nil && *colEnd >= 1 {
			reg.EndColumn = *colEnd
		}
		pl.Region = reg
	}
	return Location{PhysicalLocation: pl}, true
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func level(severity string) string {
	switch severity {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func securitySeverity(severity string) string {
	switch severity {
	case models.SeverityCritical:
		return "9.5"
	case models.SeverityHigh:
		return "8.0"
	case models.SeverityMedium:
		return "5.0"
	case models.SeverityLow:
		return "3.0"
	default:
		return "1.0"
	}
}

func messageText(f models.Finding) string {
	if f.Description != nil && *f.Description != "" {
		return *f.Description
	}
	return fallback(f.Title, f.RuleName, f.RuleID)
}

func fingerprint(f models.Finding) string {
	line := 0
	if f.LineStart != nil {
		line = *f.LineStart
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", f.RuleID, f.FilePath, line)))
	return hex.EncodeToString(h[:])[:16]
}

// cweSlug maps "CWE-89" -> "cwe-89" for the SARIF external/cwe/* tag convention.
func cweSlug(cwe string) string {
	out := make([]rune, 0, len(cwe))
	for _, r := range cwe {
		switch {
		case r >= 'A' && r <= 'Z':
			out = append(out, r+('a'-'A'))
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-':
			out = append(out, r)
		}
	}
	return string(out)
}

func fallback(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return "finding"
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit-1] + "…"
}
