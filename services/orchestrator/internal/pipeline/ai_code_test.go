package pipeline

import (
	"testing"

	"github.com/aegis-platform/orchestrator/internal/types"
)

func f(rule, file, sev string) types.Finding {
	return types.Finding{RuleID: rule, FilePath: file, Severity: sev, Engine: "semgrep"}
}

func TestTagAICodeTagsFindingsInAIFiles(t *testing.T) {
	findings := []types.Finding{
		f("aegis-js-xss", "app/ai_written.js", types.SeverityHigh),
		f("aegis-js-sqli", "app/ai_written.js", types.SeverityCritical),
		f("quality/long-func", "app/human.js", types.SeverityLow),
		f("ai-code-weak-crypto-js", "app/ai_written.js", types.SeverityHigh),
	}
	res := &types.AICodeResult{
		FilesScored: 2, AIFileCount: 1, AIGeneratedPct: 50, Threshold: 0.7,
		ModelAvailable: true,
		FileScores:     map[string]float64{"app/ai_written.js": 0.9, "app/human.js": 0.1},
		TopSignals:     []string{"generic naming"},
	}

	report := TagAICode(findings, res)

	// Findings in the AI file are tagged; the human-file one is not.
	if !findings[0].InAIGeneratedCode || !findings[1].InAIGeneratedCode || !findings[3].InAIGeneratedCode {
		t.Fatalf("expected findings in ai_written.js to be tagged")
	}
	if findings[2].InAIGeneratedCode {
		t.Fatalf("human-file finding must not be tagged")
	}
	if report.FindingsInAICode != 3 || report.FindingsInHumanCode != 1 {
		t.Fatalf("breakdown wrong: ai=%d human=%d", report.FindingsInAICode, report.FindingsInHumanCode)
	}
	if report.AIFailureModeCount != 1 {
		t.Fatalf("expected 1 ai-code-* failure-mode finding, got %d", report.AIFailureModeCount)
	}
	if report.AIFiles == nil || len(report.AIFiles) != 1 || report.AIFiles[0] != "app/ai_written.js" {
		t.Fatalf("expected ai_files=[app/ai_written.js], got %v", report.AIFiles)
	}
	// Safety score penalizes weighted findings density in AI files (< 100 here).
	if report.SafetyScore >= 100 || report.SafetyScore < 0 {
		t.Fatalf("safety score out of expected range: %d", report.SafetyScore)
	}
	// Probability copied onto findings.
	if findings[0].AIGeneratedProbability == nil || *findings[0].AIGeneratedProbability != 0.9 {
		t.Fatalf("expected probability 0.9 on tagged finding")
	}
}

func TestTagAICodeNilResultTreatsAllHuman(t *testing.T) {
	findings := []types.Finding{f("r1", "a.js", types.SeverityHigh)}
	report := TagAICode(findings, nil)
	if findings[0].InAIGeneratedCode {
		t.Fatalf("nil result must not tag findings")
	}
	if report.FindingsInHumanCode != 1 || report.SafetyScore != 100 {
		t.Fatalf("nil result should yield human=1, safety=100; got human=%d safety=%d",
			report.FindingsInHumanCode, report.SafetyScore)
	}
}
