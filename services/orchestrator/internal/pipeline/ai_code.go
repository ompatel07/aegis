package pipeline

import (
	"context"
	"math"
	"sort"
	"strings"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// AIIssueCount is one rule's finding count within AI-generated files.
type AIIssueCount struct {
	RuleID string `json:"rule_id"`
	Title  string `json:"title"`
	Count  int    `json:"count"`
}

// AICodeReport is the per-scan AI-generated-code summary (persisted as JSONB and
// surfaced in the dashboard + executive report). Derived from file metadata only.
type AICodeReport struct {
	FilesScored         int            `json:"files_scored"`
	AIFileCount         int            `json:"ai_file_count"`
	AIGeneratedPct      float64        `json:"ai_generated_pct"`
	Threshold           float64        `json:"threshold"`
	ModelAvailable      bool           `json:"model_available"`
	FindingsInAICode    int            `json:"findings_in_ai_code"`
	FindingsInHumanCode int            `json:"findings_in_human_code"`
	AIFailureModeCount  int            `json:"ai_failure_mode_findings"`
	SafetyScore         int            `json:"safety_score"`
	TopAIIssues         []AIIssueCount `json:"top_ai_issues"`
	TopSignals          []string       `json:"top_signals"`
}

var _sevWeight = map[string]float64{
	types.SeverityCritical: 5, types.SeverityHigh: 3, types.SeverityMedium: 2,
	types.SeverityLow: 1, types.SeverityInfo: 0.5,
}

// AICode runs the AI-code analysis pass. A failure degrades gracefully (nil) and
// never fails the overall scan.
func (p *Pipeline) AICode(ctx context.Context, dir, scanID string) *types.AICodeResult {
	res, err := p.scanner.AICode(ctx, dir, scanID)
	if err != nil {
		p.log.Error().Err(err).Str("scan_id", scanID).Msg("ai-code pass failed (degraded)")
		return nil
	}
	if res.Status == "failed" {
		p.log.Warn().Str("scan_id", scanID).Str("error", res.Error).Msg("ai-code pass returned failed")
		return nil
	}
	p.log.Info().Str("scan_id", scanID).
		Int("files_scored", res.FilesScored).Int("ai_files", res.AIFileCount).
		Float64("ai_pct", res.AIGeneratedPct).Bool("model", res.ModelAvailable).
		Msg("ai-code pass completed")
	return res
}

// TagAICode tags findings that sit in AI-generated files (mutating the slice) and
// returns the assembled report. Safe with a nil result (all findings → human).
func TagAICode(findings []types.Finding, res *types.AICodeResult) *AICodeReport {
	report := &AICodeReport{Threshold: 0.7}
	if res != nil {
		report.FilesScored = res.FilesScored
		report.AIFileCount = res.AIFileCount
		report.AIGeneratedPct = res.AIGeneratedPct
		report.ModelAvailable = res.ModelAvailable
		report.TopSignals = res.TopSignals
		if res.Threshold > 0 {
			report.Threshold = res.Threshold
		}
	}

	tally := map[string]*AIIssueCount{}
	var weighted float64
	for i := range findings {
		f := &findings[i]
		if strings.HasPrefix(f.RuleID, "ai-code-") {
			report.AIFailureModeCount++
		}
		inAI := false
		if res != nil {
			if score, ok := res.FileScores[f.FilePath]; ok {
				s := score
				f.AIGeneratedProbability = &s
				inAI = score > report.Threshold
			}
		}
		if inAI {
			f.InAIGeneratedCode = true
			report.FindingsInAICode++
			weighted += _sevWeight[f.Severity]
			ic := tally[f.RuleID]
			if ic == nil {
				title := f.TitleHuman
				if title == "" {
					title = f.RuleName
				}
				if title == "" {
					title = f.RuleID
				}
				ic = &AIIssueCount{RuleID: f.RuleID, Title: title}
				tally[f.RuleID] = ic
			}
			ic.Count++
		} else {
			report.FindingsInHumanCode++
		}
	}

	// AI-code safety score (0-100): 100 minus severity-weighted finding density
	// per AI-generated file. No AI code → nothing to be unsafe about → 100.
	if report.AIFileCount > 0 {
		density := weighted / float64(report.AIFileCount)
		safety := 100 - int(math.Round(density*10))
		if safety < 0 {
			safety = 0
		}
		report.SafetyScore = safety
	} else {
		report.SafetyScore = 100
	}

	for _, ic := range tally {
		report.TopAIIssues = append(report.TopAIIssues, *ic)
	}
	sort.Slice(report.TopAIIssues, func(i, j int) bool {
		return report.TopAIIssues[i].Count > report.TopAIIssues[j].Count
	})
	if len(report.TopAIIssues) > 5 {
		report.TopAIIssues = report.TopAIIssues[:5]
	}
	return report
}
