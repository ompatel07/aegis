package pipeline

import (
	"strings"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// deepDedupeLineWindow is how close (in line number) a deep finding and a fast
// finding must be, given the same CWE + file, to be considered the same issue.
const deepDedupeLineWindow = 2

// MergeDeep folds the deep-scan result into the fast-scan results, deduplicating
// so the same vulnerability is not double-reported. When a deep (Joern/CodeQL)
// finding matches a fast (Semgrep) finding on (CWE, file, ~line), the fast
// finding is dropped and the deep finding is annotated as corroborated — we keep
// the richer one (it carries the interprocedural dataflow path). The deep result
// is always appended (even when skipped/empty) so the scan record reflects it.
func MergeDeep(results []*types.EngineResult, deep *types.EngineResult) []*types.EngineResult {
	if deep == nil {
		return results
	}
	if len(deep.Findings) > 0 {
		dedupeAgainstFast(results, deep)
	}
	return append(results, deep)
}

func dedupeAgainstFast(results []*types.EngineResult, deep *types.EngineResult) {
	for _, r := range results {
		if r == nil || r.Pillar != types.PillarSecurity || len(r.Findings) == 0 {
			continue
		}
		kept := r.Findings[:0]
		for _, f := range r.Findings {
			if di := matchingDeep(deep.Findings, f); di >= 0 {
				markCorroborated(&deep.Findings[di], f.Engine)
				continue // drop the fast duplicate
			}
			kept = append(kept, f)
		}
		r.Findings = kept
	}
}

// matchingDeep returns the index of a deep finding that represents the same
// issue as the fast finding `f`, or -1. Requires a non-empty CWE on both sides
// so unrelated findings that both lack a CWE never collapse together.
func matchingDeep(deep []types.Finding, f types.Finding) int {
	cwe := strings.ToUpper(strings.TrimSpace(f.CWEID))
	if cwe == "" || f.FilePath == "" {
		return -1
	}
	for i := range deep {
		d := deep[i]
		if strings.ToUpper(strings.TrimSpace(d.CWEID)) != cwe || d.FilePath != f.FilePath {
			continue
		}
		if within(d.LineStart, f.LineStart, deepDedupeLineWindow) {
			return i
		}
	}
	return -1
}

func within(a, b *int, window int) bool {
	if a == nil || b == nil {
		return true // location unknown on one side — treat CWE+file match as enough
	}
	d := *a - *b
	if d < 0 {
		d = -d
	}
	return d <= window
}

func markCorroborated(d *types.Finding, engine string) {
	if d.Metadata == nil {
		d.Metadata = map[string]any{}
	}
	existing, _ := d.Metadata["corroborated_by"].([]string)
	for _, e := range existing {
		if e == engine {
			return
		}
	}
	d.Metadata["corroborated_by"] = append(existing, engine)
}
