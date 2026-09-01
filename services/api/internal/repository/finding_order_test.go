package repository

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/aegis-platform/api/internal/models"
)

// B1 parity (P4b): the Go SQL ordering and the web comparator
// (web/lib/findingOrder.ts) must agree, or page 2 shows a finding that belonged on
// page 1. This asserts the SQL-key order on the CANONICAL fixture matches the same
// order the TS test asserts (findingOrder.test.ts). Both reference one spec, so a
// drift on either side fails its own test.

func fp(v float64) *float64 { return &v }
func sp(v string) *string   { return &v }

func orderFinding(id, severity string, kev, reachable, isNew bool, fpProb float64) models.Finding {
	m := map[string]any{}
	if kev {
		m["kev"] = true
	}
	if reachable {
		m["reachable"] = true
	}
	raw, _ := json.Marshal(m)
	return models.Finding{
		RuleID: id, Severity: severity, IsNew: isNew,
		FalsePositiveProbability: fp(fpProb), Fingerprint: sp("f-" + id), Metadata: models.JSONB(raw),
	}
}

// sqlKey mirrors, field for field, the ORDER BY expressions in orderByFindings:
// kevFirstSQL, severityRankSQL, reachableFirstSQL, newFirstSQL, fp, fingerprint. It
// reads metadata the way `metadata->>'kev' = 'true'` does — from the raw JSON.
func sqlKey(f models.Finding) []int {
	b := func(v bool) int {
		if v {
			return 0
		}
		return 1
	}
	sevRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sr, ok := sevRank[f.Severity]
	if !ok {
		sr = 4
	}
	var meta map[string]any
	if len(f.Metadata) > 0 {
		_ = json.Unmarshal(f.Metadata, &meta)
	}
	kev := meta["kev"] == true
	reach := meta["reachable"] == true
	return []int{b(kev), sr, b(reach), b(f.IsNew)}
}

func TestFindingOrderMatchesCanonicalSpec(t *testing.T) {
	// Same fixture + expected order as web/lib/findingOrder.test.ts.
	fixture := []models.Finding{
		orderFinding("low", "low", false, false, false, 0),
		orderFinding("high-fp", "high", false, false, false, 0.9),
		orderFinding("kev-crit", "critical", true, false, false, 0),
		orderFinding("high", "high", false, false, false, 0),
		orderFinding("reach-crit", "critical", false, true, false, 0),
		orderFinding("high-new", "high", false, false, true, 0),
		orderFinding("crit", "critical", false, false, false, 0),
		orderFinding("reach-high", "high", false, true, false, 0),
	}
	want := []string{"kev-crit", "reach-crit", "crit", "reach-high", "high-new", "high", "high-fp", "low"}

	sort.SliceStable(fixture, func(i, j int) bool {
		ki, kj := sqlKey(fixture[i]), sqlKey(fixture[j])
		for x := range ki {
			if ki[x] != kj[x] {
				return ki[x] < kj[x]
			}
		}
		fi := *fixture[i].FalsePositiveProbability
		fj := *fixture[j].FalsePositiveProbability
		if fi != fj {
			return fi < fj
		}
		return *fixture[i].Fingerprint < *fixture[j].Fingerprint
	})

	got := make([]string, len(fixture))
	for i, f := range fixture {
		got[i] = f.RuleID
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order mismatch at %d: got %v, want %v", i, got, want)
		}
	}
}

// Structural guard: the single canonical ORDER BY keeps the four ranking keys in the
// exact tier sequence the comparator relies on. If someone reorders the SQL (e.g.
// drops reachable), this fails even before a data test would.
func TestOrderByRankingSequence(t *testing.T) {
	kev := strings.Index(orderByFindings, "metadata->>'kev'")
	sev := strings.Index(orderByFindings, "CASE severity")
	reach := strings.Index(orderByFindings, "metadata->>'reachable'")
	isNew := strings.Index(orderByFindings, "is_new")
	fpIdx := strings.Index(orderByFindings, "false_positive_probability")
	for _, p := range []int{kev, sev, reach, isNew, fpIdx} {
		if p < 0 {
			t.Fatalf("orderByFindings missing a ranking key: %q", orderByFindings)
		}
	}
	if !(kev < sev && sev < reach && reach < isNew && isNew < fpIdx) {
		t.Fatalf("ranking keys out of order in orderByFindings: kev=%d sev=%d reach=%d new=%d fp=%d", kev, sev, reach, isNew, fpIdx)
	}
}
