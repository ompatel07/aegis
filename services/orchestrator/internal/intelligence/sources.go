package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Source is one vulnerability feed. Fetch returns normalized CVEs (already
// deduped by the source); the syncer upserts + retroactively rescans.
type Source interface {
	Name() string
	Interval() time.Duration
	Fetch(ctx context.Context) ([]CVE, SyncResult, error)
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

// osvEcosystem maps our detected ecosystem to OSV's ecosystem name.
var osvEcosystem = map[string]string{
	"python": "PyPI", "javascript": "npm", "go": "Go", "java": "Maven",
}

// ── NVD (recent CVEs; no key required, rate-limited) ──────────────────────────
type NVDSource struct {
	APIKey string
	// how far back to pull on each sync
	Window time.Duration
	// max pages (each 2000 records) to keep a sync bounded
	MaxPages int
}

func (s *NVDSource) Name() string            { return "nvd" }
func (s *NVDSource) Interval() time.Duration { return 24 * time.Hour }

func (s *NVDSource) Fetch(ctx context.Context) ([]CVE, SyncResult, error) {
	window := s.Window
	if window == 0 {
		window = 7 * 24 * time.Hour
	}
	maxPages := s.MaxPages
	if maxPages == 0 {
		maxPages = 1
	}
	start := time.Now().UTC().Add(-window)
	var all []CVE
	for page := 0; page < maxPages; page++ {
		q := url.Values{}
		q.Set("lastModStartDate", start.Format("2006-01-02T15:04:05.000"))
		q.Set("lastModEndDate", time.Now().UTC().Format("2006-01-02T15:04:05.000"))
		q.Set("resultsPerPage", "2000")
		q.Set("startIndex", strconv.Itoa(page*2000))
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
			"https://services.nvd.nist.gov/rest/json/cves/2.0?"+q.Encode(), nil)
		if s.APIKey != "" {
			req.Header.Set("apiKey", s.APIKey)
		}
		body, err := doGet(req)
		if err != nil {
			return all, SyncResult{Source: s.Name()}, err
		}
		cves, total := parseNVD(body)
		all = append(all, cves...)
		if (page+1)*2000 >= total || len(cves) == 0 {
			break
		}
		// NVD rate limit: 5 req / 30s without a key, 50/30s with one.
		sleep := 6500 * time.Millisecond
		if s.APIKey != "" {
			sleep = 700 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return all, SyncResult{Source: s.Name()}, ctx.Err()
		case <-time.After(sleep):
		}
	}
	return all, SyncResult{Source: s.Name()}, nil
}

func parseNVD(body []byte) ([]CVE, int) {
	var doc struct {
		TotalResults    int `json:"totalResults"`
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				LastModified string `json:"lastModified"`
				Descriptions []struct {
					Lang, Value string
				} `json:"descriptions"`
				Metrics struct {
					V31 []nvdMetric `json:"cvssMetricV31"`
					V30 []nvdMetric `json:"cvssMetricV30"`
				} `json:"metrics"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0
	}
	out := make([]CVE, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		c := CVE{CVEID: v.CVE.ID, Source: "nvd"}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				c.Description = d.Value
				break
			}
		}
		m := firstMetric(v.CVE.Metrics.V31, v.CVE.Metrics.V30)
		if m != nil {
			score := m.CVSSData.BaseScore
			c.CVSSScore = &score
			c.CVSSVector = m.CVSSData.VectorString
			c.Severity = strings.ToLower(m.CVSSData.BaseSeverity)
		}
		for _, r := range v.CVE.References {
			c.References = append(c.References, r.URL)
		}
		c.Published = parseTime(v.CVE.Published)
		c.Modified = parseTime(v.CVE.LastModified)
		out = append(out, c)
	}
	return out, doc.TotalResults
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

func firstMetric(a, b []nvdMetric) *nvdMetric {
	if len(a) > 0 {
		return &a[0]
	}
	if len(b) > 0 {
		return &b[0]
	}
	return nil
}

// ── OSV (package-precise; drives retroactive rescoring) ───────────────────────
type OSVSource struct {
	Store *Store
	Limit int
}

func (s *OSVSource) Name() string            { return "osv" }
func (s *OSVSource) Interval() time.Duration { return 6 * time.Hour }

func (s *OSVSource) Fetch(ctx context.Context) ([]CVE, SyncResult, error) {
	limit := s.Limit
	if limit == 0 {
		limit = 100
	}
	pkgs, err := s.Store.RecentPackages(ctx, limit)
	if err != nil {
		return nil, SyncResult{Source: s.Name()}, err
	}
	if len(pkgs) == 0 {
		return nil, SyncResult{Source: s.Name(), Skipped: true, Note: "no recent packages to query"}, nil
	}
	seen := map[string]bool{}
	var all []CVE
	for _, p := range pkgs {
		eco := osvEcosystem[p.Ecosystem]
		if eco == "" {
			continue // unknown ecosystem — can't query OSV precisely
		}
		cves, err := osvQuery(ctx, eco, p.Name)
		if err != nil {
			continue // one package failing shouldn't abort the whole sync
		}
		for _, c := range cves {
			if !seen[c.CVEID] {
				seen[c.CVEID] = true
				all = append(all, c)
			}
		}
	}
	return all, SyncResult{Source: s.Name()}, nil
}

func osvQuery(ctx context.Context, ecosystem, name string) ([]CVE, error) {
	payload, _ := json.Marshal(map[string]any{
		"package": map[string]string{"ecosystem": ecosystem, "name": name},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.osv.dev/v1/query", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	body, err := doGet(req)
	if err != nil {
		return nil, err
	}
	return parseOSV(body), nil
}

func parseOSV(body []byte) []CVE {
	var doc struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	out := make([]CVE, 0, len(doc.Vulns))
	for _, v := range doc.Vulns {
		out = append(out, v.toCVE())
	}
	return out
}

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Published string `json:"published"`
	Modified  string `json:"modified"`
}

func (v osvVuln) toCVE() CVE {
	c := CVE{CVEID: v.ID, Source: "osv"}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			c.CVEID = a // prefer the canonical CVE id
			break
		}
	}
	c.Description = v.Summary
	if c.Description == "" {
		c.Description = v.Details
	}
	for _, sev := range v.Severity {
		if strings.HasPrefix(sev.Type, "CVSS_V3") {
			c.CVSSVector = sev.Score
		}
	}
	for _, a := range v.Affected {
		fixed := ""
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f, ok := e["fixed"]; ok {
					fixed = f
				}
			}
		}
		c.Affected = append(c.Affected, AffectedPackage{
			Ecosystem: a.Package.Ecosystem, Name: a.Package.Name, Fixed: fixed,
		})
	}
	for _, r := range v.References {
		c.References = append(c.References, r.URL)
	}
	c.Published = parseTime(v.Published)
	c.Modified = parseTime(v.Modified)
	return c
}

// ── GHSA (token-gated) + Semgrep (best-effort) ────────────────────────────────
type GHSASource struct{ Token string }

func (s *GHSASource) Name() string            { return "ghsa" }
func (s *GHSASource) Interval() time.Duration { return 24 * time.Hour }

func (s *GHSASource) Fetch(ctx context.Context) ([]CVE, SyncResult, error) {
	if s.Token == "" {
		return nil, SyncResult{Source: s.Name(), Skipped: true,
			Note: "GHSA sync requires a GitHub token (GITHUB_TOKEN)"}, nil
	}
	// A minimal REST pull of recently-published, reviewed advisories.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/advisories?type=reviewed&per_page=100&sort=published&direction=desc", nil)
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	body, err := doGet(req)
	if err != nil {
		return nil, SyncResult{Source: s.Name()}, err
	}
	return parseGHSA(body), SyncResult{Source: s.Name()}, nil
}

func parseGHSA(body []byte) []CVE {
	var advisories []struct {
		GHSAID   string `json:"ghsa_id"`
		CVEID    string `json:"cve_id"`
		Summary  string `json:"summary"`
		Severity string `json:"severity"`
		CVSS     struct {
			Score  float64 `json:"score"`
			Vector string  `json:"vector_string"`
		} `json:"cvss"`
		Vulnerabilities []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			FirstPatchedVersion string `json:"first_patched_version"`
		} `json:"vulnerabilities"`
		Published string `json:"published_at"`
		Updated   string `json:"updated_at"`
	}
	if err := json.Unmarshal(body, &advisories); err != nil {
		return nil
	}
	out := make([]CVE, 0, len(advisories))
	for _, a := range advisories {
		id := a.CVEID
		if id == "" {
			id = a.GHSAID
		}
		c := CVE{CVEID: id, Description: a.Summary, Source: "ghsa",
			Severity: strings.ToLower(a.Severity), CVSSVector: a.CVSS.Vector}
		if a.CVSS.Score > 0 {
			score := a.CVSS.Score
			c.CVSSScore = &score
		}
		for _, v := range a.Vulnerabilities {
			c.Affected = append(c.Affected, AffectedPackage{
				Ecosystem: v.Package.Ecosystem, Name: v.Package.Name, Fixed: v.FirstPatchedVersion,
			})
		}
		c.Published = parseTime(a.Published)
		c.Modified = parseTime(a.Updated)
		out = append(out, c)
	}
	return out
}

// SemgrepSource is a best-effort weekly placeholder — real rule-pack refresh is
// handled by the scanner (Phase 2B TASK 3). It records a skipped sync so the
// status page shows the source without making a flaky external call.
type SemgrepSource struct{}

func (s *SemgrepSource) Name() string            { return "semgrep" }
func (s *SemgrepSource) Interval() time.Duration { return 7 * 24 * time.Hour }
func (s *SemgrepSource) Fetch(ctx context.Context) ([]CVE, SyncResult, error) {
	return nil, SyncResult{Source: s.Name(), Skipped: true,
		Note: "rule-pack refresh handled by the scanner"}, nil
}

// ── HTTP helper ───────────────────────────────────────────────────────────────
func doGet(req *http.Request) ([]byte, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s returned %d", req.URL.Host, resp.StatusCode)
	}
	return body, nil
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}
