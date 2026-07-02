package intelligence

import "testing"

func TestParseNVD(t *testing.T) {
	body := []byte(`{
	  "totalResults": 1,
	  "vulnerabilities": [{
	    "cve": {
	      "id": "CVE-2021-23337",
	      "published": "2021-02-15T11:15:12.463",
	      "lastModified": "2022-01-01T00:00:00.000",
	      "descriptions": [{"lang":"es","value":"..."},{"lang":"en","value":"Command injection in lodash."}],
	      "metrics": {"cvssMetricV31": [{"cvssData": {
	        "baseScore": 7.2, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "baseSeverity": "HIGH"}}]},
	      "references": [{"url":"https://example.com/a"}]
	    }
	  }]
	}`)
	cves, total := parseNVD(body)
	if total != 1 || len(cves) != 1 {
		t.Fatalf("got total=%d len=%d", total, len(cves))
	}
	c := cves[0]
	if c.CVEID != "CVE-2021-23337" || c.Source != "nvd" {
		t.Fatalf("bad id/source: %+v", c)
	}
	if c.Description != "Command injection in lodash." {
		t.Fatalf("english description not selected: %q", c.Description)
	}
	if c.CVSSScore == nil || *c.CVSSScore != 7.2 || c.Severity != "high" {
		t.Fatalf("bad cvss: %+v", c)
	}
	if c.CVSSVector == "" || c.Published == nil || c.Modified == nil {
		t.Fatalf("missing vector/dates: %+v", c)
	}
}

func TestParseOSVPrefersCVEAliasAndFixedVersion(t *testing.T) {
	body := []byte(`{"vulns":[{
	  "id":"GHSA-p6mc-m468-83gw",
	  "aliases":["CVE-2020-8203"],
	  "summary":"Prototype pollution in lodash",
	  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N"}],
	  "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
	              "ranges":[{"events":[{"introduced":"0"},{"fixed":"4.17.19"}]}]}],
	  "references":[{"url":"https://example.com/x"}],
	  "published":"2020-07-15T00:00:00Z","modified":"2021-01-01T00:00:00Z"
	}]}`)
	cves := parseOSV(body)
	if len(cves) != 1 {
		t.Fatalf("len=%d", len(cves))
	}
	c := cves[0]
	if c.CVEID != "CVE-2020-8203" {
		t.Fatalf("should prefer CVE alias, got %q", c.CVEID)
	}
	if c.Source != "osv" || c.CVSSVector == "" {
		t.Fatalf("bad source/vector: %+v", c)
	}
	if len(c.Affected) != 1 || c.Affected[0].Name != "lodash" || c.Affected[0].Fixed != "4.17.19" {
		t.Fatalf("bad affected: %+v", c.Affected)
	}
}

func TestParseGHSA(t *testing.T) {
	body := []byte(`[{
	  "ghsa_id":"GHSA-xxxx","cve_id":"CVE-2023-1000","summary":"SQLi in orm",
	  "severity":"critical","cvss":{"score":9.8,"vector_string":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	  "vulnerabilities":[{"package":{"ecosystem":"pip","name":"some-orm"},"first_patched_version":"2.0.1"}],
	  "published_at":"2023-05-01T00:00:00Z","updated_at":"2023-05-02T00:00:00Z"
	}]`)
	cves := parseGHSA(body)
	if len(cves) != 1 {
		t.Fatalf("len=%d", len(cves))
	}
	c := cves[0]
	if c.CVEID != "CVE-2023-1000" || c.Source != "ghsa" || c.Severity != "critical" {
		t.Fatalf("bad ghsa: %+v", c)
	}
	if c.CVSSScore == nil || *c.CVSSScore != 9.8 {
		t.Fatalf("bad score: %+v", c)
	}
	if len(c.Affected) != 1 || c.Affected[0].Name != "some-orm" || c.Affected[0].Fixed != "2.0.1" {
		t.Fatalf("bad affected: %+v", c.Affected)
	}
}

func TestPackageNamesDedupes(t *testing.T) {
	c := CVE{Affected: []AffectedPackage{{Name: "a"}, {Name: "a"}, {Name: "b"}, {Name: ""}}}
	got := packageNames(c)
	if len(got) != 2 {
		t.Fatalf("want 2 distinct names, got %v", got)
	}
}
