"""Compliance reports must express OPEN vs CLOSED (J3 Part A).

Om's framing, from working in compliance: an auditor does not verify every
guideline in a standard. What they consume is open versus closed — this
vulnerability appeared, it was remediated, and a later scan proves it closed.

Before J3 the compliance report could not express that at all. It received one
scan's findings, and a resolved finding is by definition absent from the current
scan, so the report only ever had the open half. It never said anything had been
fixed, and it carried no dates. All of the data existed in
`project_finding_states` — nothing connected it to the report.

These tests pin the three properties that make the report evidence rather than a
snapshot: remediated findings are attributed, they never count against a control,
and a missing history is never rendered as an empty one.
"""
from __future__ import annotations

import pytest

from compliance.report import build_report, load_framework, map_findings, render_html

CMDI = {
    "cwe_id": "CWE-78",
    "owasp_category": "A03:2021 - Injection",
    "severity": "critical",
    "title": "Request data flows into os.system",
    "file_path": "app/routes.py",
    "fingerprint": "b3b4622e15",
    "first_seen_at": "2026-08-12T09:00:00Z",
    "resolved_at": "2026-08-19T11:30:00Z",
    "resolved_scan_id": "e54c474b-1111-2222-3333-444455556666",
    "times_seen": 3,
}


def _soc2():
    return load_framework("soc2")


# ── the P0: a fixed vulnerability is evidence, not a failure ──────────────────

def test_a_remediated_finding_does_not_fail_its_control():
    """The whole point. If a weakness was fixed three scans ago, the control must
    not still read as failing today."""
    controls = {c.id: c for c in map_findings([], _soc2(), remediated=[CMDI])}
    cc66 = controls["CC6.6"]
    assert cc66.remediated, "the remediated finding was not attributed to a control"
    assert cc66.findings == [], "a fixed finding must not be counted as an open finding"
    assert cc66.open_count == 0
    assert cc66.status == "no-findings", f"a control with only fixed findings reads {cc66.status}"


def test_a_control_with_both_open_and_closed_findings_still_fails():
    """Remediation evidence does not offset an open finding — an auditor reads
    both halves, and closing one issue does not close another."""
    open_f = {"cwe_id": "CWE-89", "owasp_category": "A03:2021 - Injection",
              "severity": "high", "title": "SQLi", "file_path": "db.py"}
    controls = {c.id: c for c in map_findings([open_f], _soc2(), remediated=[CMDI])}
    cc66 = controls["CC6.6"]
    assert cc66.status == "needs-attention"
    assert cc66.open_count == 1
    assert len(cc66.remediated) == 1


def test_remediated_findings_are_counted_in_the_summary():
    rep = build_report({}, [], _soc2(), remediated=[CMDI])
    s = rep["summary"]
    assert s["findings_remediated"] == 1
    assert s["controls_with_remediation"] == 1


def test_remediation_is_attributed_by_the_same_precedence_rule_as_open_findings():
    """A remediated dependency CVE must land on the vulnerability-management
    control, not on secure coding — the same J1 rule, applied to the closed half."""
    cve = dict(CMDI, cwe_id="CWE-1321",
               owasp_category="A06:2021 - Vulnerable and Outdated Components",
               cve_id="CVE-2026-42044")
    controls = {c.id: c for c in map_findings([], _soc2(), remediated=[cve])}
    assert len(controls["CC7.1"].remediated) == 1
    assert controls["CC6.6"].remediated == []


# ── the report has to show the dates ──────────────────────────────────────────

def test_the_report_shows_when_a_finding_opened_and_when_it_closed():
    """An auditor asks 'when was this fixed, and what proves it'."""
    html_out = render_html(build_report({}, [], _soc2(), remediated=[CMDI]))
    assert "Remediation evidence" in html_out
    assert "2026-08-12" in html_out, "first-seen date missing"
    assert "2026-08-19" in html_out, "resolved date missing"
    assert "e54c474b" in html_out, "the scan that proved it closed is not cited"


def test_a_missing_history_is_not_rendered_as_nothing_was_fixed():
    """If the lifecycle store cannot be read, the report must say the history is
    unavailable. Showing an empty section would assert that nothing was ever
    fixed, which is a different and false claim."""
    html_out = render_html(build_report({}, [], _soc2(), remediated=[], remediation_available=False))
    assert "Remediation history unavailable" in html_out
    assert "not because nothing was fixed" in html_out


def test_no_remediation_yet_is_explained_rather_than_left_blank():
    html_out = render_html(build_report({}, [], _soc2(), remediated=[]))
    assert "No findings have been observed opening and then closing" in html_out


def test_disclaimer_states_that_status_reflects_open_findings_only():
    html_out = render_html(build_report({}, [], _soc2(), remediated=[CMDI]))
    assert "OPEN findings only" in html_out


# ── lifecycle state travels with open findings ────────────────────────────────

@pytest.mark.parametrize("status", ["new", "existing", "reopened"])
def test_open_findings_keep_their_lifecycle_status(status):
    """A reopened finding is a regression, and an auditor treats it differently
    from a first sighting. The status must survive into the report payload."""
    f = {"cwe_id": "CWE-89", "owasp_category": "A03:2021 - Injection",
         "severity": "high", "title": "SQLi", "file_path": "db.py",
         "lifecycle_status": status}
    controls = {c.id: c for c in map_findings([f], _soc2())}
    assert controls["CC6.6"].findings[0]["lifecycle_status"] == status


def test_backwards_compatible_when_no_remediation_is_supplied():
    """Older callers pass no remediated list at all; that must still work."""
    rep = build_report({}, [], _soc2())
    assert rep["summary"]["findings_remediated"] == 0
    assert rep["summary"]["remediation_available"] is True
