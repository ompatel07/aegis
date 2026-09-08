"""Compliance mapping-accuracy tests (J1 Part B).

F1 sampled ten SOC 2 control mappings and found two defects. J1 audited all six
frameworks we ship and found the same two classes throughout, plus one outright
wrong control. The tests here pin the invariants that stop them recurring:

* **Single attribution.** One finding must fail at most one control. Before J1 a
  finding was attributed to *every* control whose evidence matched, so a single
  dependency CVE failed both SOC 2 CC6.8 and CC7.1 — 1,975 double-attributions
  across our 14,041-finding corpus, and 1,942 more on PCI 6.3.1/6.3.3. That
  inflates the failure count, the evidence list and the remediation timeline at
  once.
* **Mutually exclusive evidence.** No CWE or OWASP category may be claimed by two
  assessable controls in the same framework. This is what makes single
  attribution a property of the mapping rather than of the code that reads it.
* **Honest not-assessed.** A control we cannot evidence must be excluded from the
  score, not counted as a pass.
"""
from __future__ import annotations

import glob
import os

import pytest
import yaml

from compliance.report import (
    FRAMEWORK_DIR,
    attribution_conflicts,
    build_report,
    load_framework,
    map_findings,
)

FRAMEWORKS = sorted(
    os.path.splitext(os.path.basename(p))[0] for p in glob.glob(str(FRAMEWORK_DIR / "*.yaml"))
)


def test_we_ship_the_frameworks_we_think_we_do():
    assert set(FRAMEWORKS) == {"hipaa", "iso27001", "nist_csf", "owasp_asvs", "pci_dss", "soc2"}


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_no_evidence_key_is_claimed_by_two_controls(name):
    """The mapping-level guarantee behind single attribution."""
    conflicts = attribution_conflicts(load_framework(name))
    assert conflicts == {}, (
        f"{name}: these evidence keys are claimed by more than one assessable control, "
        f"so one finding would fail several: {conflicts}"
    )


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_a_finding_never_fails_two_controls(name):
    """The behavioural guarantee, exercised over one finding per evidence key in
    the framework — including findings that carry a CWE and an OWASP category
    pointing at different controls, which is how the residual double-counting
    survived the mapping fix."""
    fw = load_framework(name)
    findings = []
    for ctrl in fw.get("controls", []):
        ev = ctrl.get("evidence") or {}
        for cwe in ev.get("cwe", []):
            findings.append({"cwe_id": cwe, "owasp_category": "A06:2021 - Vulnerable and Outdated Components"})
        for ow in ev.get("owasp", []):
            findings.append({"cwe_id": "CWE-89", "owasp_category": ow})
    results = map_findings(findings, fw)
    counts: dict[int, int] = {}
    for cr in results:
        for f in cr.findings:
            counts[id(f)] = counts.get(id(f), 0) + 1
    duplicated = [k for k, v in counts.items() if v > 1]
    assert not duplicated, f"{name}: {len(duplicated)} findings were attributed to more than one control"


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_not_assessed_controls_are_declared_and_explained(name):
    """A control we cannot evidence has to say why. An unexplained gap in an
    audit document is worse than a stated one."""
    fw = load_framework(name)
    for ctrl in fw.get("controls", []):
        if ctrl.get("aegis_scope") == "not-assessed":
            reason = str(ctrl.get("not_assessed_reason") or "").strip()
            assert reason, f"{name}: {ctrl['id']} is not-assessed but gives no reason"
            assert not ctrl.get("evidence"), (
                f"{name}: {ctrl['id']} is not-assessed but still carries evidence keys"
            )


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_not_assessed_controls_are_excluded_from_the_score(name):
    """They must not be silently counted as passes — that is how an automated
    report overstates assurance."""
    fw = load_framework(name)
    report = build_report({}, [], fw)
    s = report["summary"]
    assert s["controls_assessed"] + s["controls_not_assessed"] == s["controls_in_scope"]
    # With no findings at all, every *assessed* control has no findings, so the
    # score is 100% over the assessed set and the not-assessed ones sit outside.
    assert s["compliance_score_pct"] == 100
    assert s["controls_no_findings"] == s["controls_assessed"]


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_every_control_is_either_evidenced_or_explicitly_scoped(name):
    """No control may sit in the framework with neither evidence nor a scope
    marker: that shape reports as passing while checking nothing."""
    fw = load_framework(name)
    for ctrl in fw.get("controls", []):
        scoped = ctrl.get("aegis_scope") in ("out-of-scope", "not-assessed")
        assert scoped or (ctrl.get("evidence") or {}).get("cwe") or (ctrl.get("evidence") or {}).get("owasp"), (
            f"{name}: {ctrl['id']} has no evidence and no scope marker"
        )


# ── regressions for the specific defects found in F1 and J1 ───────────────────

def test_soc2_cc6_3_no_longer_pulls_in_container_hardening():
    """F1 defect 1: CWE-732 fires on filesystem/container permissions, so it
    dragged container-hardening findings into a role-based-access criterion."""
    fw = load_framework("soc2")
    cc63 = next(c for c in fw["controls"] if c["id"] == "CC6.3")
    assert "CWE-732" not in (cc63.get("evidence") or {}).get("cwe", [])


def test_soc2_dependency_cves_fail_vulnerability_detection_not_malicious_software():
    """F1 defect 2: CC6.8 and CC7.1 both claimed A06:2021, so every dependency
    CVE failed both. CC6.8 is about unauthorized or malicious software; a
    known-vulnerable dependency is CC7.1's subject."""
    fw = load_framework("soc2")
    cc68 = next(c for c in fw["controls"] if c["id"] == "CC6.8")
    cc71 = next(c for c in fw["controls"] if c["id"] == "CC7.1")
    assert "A06:2021" not in (cc68.get("evidence") or {}).get("owasp", [])
    assert "A06:2021" in (cc71.get("evidence") or {}).get("owasp", [])

    cve = {"cwe_id": "CWE-1321", "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
           "cve_id": "CVE-2026-42044"}
    results = {c.id: c for c in map_findings([cve], fw)}
    assert len(results["CC7.1"].findings) == 1, "a dependency CVE should evidence vulnerability detection"
    assert results["CC6.6"].findings == [], (
        "a dependency CVE must not be charged to the customer's secure-coding control "
        "just because the upstream bug has a CWE"
    )


def test_hipaa_encryption_specification_is_not_an_ssrf_control():
    """J1 defect: 164.312(e)(2)(ii) was named 'Guard against unauthorized access
    during transmission' and fed SSRF/open-redirect findings. Checked against
    45 CFR 164.312, that paragraph is 'Encryption'."""
    fw = load_framework("hipaa")
    ids = {c["id"] for c in fw["controls"]}
    assert "164.312(e)(2)(ii)" not in ids, (
        "the mis-titled encryption sub-specification is still present as a scored control"
    )
    for ctrl in fw["controls"]:
        cwes = (ctrl.get("evidence") or {}).get("cwe", [])
        if "CWE-918" in cwes:
            assert ctrl["id"] == "164.312(c)(1)", (
                f"SSRF is attributed to {ctrl['id']}; it belongs to Integrity, not an encryption control"
            )


def test_soc2_change_management_is_not_evidenced_by_hardcoded_secrets():
    """J1 defect: CC8.1 (change management) was fed hard-coded-credential CWEs.
    A secret in source is an authentication weakness, not a change-control one."""
    fw = load_framework("soc2")
    cc81 = next(c for c in fw["controls"] if c["id"] == "CC8.1")
    assert cc81.get("aegis_scope") == "not-assessed"
    cc62 = next(c for c in fw["controls"] if c["id"] == "CC6.2")
    assert "CWE-798" in (cc62.get("evidence") or {}).get("cwe", [])


def test_framework_yaml_is_parseable_and_titled():
    for name in FRAMEWORKS:
        with open(FRAMEWORK_DIR / f"{name}.yaml", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        assert doc.get("framework") and doc.get("version") and doc.get("authority")
        assert doc.get("controls"), name
