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


# ── J2: structural guards ─────────────────────────────────────────────────────
# These two tests exist because both defect classes came back after being fixed
# once. A corrected compliance defect must not be able to return quietly.

def _repo_root() -> str | None:
    """Walk up to the git checkout. Returns None inside the scanner image, where
    services/scanner is mounted as / and there is no repository to inspect."""
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        if os.path.isdir(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def test_only_one_framework_tree_exists_in_the_repository():
    """J2 Part A. Two copies of the framework mappings existed: the loaded one
    under services/scanner/compliance/frameworks/, and a stale duplicate at the
    repository root with its own README. Only the loaded copy was fixed, so the
    root copy still carried the wrong HIPAA control title, CC6.3's over-broad
    CWE-732 and CC8.1's wrong title -- and it is the copy someone browsing the
    repository finds first.

    A second tree must not be able to reappear unnoticed."""
    root = _repo_root()
    if root is None:
        pytest.skip("not a git checkout (running inside the scanner image)")
    found = []
    skip = {".git", "node_modules", ".venv", "__pycache__", ".next", "dist", "build"}
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip]
        if os.path.basename(dirpath) != "frameworks":
            continue
        if any(f.endswith((".yaml", ".yml")) for f in files):
            found.append(os.path.relpath(dirpath, root))
    assert len(found) == 1, (
        f"expected exactly one framework tree, found {len(found)}: {found}. "
        f"A duplicate diverges silently -- the copy that is not loaded keeps its defects."
    )
    assert found[0].replace(os.sep, "/").endswith("services/scanner/compliance/frameworks")


def _emittable() -> tuple[set[str], set[str]]:
    path = FRAMEWORK_DIR.parent / "emittable_identifiers.yaml"
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    cwe = {c.upper() for c in doc["declared"]["cwe"]} | {c.upper() for c in doc["observed"]["cwe"]}
    ow = set(doc["declared"]["owasp"]) | set(doc["observed"]["owasp"])
    return cwe, ow


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_every_evidence_identifier_is_one_an_engine_can_emit(name):
    """J2 Part B. An evidence rule that can never fire makes a control read
    "no findings" when the truth is "never checked". J1 found CWE-937 and
    CWE-1035 mapped in six frameworks and emitted by nothing; the full audit
    found 36 such entries.

    Every identifier must appear in the emittable inventory -- either declared in
    a rule we ship, or observed on a real finding."""
    live_cwe, live_ow = _emittable()
    fw = load_framework(name)
    dead = []
    for ctrl in fw.get("controls", []):
        if ctrl.get("aegis_scope") in ("out-of-scope", "not-assessed"):
            continue
        ev = ctrl.get("evidence") or {}
        for c in ev.get("cwe", []):
            if c.upper() not in live_cwe:
                dead.append((ctrl["id"], c))
        for o in ev.get("owasp", []):
            if o not in live_ow:
                dead.append((ctrl["id"], o))
    assert not dead, (
        f"{name}: these evidence entries reference identifiers no engine can emit, so the "
        f"control would report 'no findings' without ever being checkable: {dead}. "
        f"Remove them, or add the detector and refresh the inventory with "
        f"scripts/refresh_emittable_identifiers.py."
    )


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_every_assessable_control_has_at_least_one_emittable_identifier(name):
    """The consequence of the test above, at control granularity: a control whose
    evidence is entirely un-emittable must be not-assessed, not scored."""
    live_cwe, live_ow = _emittable()
    fw = load_framework(name)
    for ctrl in fw.get("controls", []):
        if ctrl.get("aegis_scope") in ("out-of-scope", "not-assessed"):
            continue
        ev = ctrl.get("evidence") or {}
        usable = [c for c in ev.get("cwe", []) if c.upper() in live_cwe]
        usable += [o for o in ev.get("owasp", []) if o in live_ow]
        assert usable, (
            f"{name}: {ctrl['id']} is scored but no engine can produce any of its evidence. "
            f"Mark it aegis_scope: not-assessed instead of letting it read 'no findings'."
        )


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_pillars_are_real_pillars(name):
    valid = {"security", "quality", "deployment"}
    fw = load_framework(name)
    for ctrl in fw.get("controls", []):
        for p in (ctrl.get("evidence") or {}).get("pillars", []):
            assert p in valid, f"{name}: {ctrl['id']} references unknown pillar {p!r}"


# ── J2 Part C: scope must be declared, and must reach the report ──────────────

HEADLINE = {"soc2", "owasp_asvs"}


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_every_framework_declares_its_scope(name):
    """A framework where we assess 7 of ~300 sub-requirements must say so in the
    mapping, not only in a document a reader may never open."""
    fw = load_framework(name)
    sc = fw.get("scope") or {}
    assert sc.get("standard_total"), f"{name}: no standard_total declared"
    assert sc.get("claim") in ("headline", "supporting-evidence"), f"{name}: {sc.get('claim')!r}"
    assert sc.get("verification") in ("normative-text", "numbering-and-titles"), name
    assert sc.get("note"), f"{name}: no scope note"


def test_only_asvs_and_soc2_are_headline_claims():
    """Everything else is labelled supporting evidence. If this changes, it should
    be a deliberate decision, not a drift."""
    actual = {n for n in FRAMEWORKS if (load_framework(n).get("scope") or {}).get("claim") == "headline"}
    assert actual == HEADLINE, f"headline claims drifted: {actual}"


@pytest.mark.parametrize("name", sorted(set(FRAMEWORKS) - HEADLINE))
def test_supporting_frameworks_say_so_on_the_report_itself(name):
    """The scope caveat has to be on the artifact. A caveat that lives only in a
    doc is not attached to the thing someone forwards to an auditor."""
    from compliance.report import render_html
    fw = load_framework(name)
    html_out = render_html(build_report({}, [], fw))
    assert "SUPPORTING EVIDENCE ONLY" in html_out, f"{name}: report does not carry its scope caveat"
    assert str((fw.get("scope") or {})["standard_total"]) in html_out


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_paywalled_verification_is_disclosed_on_the_report(name):
    """Where we could not read the normative text, the report must say so rather
    than implying the mapping was checked against the standard itself."""
    from compliance.report import render_html
    fw = load_framework(name)
    if (fw.get("scope") or {}).get("verification") != "numbering-and-titles":
        pytest.skip("verified against normative text")
    html_out = render_html(build_report({}, [], fw))
    assert "was NOT read" in html_out
