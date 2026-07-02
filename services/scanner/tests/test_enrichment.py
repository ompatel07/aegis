"""Tests for context-rich finding enrichment.

Every finding must come out with non-empty title_human / impact /
remediation_action / risk_level / estimated_effort — from a template where one
exists, else from the finding's own metadata (never empty). Engine-specific
enrichment (CVSS breakdown, quality numbers, image size) is asserted too.
"""
from __future__ import annotations

from enrichment import enricher
from models.scan_result import Engine, Finding, Pillar, Severity


def mk(**kw) -> Finding:
    base = dict(
        pillar=Pillar.SECURITY, engine=Engine.SEMGREP, rule_id="x", rule_name="x",
        severity=Severity.HIGH, title="t", file_path="f",
    )
    base.update(kw)
    return Finding(**base)


def _all_populated(f: Finding) -> None:
    assert f.title_human, "title_human empty"
    assert f.impact, "impact empty"
    assert f.remediation_action, "remediation_action empty"
    assert f.risk_level, "risk_level empty"
    assert f.estimated_effort, "estimated_effort empty"


def test_trivy_cve_cvss_breakdown():
    f = mk(
        engine=Engine.TRIVY, rule_id="CVE-2019-1010083", cve_id="CVE-2019-1010083",
        severity=Severity.HIGH,
        metadata={
            "package": "flask", "installed_version": "0.12.0", "fixed_version": "1.0",
            "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        },
    )
    enricher.enrich_all([f])
    _all_populated(f)
    assert "flask" in f.title_human
    assert "CVE-2019-1010083" in f.impact
    assert "flask" in f.remediation_action
    assert f.estimated_effort == "quick"
    cm = f.context_metadata
    assert cm["attack_vector"] == "Network"
    assert cm["attack_complexity"] == "Low"
    assert cm["user_interaction"] == "None"
    assert cm["availability_impact"] == "High"
    assert cm["confidentiality_impact"] == "None"


def test_quality_complexity_number_in_impact():
    f = mk(
        engine=Engine.QUALITY, rule_id="quality/high-cyclomatic-complexity",
        severity=Severity.MEDIUM, metadata={"complexity": 42, "nloc": 120},
    )
    enricher.enrich_all([f])
    _all_populated(f)
    assert "42" in f.impact
    assert f.title_human == "Function is too complex"
    assert f.estimated_effort == "significant"


def test_quality_duplication_numbers():
    f = mk(
        engine=Engine.QUALITY, rule_id="quality/duplicated-code", severity=Severity.MEDIUM,
        metadata={"clone_lines": 21, "occurrences": 4},
    )
    enricher.enrich_all([f])
    assert "21" in f.impact and "4" in f.impact


def test_gitleaks_aws_template():
    f = mk(engine=Engine.GITLEAKS, rule_id="aws-access-token", severity=Severity.HIGH)
    enricher.enrich_all([f])
    _all_populated(f)
    assert "AWS access key" in f.title_human
    assert f.risk_level == "critical"
    assert "IAM" in f.remediation_action


def test_gitleaks_unknown_rule_falls_back_to_default():
    f = mk(engine=Engine.GITLEAKS, rule_id="some-obscure-token", severity=Severity.HIGH)
    enricher.enrich_all([f])
    _all_populated(f)
    assert "secret" in f.title_human.lower()


def test_custom_taint_rule():
    f = mk(engine=Engine.SEMGREP, rule_id="aegis-js-sql-injection", severity=Severity.CRITICAL, cwe_id="CWE-89")
    enricher.enrich_all([f])
    _all_populated(f)
    assert f.title_human == "SQL injection"
    assert f.risk_level == "critical"
    assert "parameterized" in f.remediation_action.lower()


def test_joern_deep_reuses_taint_template():
    f = mk(engine=Engine.JOERN, rule_id="joern/sql-injection", severity=Severity.CRITICAL)
    enricher.enrich_all([f])
    assert f.title_human == "SQL injection"


def test_registry_rule_falls_back_to_metadata_never_empty():
    f = mk(
        engine=Engine.SEMGREP, rule_id="javascript.express.security.audit.xss.direct-response-write",
        rule_name="Express direct response write (XSS)", severity=Severity.HIGH, cwe_id="CWE-79",
        description="User input is written to the response without escaping, enabling XSS.",
        fix_suggestion="Escape output or use a templating engine with autoescaping.",
    )
    enricher.enrich_all([f])
    _all_populated(f)
    assert f.title_human == "Express direct response write (XSS)"
    assert "XSS" in f.impact or "escaping" in f.impact.lower()
    assert f.risk_level == "high"


def test_docker_base_image_reduction():
    f = mk(
        engine=Engine.DEPLOYMENT, pillar=Pillar.DEPLOYMENT, rule_id="docker:base-image",
        severity=Severity.LOW,
        metadata={"base_image": "node:20", "current_mb": 1100, "recommended_base": "node:20-slim", "reduction_pct": 78},
    )
    enricher.enrich_all([f])
    _all_populated(f)
    assert "78%" in f.impact
    assert "node:20-slim" in f.remediation_action
