"""Compliance router — turns a scan's findings into an audit-ready compliance
report for one of the six supported frameworks (SOC 2, PCI-DSS, HIPAA, ISO 27001,
OWASP ASVS, NIST CSF). Maps findings to controls via CWE / OWASP category.

Wired to the product in Phase 2G so a real user can generate + download a report
from the dashboard (previously a repo-only CLI that crashed in the container).
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from compliance import report as compliance_report
from logging_config import get_logger

router = APIRouter(prefix="/report", tags=["compliance"])
log = get_logger("router.compliance")

# The six shipped frameworks (mapping YAMLs live in compliance/frameworks/).
FRAMEWORKS = {"soc2", "pci_dss", "hipaa", "iso27001", "owasp_asvs", "nist_csf"}


class ComplianceRequest(BaseModel):
    framework: str
    scan_meta: dict = {}
    findings: list[dict] = []
    # J3: findings that were open and are now proven fixed by a later scan. These
    # are evidence FOR a control and never count against it.
    remediated: list[dict] = []
    # False when the lifecycle store could not be read, so an empty list is
    # rendered as "history unavailable" rather than "nothing was ever fixed".
    remediation_available: bool = True


class ComplianceResponse(BaseModel):
    framework: str
    score_pct: int
    controls_needs_attention: int
    controls_in_scope: int
    # J1: score_pct is computed over ASSESSED controls, not all in-scope ones.
    # Controls we cannot evidence (runtime monitoring, change approval) are
    # excluded rather than counted as passes, so the denominator has to travel
    # with the score or a caller will show a percentage against the wrong total.
    controls_assessed: int = 0
    controls_not_assessed: int = 0
    findings_remediated: int = 0
    html: str
    error: str | None = None


@router.get("/compliance/frameworks")
async def list_frameworks() -> dict:
    """The frameworks a user can pick from (id + human label)."""
    labels = {
        "soc2": "SOC 2", "pci_dss": "PCI-DSS", "hipaa": "HIPAA",
        "iso27001": "ISO 27001", "owasp_asvs": "OWASP ASVS", "nist_csf": "NIST CSF",
    }
    return {"frameworks": [{"id": k, "label": labels[k]} for k in sorted(FRAMEWORKS)]}


@router.post("/compliance", response_model=ComplianceResponse)
async def generate(req: ComplianceRequest) -> ComplianceResponse:
    if req.framework not in FRAMEWORKS:
        return ComplianceResponse(
            framework=req.framework, score_pct=0, controls_needs_attention=0,
            controls_in_scope=0, html="", error=f"unknown framework '{req.framework}'",
        )
    try:
        fw = compliance_report.load_framework(req.framework)
        rep = compliance_report.build_report(
            req.scan_meta, req.findings, fw,
            remediated=req.remediated, remediation_available=req.remediation_available,
        )
        html = compliance_report.render_html(rep)
    except Exception as exc:  # noqa: BLE001 — report generation is best-effort
        log.exception("compliance.error", framework=req.framework)
        return ComplianceResponse(
            framework=req.framework, score_pct=0, controls_needs_attention=0,
            controls_in_scope=0, html="", error=str(exc),
        )
    s = rep["summary"]
    return ComplianceResponse(
        framework=req.framework,
        score_pct=s["compliance_score_pct"],
        controls_needs_attention=s["controls_needs_attention"],
        controls_in_scope=s["controls_in_scope"],
        controls_assessed=s["controls_assessed"],
        controls_not_assessed=s["controls_not_assessed"],
        findings_remediated=s["findings_remediated"],
        html=html,
    )
