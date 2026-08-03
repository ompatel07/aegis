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


class ComplianceResponse(BaseModel):
    framework: str
    score_pct: int
    controls_needs_attention: int
    controls_in_scope: int
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
        rep = compliance_report.build_report(req.scan_meta, req.findings, fw)
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
        html=html,
    )
