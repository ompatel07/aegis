"""SBOM router (Phase 2E Task 3). Generates a Software Bill of Materials from a
checked-out repo using Trivy, in the two standard formats enterprises ask for:
CycloneDX and SPDX. The SBOM lists every resolved dependency with its version,
license, and known CVEs. Generated at scan time (the orchestrator calls this with
the authenticated checkout) and stored per-scan for download."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from config import Settings, get_settings
from logging_config import get_logger
from utils.sandbox import binary_available, run_command

router = APIRouter(prefix="/sbom", tags=["sbom"])
log = get_logger("router.sbom")

# Requested format -> Trivy --format value.
_FORMATS = {"cyclonedx": "cyclonedx", "spdx": "spdx-json"}


class SBOMRequest(BaseModel):
    path: str
    scan_id: str | None = None
    format: str = "cyclonedx"  # cyclonedx | spdx


class SBOMResponse(BaseModel):
    format: str
    content: str          # the SBOM document (JSON text)
    components: int        # number of components/packages catalogued
    error: str | None = None


def _count_components(fmt: str, doc: dict) -> int:
    if fmt == "cyclonedx":
        return len(doc.get("components") or [])
    return len(doc.get("packages") or [])  # spdx


@router.post("", response_model=SBOMResponse)
async def generate_sbom(req: SBOMRequest, settings: Settings = Depends(get_settings)) -> SBOMResponse:
    fmt = req.format.lower()
    trivy_format = _FORMATS.get(fmt)
    if not trivy_format:
        return SBOMResponse(format=fmt, content="", components=0, error="unsupported format")
    if not binary_available(settings.trivy_bin):
        return SBOMResponse(format=fmt, content="", components=0, error="trivy not available")

    args = [
        settings.trivy_bin, "fs",
        "--format", trivy_format,
        "--scanners", "vuln,license",   # embed CVEs + licenses in the SBOM
        "--quiet", "--no-progress",
        "--cache-dir", settings.trivy_cache_dir,
        req.path,
    ]
    result = await run_command(
        args, cwd=req.path, timeout=settings.trivy_timeout_seconds, allowed_returncodes=(0,),
    )
    if result.timed_out or not result.ok or not result.stdout.strip():
        detail = "sbom generation timed out" if result.timed_out else (result.stderr[:500] or "trivy produced no output")
        log.warning("sbom.failed", scan_id=req.scan_id, format=fmt, error=detail)
        return SBOMResponse(format=fmt, content="", components=0, error=detail)

    try:
        doc = json.loads(result.stdout)
        components = _count_components(fmt, doc)
    except json.JSONDecodeError:
        return SBOMResponse(format=fmt, content="", components=0, error="sbom output was not valid JSON")

    log.info("sbom.done", scan_id=req.scan_id, format=fmt, components=components)
    return SBOMResponse(format=fmt, content=result.stdout, components=components)
