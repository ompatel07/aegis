"""Rule management router — validate customer-supplied Semgrep rules + expose the
catalog of Aegis's bundled rules (consumed by the orchestrator's rule_registry)."""
from __future__ import annotations

import glob
import os
import shutil
import tempfile

import yaml
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from config import Settings, get_settings
from logging_config import get_logger
from utils.sandbox import binary_available, run_command

router = APIRouter(prefix="/rules", tags=["rules"])
log = get_logger("router.rules")

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


class CatalogRule(BaseModel):
    rule_id: str
    engine: str = "semgrep"
    category: str = ""
    severity: str = ""
    source_registry: str = "aegis-bundled"


@router.get("/catalog", response_model=list[CatalogRule])
async def catalog() -> list[CatalogRule]:
    """List Aegis's bundled Semgrep rules (id/category/severity) so the
    orchestrator can populate the rule_registry table. Metadata only — no
    customer code involved."""
    out: list[CatalogRule] = []
    for path in sorted(glob.glob(os.path.join(_RULES_DIR, "**", "*.yaml"), recursive=True)):
        try:
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError):
            continue
        pack = os.path.basename(os.path.dirname(path))  # e.g. taint | quality | iac
        for r in doc.get("rules", []):
            meta = r.get("metadata", {}) or {}
            out.append(CatalogRule(
                rule_id=str(r.get("id", "")),
                category=str(meta.get("category", pack)),
                severity=str(r.get("severity", "")),
                source_registry=f"aegis/{pack}",
            ))
    return out


class ValidateRequest(BaseModel):
    rule_yaml: str = Field(..., description="A Semgrep rule YAML document to validate.")


class ValidateResponse(BaseModel):
    valid: bool
    error: str | None = None
    rule_count: int = 0


@router.post("/validate", response_model=ValidateResponse)
async def validate_rule(req: ValidateRequest, settings: Settings = Depends(get_settings)) -> ValidateResponse:
    """Validate a Semgrep rule with `semgrep --validate` before it is stored."""
    if not binary_available(settings.semgrep_bin):
        return ValidateResponse(valid=False, error="semgrep binary not available")
    if not req.rule_yaml.strip():
        return ValidateResponse(valid=False, error="empty rule")

    workdir = tempfile.mkdtemp(prefix="aegis-validate-")
    path = os.path.join(workdir, "rule.yaml")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(req.rule_yaml)
        result = await run_command(
            [settings.semgrep_bin, "--validate", "--config", path, "--quiet",
             "--metrics", "off", "--disable-version-check"],
            timeout=90, allowed_returncodes=(0,),
        )
        if result.ok:
            # A crude but useful rule count: number of top-level "- id:" entries.
            count = req.rule_yaml.count("- id:") or req.rule_yaml.count("  - id:")
            return ValidateResponse(valid=True, rule_count=max(count, 1))
        detail = (result.stderr or result.stdout or "rule failed validation").strip()
        return ValidateResponse(valid=False, error=detail[:2000])
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
