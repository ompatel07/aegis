"""Rule management router — validate customer-supplied Semgrep rules."""
from __future__ import annotations

import os
import shutil
import tempfile

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from config import Settings, get_settings
from logging_config import get_logger
from utils.sandbox import binary_available, run_command

router = APIRouter(prefix="/rules", tags=["rules"])
log = get_logger("router.rules")


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
