"""Rule management router — validate customer-supplied Semgrep rules + expose the
catalog of Aegis's bundled rules (consumed by the orchestrator's rule_registry)."""
from __future__ import annotations

import glob
import json
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
        for r in doc.get("rules", []) if isinstance(doc, dict) else []:
            meta = r.get("metadata", {}) or {}
            # rules/vendor/ holds third-party packs (only njsscan since N1); name the
            # real source and licence instead of claiming them as Aegis rules.
            source = (f"{os.path.splitext(os.path.basename(path))[0]} ({meta.get('license', 'unknown licence')})"
                      if pack == "vendor" else f"aegis/{pack}")
            out.append(CatalogRule(
                rule_id=str(r.get("id", "")),
                category=str(meta.get("category", pack)),
                severity=str(r.get("severity", "")),
                source_registry=source,
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
    """Validate a Semgrep rule before it is stored -- fully offline.

    This used to run `semgrep --validate`, which downloads `p/semgrep-rule-lints`
    from the Semgrep registry and runs those (Semgrep-licensed) lint rules over the
    customer's rule (semgrep core_runner.validate_configs). Measured in N1 with the
    network disabled, it rejected even a correct rule: validation depended on
    semgrep.dev being reachable.

    Instead the rule is loaded by `semgrep scan` against an empty directory. Loading
    parses and schema-checks every rule and compiles every pattern, so the same
    defects are caught (missing pattern/languages -> rc 7, unparseable pattern ->
    rc 2, unknown language -> rc 8) with no network and no third-party rules.
    """
    if not binary_available(settings.semgrep_bin):
        return ValidateResponse(valid=False, error="semgrep binary not available")
    if not req.rule_yaml.strip():
        return ValidateResponse(valid=False, error="empty rule")

    workdir = tempfile.mkdtemp(prefix="aegis-validate-")
    path = os.path.join(workdir, "rule.yaml")
    target = os.path.join(workdir, "empty")
    try:
        os.mkdir(target)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(req.rule_yaml)
        result = await run_command(
            [settings.semgrep_bin, "scan", "--config", path, "--json", "--quiet",
             "--metrics", "off", "--disable-version-check", target],
            timeout=90, allowed_returncodes=(0, 1, 2, 3, 4, 5, 6, 7, 8),
        )
        errors: list[str] = []
        try:
            out = json.loads(result.stdout) if result.stdout.strip() else {}
            errors = [str(e.get("message") or e.get("type") or e) for e in out.get("errors") or []]
        except json.JSONDecodeError:
            pass
        if result.returncode == 0 and not errors:
            try:
                count = len((yaml.safe_load(req.rule_yaml) or {}).get("rules") or [])
            except yaml.YAMLError:
                count = 0
            return ValidateResponse(valid=True, rule_count=max(count, 1))
        detail = "; ".join(errors) or (result.stderr or result.stdout or "rule failed validation")
        return ValidateResponse(valid=False, error=detail.strip()[:2000])
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
