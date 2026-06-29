"""Secrets router — Gitleaks credential detection."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from config import Settings, get_settings
from engines import gitleaks_engine
from logging_config import get_logger
from models.scan_request import ScanRequest
from models.scan_result import Engine, EngineResult, Pillar

router = APIRouter(prefix="/scan", tags=["secrets"])
log = get_logger("router.secrets")


@router.post("/secrets", response_model=EngineResult)
async def run_secrets(req: ScanRequest, settings: Settings = Depends(get_settings)) -> EngineResult:
    log.info("secrets.start", scan_id=req.scan_id, path=req.path)
    try:
        result = await gitleaks_engine.run(req, settings)
    except Exception as exc:
        log.exception("secrets.error", scan_id=req.scan_id)
        return EngineResult.failed(Engine.GITLEAKS, Pillar.SECURITY, str(exc), scan_id=req.scan_id)
    log.info("secrets.done", scan_id=req.scan_id, status=result.status, findings=len(result.findings))
    return result
