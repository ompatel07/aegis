"""SAST router — Semgrep-powered static analysis."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from config import Settings, get_settings
from engines import semgrep_engine
from logging_config import get_logger
from models.scan_request import ScanRequest
from models.scan_result import Engine, EngineResult, Pillar

router = APIRouter(prefix="/scan", tags=["sast"])
log = get_logger("router.sast")


@router.post("/sast", response_model=EngineResult)
async def run_sast(req: ScanRequest, settings: Settings = Depends(get_settings)) -> EngineResult:
    log.info("sast.start", scan_id=req.scan_id, path=req.path)
    try:
        result = await semgrep_engine.run(req, settings)
    except Exception as exc:  # never let one engine crash the fan-out
        log.exception("sast.error", scan_id=req.scan_id)
        return EngineResult.failed(Engine.SEMGREP, Pillar.SECURITY, str(exc), scan_id=req.scan_id)
    log.info("sast.done", scan_id=req.scan_id, status=result.status, findings=len(result.findings))
    return result
