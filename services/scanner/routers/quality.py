"""Quality router — complexity, duplication, maintainability, documentation."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from config import Settings, get_settings
from engines import quality_engine
from logging_config import get_logger
from models.scan_request import ScanRequest
from models.scan_result import Engine, EngineResult, Pillar

router = APIRouter(prefix="/scan", tags=["quality"])
log = get_logger("router.quality")


@router.post("/quality", response_model=EngineResult)
async def run_quality(req: ScanRequest, settings: Settings = Depends(get_settings)) -> EngineResult:
    log.info("quality.start", scan_id=req.scan_id, path=req.path)
    try:
        result = await quality_engine.run(req, settings)
    except Exception as exc:
        log.exception("quality.error", scan_id=req.scan_id)
        return EngineResult.failed(Engine.QUALITY, Pillar.QUALITY, str(exc), scan_id=req.scan_id)
    log.info("quality.done", scan_id=req.scan_id, status=result.status, findings=len(result.findings))
    return result
