"""SCA router — Trivy dependency + IaC scanning."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from config import Settings, get_settings
from engines import trivy_engine
from logging_config import get_logger
from models.scan_request import ScanRequest
from models.scan_result import Engine, EngineResult, Pillar

router = APIRouter(prefix="/scan", tags=["sca"])
log = get_logger("router.sca")


@router.post("/sca", response_model=EngineResult)
async def run_sca(req: ScanRequest, settings: Settings = Depends(get_settings)) -> EngineResult:
    log.info("sca.start", scan_id=req.scan_id, path=req.path)
    try:
        result = await trivy_engine.run(req, settings)
    except Exception as exc:
        log.exception("sca.error", scan_id=req.scan_id)
        return EngineResult.failed(Engine.TRIVY, Pillar.SECURITY, str(exc), scan_id=req.scan_id)
    log.info("sca.done", scan_id=req.scan_id, status=result.status, findings=len(result.findings))
    return result
