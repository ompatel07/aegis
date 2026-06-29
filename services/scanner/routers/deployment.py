"""Deployment router — build verification + smoke testing."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from config import Settings, get_settings
from engines import deployment_engine
from logging_config import get_logger
from models.scan_request import DeploymentRequest
from models.scan_result import Engine, EngineResult, Pillar

router = APIRouter(prefix="/scan", tags=["deployment"])
log = get_logger("router.deployment")


@router.post("/deployment", response_model=EngineResult)
async def run_deployment(
    req: DeploymentRequest, settings: Settings = Depends(get_settings)
) -> EngineResult:
    log.info("deployment.start", scan_id=req.scan_id, path=req.path)
    try:
        result = await deployment_engine.run(req, settings)
    except Exception as exc:
        log.exception("deployment.error", scan_id=req.scan_id)
        return EngineResult.failed(Engine.DEPLOYMENT, Pillar.DEPLOYMENT, str(exc), scan_id=req.scan_id)
    log.info("deployment.done", scan_id=req.scan_id, status=result.status, findings=len(result.findings))
    return result
