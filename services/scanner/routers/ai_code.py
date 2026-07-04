"""AI-code router — scores a repository for AI-generated code (Phase 2C TASK 3a)."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from config import Settings, get_settings
from engines import ai_code_engine
from logging_config import get_logger
from models.scan_request import ScanRequest
from models.scan_result import AICodeResult, EngineStatus

router = APIRouter(prefix="/scan", tags=["ai-code"])
log = get_logger("router.ai_code")


@router.post("/ai-code", response_model=AICodeResult)
async def run_ai_code(req: ScanRequest, settings: Settings = Depends(get_settings)) -> AICodeResult:
    log.info("ai_code.start", scan_id=req.scan_id, path=req.path)
    try:
        result = ai_code_engine.run(req, settings)
    except Exception as exc:  # never let this pass crash the scan
        log.exception("ai_code.router_error", scan_id=req.scan_id)
        return AICodeResult(status=EngineStatus.FAILED, error=str(exc), scan_id=req.scan_id)
    log.info("ai_code.done", scan_id=req.scan_id, files=result.files_scored, ai=result.ai_file_count)
    return result
