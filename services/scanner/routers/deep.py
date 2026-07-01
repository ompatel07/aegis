"""Deep-scan router — interprocedural, cross-file taint analysis.

Joern (Apache-2.0) is the bundled default; CodeQL is an opt-in slot that only
runs where the customer has installed the CLI. Both share this one endpoint and
return the standard EngineResult. When a backend's tool is absent the engine
returns status=skipped (not failed), so the orchestrator records a degraded/
skipped deep scan without failing the overall scan.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from config import Settings, get_settings
from engines import codeql_engine, joern_engine
from logging_config import get_logger
from models.scan_request import DeepScanRequest
from models.scan_result import Engine, EngineResult, Pillar

router = APIRouter(prefix="/scan", tags=["deep"])
log = get_logger("router.deep")

_ENGINES = {
    "joern": (joern_engine, Engine.JOERN),
    "codeql": (codeql_engine, Engine.CODEQL),
}


@router.post("/deep", response_model=EngineResult)
async def run_deep(req: DeepScanRequest, settings: Settings = Depends(get_settings)) -> EngineResult:
    engine_mod, engine_enum = _ENGINES[req.engine]
    log.info("deep.start", scan_id=req.scan_id, engine=req.engine, path=req.path)
    try:
        result = await engine_mod.run(req, settings)
    except Exception as exc:  # never let the deep engine crash the request
        log.exception("deep.error", scan_id=req.scan_id, engine=req.engine)
        return EngineResult.failed(engine_enum, Pillar.SECURITY, str(exc), scan_id=req.scan_id)
    log.info(
        "deep.done", scan_id=req.scan_id, engine=req.engine,
        status=result.status.value, findings=len(result.findings),
    )
    return result
