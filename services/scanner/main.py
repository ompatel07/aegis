"""Aegis scanner service — FastAPI entrypoint.

Stateless analysis engine. Exposes one endpoint per pillar/tool plus a health
check that reports which underlying binaries are available.
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from config import get_settings
from engines import gitleaks_engine, quality_engine, semgrep_engine, trivy_engine
from logging_config import configure_logging, get_logger
from routers import compliance, deep, deployment, quality, rules, sast, sbom, sca, secrets
from utils.sandbox import binary_available

settings = get_settings()
configure_logging(settings.log_level, settings.environment)
log = get_logger("scanner")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure tool cache directories exist so semgrep/trivy can write to them.
    for path in (settings.semgrep_rules_cache, settings.trivy_cache_dir):
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as exc:
            log.warning("cache.mkdir_failed", path=path, error=str(exc))

    tools = _tool_status()
    missing = [name for name, ok in tools.items() if not ok]
    if missing:
        log.warning("startup.tools_missing", missing=missing)
    log.info("startup", environment=settings.environment, tools=tools)

    # Load (or seed-train) the false-positive classifier so findings get scored.
    try:
        from ml import classifier

        await asyncio.get_event_loop().run_in_executor(None, classifier.ensure_model)
    except Exception as exc:  # noqa: BLE001 — ML is best-effort, never fatal
        log.warning("startup.ml_model_unavailable", error=str(exc))

    # Keep rule packs / vuln DBs fresh in the background (on boot + every 6h).
    refresh_task = asyncio.create_task(_rulepack_refresh_loop())
    yield
    refresh_task.cancel()
    log.info("shutdown")


async def _rulepack_refresh_loop() -> None:
    """Refresh the Trivy vuln DB periodically so scans use current advisories.
    Semgrep registry rules are cached and re-fetched by semgrep itself."""
    from utils.sandbox import run_command

    while True:
        try:
            if binary_available(settings.trivy_bin):
                res = await run_command(
                    [settings.trivy_bin, "image", "--download-db-only",
                     "--cache-dir", settings.trivy_cache_dir],
                    timeout=600, allowed_returncodes=(0,),
                )
                if res.ok:
                    log.info("rulepack.trivy_db_refreshed")
                else:
                    log.warning("rulepack.trivy_db_refresh_failed",
                                error=(res.stderr or "")[:300])
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — never crash on a refresh error
            log.warning("rulepack.refresh_failed", error=str(exc))
        try:
            await asyncio.sleep(6 * 3600)
        except asyncio.CancelledError:
            raise


app = FastAPI(
    title="Aegis Scanner",
    version="1.0.0",
    description="Stateless code analysis engine (SAST, SCA, secrets, quality, deployment).",
    lifespan=lifespan,
)

app.include_router(sast.router)
app.include_router(sca.router)
app.include_router(secrets.router)
app.include_router(quality.router)
app.include_router(deployment.router)
app.include_router(compliance.router)
app.include_router(deep.router)
app.include_router(rules.router)
app.include_router(sbom.router)


def _tool_status() -> dict[str, bool]:
    return {
        "semgrep": binary_available(settings.semgrep_bin),
        "trivy": binary_available(settings.trivy_bin),
        "gitleaks": binary_available(settings.gitleaks_bin),
    }


@app.get("/health", tags=["health"])
async def health() -> JSONResponse:
    tools = _tool_status()
    # Healthy as long as the process serves; tool gaps are surfaced, not fatal.
    return JSONResponse(
        {"status": "ok", "service": "scanner", "tools": tools, "environment": settings.environment}
    )


# Path to the planted-vulnerability fixture bundled in the image.
_SMOKE_FIXTURE = os.path.join(os.path.dirname(__file__), "tests", "fixtures", "vulnerable_app")


@app.get("/health/engines", tags=["health"])
async def health_engines() -> JSONResponse:
    """Run every engine against the smoke fixture and report per-engine health.

    Returns 200 when all engines find issues, 503 if any engine is broken (0
    findings or a failure). Used by `make smoke` and for live debugging so a
    silently-dead engine (e.g. a crashed tool) is caught immediately.
    """
    from models.scan_request import ScanRequest
    from models.scan_result import EngineStatus

    req = ScanRequest(path=_SMOKE_FIXTURE, scan_id="health-engines")
    engines = {
        "semgrep": semgrep_engine.run,
        "trivy": trivy_engine.run,
        "gitleaks": gitleaks_engine.run,
        "quality": quality_engine.run,
    }

    report: dict[str, dict] = {}
    all_ok = True
    for name, run_fn in engines.items():
        try:
            result = await run_fn(req, settings)
            ok = result.status != EngineStatus.FAILED and len(result.findings) > 0
            report[name] = {
                "ok": ok,
                "status": result.status.value,
                "findings": len(result.findings),
                "error": result.error,
            }
        except Exception as exc:  # noqa: BLE001 — surface, never crash the probe
            ok = False
            report[name] = {"ok": False, "status": "exception", "findings": 0, "error": str(exc)}
        all_ok = all_ok and ok

    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": "ok" if all_ok else "degraded", "engines": report},
    )


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"error": {"code": "VALIDATION_ERROR", "message": "invalid request", "details": exc.errors()}},
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled", path=str(request.url))
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "INTERNAL_ERROR", "message": "internal server error"}},
    )


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.scanner_host,
        port=settings.scanner_port,
        log_config=None,  # we configure logging ourselves
    )
