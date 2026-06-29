"""Aegis scanner service — FastAPI entrypoint.

Stateless analysis engine. Exposes one endpoint per pillar/tool plus a health
check that reports which underlying binaries are available.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from config import get_settings
from logging_config import configure_logging, get_logger
from routers import deployment, quality, sast, sca, secrets
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
    yield
    log.info("shutdown")


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
