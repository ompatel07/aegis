"""Deployment testing engine — the capability competitors lack.

Verifies that a codebase actually builds and (optionally) starts:
  1. dependency resolution  (npm ci / pip install / go mod download / ...)
  2. build verification      (npm run build / go build / mvn package / ...)
  3. smoke test              (start the app, confirm it stays up / a port answers)

Build execution is gated behind a config flag because it runs project-supplied
commands; hardened deployments can disable it. Each step's output tail is kept
for diagnosis, and a failed step produces a deployment-pillar finding.
"""
from __future__ import annotations

import asyncio
import json
import os
import shlex

from config import Settings
from logging_config import get_logger
from models.scan_request import DeploymentRequest
from models.scan_result import (
    DeploymentReport,
    DeploymentStep,
    Engine,
    EngineResult,
    EngineStatus,
    Finding,
    Pillar,
    Severity,
    SeveritySummary,
)
from utils.language_detector import detect
from utils.sandbox import run_command

log = get_logger("deployment")

_COMMON_PORTS = (3000, 8080, 8000, 5000, 4000, 80)


async def run(req: DeploymentRequest, settings: Settings) -> EngineResult:
    build_enabled = (
        req.build_enabled if req.build_enabled is not None else settings.deployment_build_enabled
    )
    detection = detect(req.path)
    report = DeploymentReport()
    findings: list[Finding] = []

    if not build_enabled:
        # Use a non-scored step name so a *disabled* build is not counted as a
        # *failed* build by the orchestrator's deployment scorer.
        report.steps.append(
            DeploymentStep(name="build-skipped", success=False, output_tail="build execution disabled by config")
        )
        return _result(report, findings, req, status=EngineStatus.SKIPPED)

    project_types = detection.project_types
    if not project_types:
        report.steps.append(
            DeploymentStep(name="detect", success=False,
                           output_tail="no recognized build system (no package.json/go.mod/etc.)")
        )
        return _result(report, findings, req, status=EngineStatus.COMPLETED)

    # Pick the primary build system (first detected) for the install/build flow.
    ptype = project_types[0]

    # ── 1. Dependency resolution ────────────────────────────────────────────
    install_cmd = _install_command(ptype, req.path)
    if install_cmd:
        step = await _run_step("dependency-resolution", install_cmd, req.path,
                               settings.deployment_timeout_seconds)
        report.steps.append(step)
        report.dependency_resolution_ok = step.success
        if not step.success:
            findings.append(_step_finding(
                "deployment/dependency-resolution-failed",
                "Dependency installation failed", step, Severity.HIGH,
            ))

    # ── 2. Build verification ───────────────────────────────────────────────
    build_cmd = _build_command(ptype, req.path)
    if build_cmd:
        report.build_attempted = True
        step = await _run_step("build", build_cmd, req.path,
                               settings.deployment_timeout_seconds)
        report.steps.append(step)
        report.build_succeeded = step.success
        if not step.success:
            findings.append(_step_finding(
                "deployment/build-failed", "Build failed", step, Severity.CRITICAL,
            ))

    # ── 3. Smoke test (best-effort) ─────────────────────────────────────────
    if req.smoke_test and report.build_succeeded:
        start_cmd = _start_command(ptype, req.path)
        if start_cmd:
            report.smoke_attempted = True
            ok, tail = await _smoke_test(start_cmd, req.path, req.start_timeout_seconds)
            report.smoke_succeeded = ok
            report.steps.append(
                DeploymentStep(name="smoke", command=start_cmd, success=ok, output_tail=tail)
            )
            if not ok:
                findings.append(Finding(
                    pillar=Pillar.DEPLOYMENT, engine=Engine.DEPLOYMENT,
                    rule_id="deployment/smoke-test-failed",
                    rule_name="Smoke test failed", severity=Severity.MEDIUM,
                    title="Application failed to start during smoke test",
                    description=(
                        "The start command exited or no port responded within the "
                        f"{req.start_timeout_seconds}s window. The build may produce an "
                        "artifact that does not run cleanly in a clean environment."
                    ),
                    file_path=".", metadata={"command": start_cmd},
                ))

    return _result(report, findings, req, status=EngineStatus.COMPLETED)


# ── Command resolution ───────────────────────────────────────────────────────

def _install_command(ptype: str, root: str) -> str | None:
    if ptype == "node":
        lock = os.path.isfile(os.path.join(root, "package-lock.json"))
        return "npm ci" if lock else "npm install --no-audit --no-fund"
    if ptype == "python":
        if os.path.isfile(os.path.join(root, "requirements.txt")):
            return "pip install --no-input -r requirements.txt"
        if os.path.isfile(os.path.join(root, "pyproject.toml")):
            return "pip install --no-input ."
        return None
    if ptype == "go":
        return "go mod download"
    if ptype == "ruby":
        return "bundle install"
    if ptype == "cargo":
        return "cargo fetch"
    if ptype in ("maven",):
        return None  # maven resolves during package
    if ptype == "gradle":
        return None
    return None


def _build_command(ptype: str, root: str) -> str | None:
    if ptype == "node":
        return "npm run build" if _has_npm_script(root, "build") else None
    if ptype == "python":
        # Python has no build; syntax-compile everything as a smoke of importability.
        return "python -m compileall -q ."
    if ptype == "go":
        return "go build ./..."
    if ptype == "maven":
        return "mvn -q -B -DskipTests package"
    if ptype == "gradle":
        return "gradle build -x test --console=plain"
    if ptype == "ruby":
        return None
    if ptype == "cargo":
        return "cargo build --quiet"
    return None


def _start_command(ptype: str, root: str) -> str | None:
    if ptype == "node":
        if _has_npm_script(root, "start"):
            return "npm run start"
        return None
    if ptype == "go":
        return "go run ."
    return None


def _has_npm_script(root: str, script: str) -> bool:
    try:
        with open(os.path.join(root, "package.json"), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return script in (data.get("scripts") or {})
    except (OSError, ValueError):
        return False


# ── Execution helpers ────────────────────────────────────────────────────────

async def _run_step(name: str, command: str, cwd: str, timeout: int) -> DeploymentStep:
    result = await run_command(
        shlex.split(command), cwd=cwd, timeout=timeout, allowed_returncodes=(0,),
    )
    tail = _tail(result.stdout + ("\n" + result.stderr if result.stderr else ""))
    return DeploymentStep(
        name=name, command=command, success=result.ok,
        duration_seconds=round(result.duration_seconds, 2), output_tail=tail,
    )


async def _smoke_test(command: str, cwd: str, timeout: int) -> tuple[bool, str]:
    """Start the app; success = it stays alive AND a common port answers.

    The process is always terminated afterwards so we never leak a server.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *shlex.split(command), cwd=cwd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
    except OSError as exc:
        return False, f"failed to start: {exc}"

    try:
        # Poll for a listening port for up to `timeout` seconds.
        deadline = asyncio.get_event_loop().time() + timeout
        port_up = False
        while asyncio.get_event_loop().time() < deadline:
            if proc.returncode is not None:
                break  # process exited early
            if await _any_port_open(_COMMON_PORTS):
                port_up = True
                break
            await asyncio.sleep(1.0)

        alive = proc.returncode is None
        success = alive and port_up
        tail = "process started and a port responded" if success else (
            "process exited before serving" if not alive else "no port responded in time"
        )
        return success, tail
    finally:
        _terminate(proc)
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass


async def _any_port_open(ports) -> bool:
    for port in ports:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=0.5
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (OSError, asyncio.TimeoutError):
            continue
    return False


def _terminate(proc: asyncio.subprocess.Process) -> None:
    try:
        proc.terminate()
    except ProcessLookupError:
        pass


def _tail(text: str, lines: int = 40) -> str:
    parts = text.strip().splitlines()
    return "\n".join(parts[-lines:])


def _step_finding(rule_id: str, name: str, step: DeploymentStep, severity: Severity) -> Finding:
    return Finding(
        pillar=Pillar.DEPLOYMENT, engine=Engine.DEPLOYMENT,
        rule_id=rule_id, rule_name=name, severity=severity,
        title=f"{name}: `{step.command}`",
        description=(
            f"The command `{step.command}` failed during deployment testing.\n\n"
            f"Output tail:\n{step.output_tail or '(no output)'}"
        ),
        file_path=".", metadata={"command": step.command, "step": step.name},
    )


def _result(report, findings, req, status: EngineStatus) -> EngineResult:
    return EngineResult(
        engine=Engine.DEPLOYMENT, pillar=Pillar.DEPLOYMENT, status=status,
        findings=findings, summary=SeveritySummary.from_findings(findings),
        deployment_report=report, raw={"report": report.model_dump()},
        scan_id=req.scan_id,
    )
