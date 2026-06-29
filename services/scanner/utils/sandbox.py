"""Sandboxed command execution utilities.

All scanner engines shell out to external binaries (semgrep, trivy, gitleaks,
build tools). This module centralizes how we run them so every call gets:

  * an enforced timeout (a hung tool can never block a worker forever),
  * captured stdout/stderr with size guards,
  * structured logging,
  * optional exponential-backoff retry for transient/network operations.

Execution is async (asyncio subprocess) so a router can fan several tools out
concurrently without blocking the event loop.
"""
from __future__ import annotations

import asyncio
import os
import shutil
from dataclasses import dataclass, field
from typing import Sequence

from logging_config import get_logger

log = get_logger("sandbox")

# Cap captured output so a pathological tool cannot exhaust memory.
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024  # 64 MB


class CommandError(RuntimeError):
    """Raised when a command cannot be started or times out."""


@dataclass
class CommandResult:
    """Outcome of a single command execution."""

    args: Sequence[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def binary_available(binary: str) -> bool:
    """Return True if `binary` is resolvable on PATH (or is an existing file)."""
    return shutil.which(binary) is not None or os.path.isfile(binary)


async def run_command(
    args: Sequence[str],
    *,
    cwd: str | None = None,
    timeout: float = 600.0,
    env: dict[str, str] | None = None,
    allowed_returncodes: Sequence[int] = (0,),
) -> CommandResult:
    """Run a command asynchronously with a hard timeout.

    `allowed_returncodes` lets callers treat non-zero exits as success — several
    of these tools use a non-zero code to mean "findings were detected" rather
    than "the run failed".
    """
    loop = asyncio.get_event_loop()
    start = loop.time()

    merged_env = {**os.environ, **(env or {})}

    log.debug("command.start", args=list(args), cwd=cwd, timeout=timeout)

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            cwd=cwd,
            env=merged_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise CommandError(f"binary not found: {args[0]}") from exc
    except OSError as exc:
        raise CommandError(f"failed to start {args[0]}: {exc}") from exc

    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        _kill(proc)
        # Give it a moment to die so we don't leak zombies.
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass
        duration = loop.time() - start
        log.warning("command.timeout", args=list(args), duration=duration)
        return CommandResult(
            args=args,
            returncode=-1,
            stdout="",
            stderr=f"command timed out after {timeout}s",
            duration_seconds=duration,
            timed_out=True,
        )

    duration = loop.time() - start
    stdout = _decode(stdout_b)
    stderr = _decode(stderr_b)

    result = CommandResult(
        args=args,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=duration,
    )

    if result.returncode in allowed_returncodes:
        log.debug("command.done", args=list(args), code=result.returncode, duration=duration)
    else:
        log.warning(
            "command.nonzero",
            args=list(args),
            code=result.returncode,
            duration=duration,
            stderr=stderr[:2000],
        )

    return result


async def run_with_retry(
    args: Sequence[str],
    *,
    cwd: str | None = None,
    timeout: float = 600.0,
    env: dict[str, str] | None = None,
    allowed_returncodes: Sequence[int] = (0,),
    retries: int = 2,
    base_delay: float = 1.0,
) -> CommandResult:
    """Run a command with exponential-backoff retry.

    Intended for operations with a network dependency (e.g. trivy DB refresh).
    Retries on timeout or disallowed return code; does not retry a missing binary.
    """
    attempt = 0
    last: CommandResult | None = None
    while attempt <= retries:
        result = await run_command(
            args,
            cwd=cwd,
            timeout=timeout,
            env=env,
            allowed_returncodes=allowed_returncodes,
        )
        if result.returncode in allowed_returncodes and not result.timed_out:
            return result
        last = result
        attempt += 1
        if attempt <= retries:
            delay = base_delay * (2 ** (attempt - 1))
            log.warning("command.retry", args=list(args), attempt=attempt, delay=delay)
            await asyncio.sleep(delay)
    assert last is not None
    return last


def _decode(data: bytes) -> str:
    if len(data) > _MAX_OUTPUT_BYTES:
        data = data[:_MAX_OUTPUT_BYTES]
    return data.decode("utf-8", errors="replace")


def _kill(proc: asyncio.subprocess.Process) -> None:
    try:
        proc.kill()
    except ProcessLookupError:
        pass
