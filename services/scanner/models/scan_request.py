"""Pydantic request models for the scanner endpoints.

The orchestrator and scanner share a filesystem volume; requests carry the
absolute `path` to the already-checked-out source tree. The scanner never
fetches code itself — that keeps it stateless and side-effect free.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    """Common request shape for sast / sca / secrets / quality scans."""

    path: str = Field(..., description="Absolute path to the source tree to scan.")
    scan_id: str | None = Field(
        default=None, description="Originating scan id, echoed back for correlation."
    )
    languages: list[str] | None = Field(
        default=None,
        description="Optional pre-detected languages; if omitted the scanner detects them.",
    )
    project_types: list[str] | None = Field(
        default=None, description="Optional pre-detected project types (node, go, ...)."
    )

    @field_validator("path")
    @classmethod
    def _path_not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("path must not be empty")
        return v


class DeepScanRequest(ScanRequest):
    """Opt-in deep (interprocedural, cross-file) taint scan request.

    `engine` selects the deep-scan backend. Joern (Apache-2.0) is the bundled
    default; CodeQL is an opt-in slot that only runs where the customer has
    installed the CodeQL CLI under their own license.
    """

    engine: Literal["joern", "codeql"] = Field(
        default="joern", description="Deep-scan backend to use."
    )


class DeploymentRequest(ScanRequest):
    """Deployment-test request with optional build controls."""

    build_enabled: bool | None = Field(
        default=None,
        description="Override the service default for running build commands.",
    )
    smoke_test: bool = Field(
        default=True, description="Attempt to start the app and probe key routes."
    )
    start_timeout_seconds: int = Field(
        default=30, ge=1, le=300, description="Seconds to wait for the app to come up."
    )
