"""Pydantic response models — the normalized finding contract.

Every engine, regardless of the underlying tool, returns an `EngineResult` with
a list of `Finding`s in this shape. The orchestrator maps these 1:1 onto the
`findings` database table, so field names intentionally match the schema.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Pillar(str, Enum):
    QUALITY = "quality"
    SECURITY = "security"
    DEPLOYMENT = "deployment"


class Engine(str, Enum):
    SEMGREP = "semgrep"
    TRIVY = "trivy"
    GITLEAKS = "gitleaks"
    QUALITY = "quality"
    DEPLOYMENT = "deployment"
    CODEQL = "codeql"
    JOERN = "joern"


class EngineStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


# Ordering used for sorting/aggregation (most severe first).
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Finding(BaseModel):
    """A single normalized finding. Mirrors the `findings` table columns."""

    pillar: Pillar
    engine: Engine
    rule_id: str
    rule_name: str
    severity: Severity
    title: str
    description: str | None = None

    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None

    cwe_id: str | None = None
    cve_id: str | None = None
    owasp_category: str | None = None

    fix_suggestion: str | None = None
    metadata: dict | None = None

    # ── Context-rich enrichment (Phase 2B) ───────────────────────────────────
    # Populated by the enrichment layer so findings are actionable, not raw rule
    # names. See enrichment/enricher.py + enrichment/rule_templates.yaml.
    title_human: str | None = None          # "AWS secret key detected"
    impact: str | None = None               # one-line concrete consequence
    risk_level: str | None = None           # informational|low|medium|high|critical
    remediation_action: str | None = None   # short imperative action
    remediation_details: str | None = None  # markdown fix guide
    estimated_effort: str | None = None     # trivial|quick|moderate|significant
    context_metadata: dict | None = None    # engine-specific enrichment

    # Local ML false-positive filter output (advisory: sorts + badges, never hides).
    false_positive_probability: float | None = None


class SeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "SeveritySummary":
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] += 1
        return cls(**counts)


class QualityMetrics(BaseModel):
    """Sub-scores (0-100) and raw measurements feeding the quality pillar score."""

    complexity_score: float = 0.0
    duplication_score: float = 0.0
    maintainability_score: float = 0.0
    test_coverage_score: float = 0.0
    documentation_score: float = 0.0

    avg_cyclomatic_complexity: float = 0.0
    max_cyclomatic_complexity: int = 0
    duplicated_line_percentage: float = 0.0
    comment_density: float = 0.0
    total_functions: int = 0
    total_code_lines: int = 0
    has_tests: bool = False


class DeploymentStep(BaseModel):
    """One stage of the deployment check (e.g. install, build, smoke)."""

    name: str
    command: str | None = None
    success: bool
    duration_seconds: float = 0.0
    output_tail: str | None = None  # last lines of stdout/stderr for diagnosis


class DeploymentReport(BaseModel):
    build_attempted: bool = False
    build_succeeded: bool = False
    smoke_attempted: bool = False
    smoke_succeeded: bool = False
    dependency_resolution_ok: bool = False
    steps: list[DeploymentStep] = Field(default_factory=list)


class AICodeResult(BaseModel):
    """AI-generated-code analysis for a repository (Phase 2C TASK 3a).

    Runs locally over file text — no code leaves the scanner. `file_scores` holds
    only files scoring >= 0.3 (AI + borderline) to bound payload size on large
    repos; findings in files absent from the map are treated as human-written.
    """

    status: EngineStatus = EngineStatus.COMPLETED
    files_scored: int = 0
    ai_file_count: int = 0            # files with probability > threshold
    ai_generated_pct: float = 0.0    # ai_file_count / files_scored * 100
    threshold: float = 0.7
    model_available: bool = False    # trained model vs heuristic fallback
    file_scores: dict[str, float] = Field(default_factory=dict)
    top_signals: list[str] = Field(default_factory=list)  # why files were flagged
    duration_seconds: float = 0.0
    scan_id: str | None = None
    error: str | None = None


class EngineResult(BaseModel):
    """Uniform envelope returned by every scanner endpoint."""

    engine: Engine
    pillar: Pillar
    status: EngineStatus
    findings: list[Finding] = Field(default_factory=list)
    summary: SeveritySummary = Field(default_factory=SeveritySummary)

    # Pillar-specific extras.
    quality_metrics: QualityMetrics | None = None
    deployment_report: DeploymentReport | None = None

    # Raw underlying tool output (stored to scans.raw_*_output).
    raw: dict | None = None

    duration_seconds: float = 0.0
    scan_id: str | None = None
    error: str | None = None
    # Reproducible id of the rule set used (semgrep), recorded on the scan.
    rule_pack_version: str | None = None

    @classmethod
    def failed(
        cls,
        engine: Engine,
        pillar: Pillar,
        error: str,
        *,
        scan_id: str | None = None,
        duration_seconds: float = 0.0,
    ) -> "EngineResult":
        return cls(
            engine=engine,
            pillar=pillar,
            status=EngineStatus.FAILED,
            error=error,
            scan_id=scan_id,
            duration_seconds=duration_seconds,
        )
