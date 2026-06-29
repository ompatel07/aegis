"""Code quality engine.

Combines:
  * lizard  — multi-language cyclomatic complexity, function length, params,
  * radon   — Python maintainability index (when Python files are present),
  * custom  — block-level duplication detection + comment/documentation density.

Produces both a `QualityMetrics` block (sub-scores 0-100 feeding the pillar
score) and individual `Finding`s for the worst offenders.
"""
from __future__ import annotations

import hashlib
import os

import lizard

from config import Settings
from logging_config import get_logger
from models.scan_request import ScanRequest
from models.scan_result import (
    Engine,
    EngineResult,
    EngineStatus,
    Finding,
    Pillar,
    QualityMetrics,
    Severity,
    SeveritySummary,
)
from utils import normalizer
from utils.language_detector import IGNORED_DIRS, _EXTENSION_MAP

log = get_logger("quality")

# Thresholds.
_CC_WARN = 11           # cyclomatic complexity considered a smell
_CC_HIGH = 21           # high-severity complexity
_LONG_FUNC_NLOC = 80    # function length (lines of code) considered too long
_MANY_PARAMS = 6        # parameter count considered a smell
_DUP_WINDOW = 6         # consecutive normalized lines forming a duplication block
_MAX_FILE_BYTES = 1_500_000

# Single-line comment markers per language family (best-effort heuristic).
_LINE_COMMENT = {
    "python": "#",
    "ruby": "#",
    "javascript": "//",
    "typescript": "//",
    "go": "//",
    "java": "//",
    "csharp": "//",
    "c": "//",
    "cpp": "//",
    "php": "//",
    "rust": "//",
    "kotlin": "//",
    "scala": "//",
}
_TEST_HINTS = ("test", "spec", "__tests__", "_test", ".test.", ".spec.")


async def run(req: ScanRequest, settings: Settings) -> EngineResult:
    try:
        files = _collect_files(req.path)
    except OSError as exc:
        return EngineResult.failed(
            Engine.QUALITY, Pillar.QUALITY, f"failed to walk source tree: {exc}",
            scan_id=req.scan_id,
        )

    if not files:
        # Nothing to analyze — report a perfect-but-empty quality result.
        return EngineResult(
            engine=Engine.QUALITY, pillar=Pillar.QUALITY,
            status=EngineStatus.COMPLETED, findings=[],
            quality_metrics=QualityMetrics(), summary=SeveritySummary(),
            raw={"files_analyzed": 0}, scan_id=req.scan_id,
        )

    findings: list[Finding] = []
    total_cc = 0
    max_cc = 0
    total_functions = 0
    total_code_lines = 0

    for path, language in files:
        try:
            info = lizard.analyze_file(path)
        except Exception as exc:  # lizard can raise on exotic files; skip them.
            log.debug("lizard.skip", path=path, error=str(exc))
            continue

        total_code_lines += info.nloc
        rel = normalizer.relative_path(path, req.path)

        for fn in info.function_list:
            total_functions += 1
            total_cc += fn.cyclomatic_complexity
            max_cc = max(max_cc, fn.cyclomatic_complexity)
            findings.extend(_function_findings(fn, rel, language))

    avg_cc = (total_cc / total_functions) if total_functions else 0.0

    dup_pct, dup_findings = _duplication(files, req.path)
    findings.extend(dup_findings)

    comment_density = _comment_density(files)
    has_tests = _has_tests(files)
    coverage_pct = _coverage_percentage(req.path)

    metrics = _build_metrics(
        avg_cc=avg_cc, max_cc=max_cc, total_functions=total_functions,
        total_code_lines=total_code_lines, smell_count=len(findings),
        dup_pct=dup_pct, comment_density=comment_density,
        has_tests=has_tests, coverage_pct=coverage_pct,
    )

    return EngineResult(
        engine=Engine.QUALITY,
        pillar=Pillar.QUALITY,
        status=EngineStatus.COMPLETED,
        findings=findings,
        summary=SeveritySummary.from_findings(findings),
        quality_metrics=metrics,
        raw={
            "files_analyzed": len(files),
            "metrics": metrics.model_dump(),
        },
        scan_id=req.scan_id,
    )


# ── Findings ─────────────────────────────────────────────────────────────────

def _function_findings(fn, rel_path: str, language: str) -> list[Finding]:
    out: list[Finding] = []
    cc = fn.cyclomatic_complexity

    if cc >= _CC_WARN:
        severity = Severity.HIGH if cc >= _CC_HIGH else Severity.MEDIUM
        out.append(
            Finding(
                pillar=Pillar.QUALITY, engine=Engine.QUALITY,
                rule_id="quality/high-cyclomatic-complexity",
                rule_name="High cyclomatic complexity",
                severity=severity,
                title=f"Function '{fn.name}' has cyclomatic complexity {cc}",
                description=(
                    f"'{fn.name}' has a cyclomatic complexity of {cc} (threshold {_CC_WARN}). "
                    "High complexity makes code harder to test and maintain. Consider "
                    "extracting helpers or simplifying branching."
                ),
                file_path=rel_path,
                line_start=fn.start_line, line_end=fn.end_line,
                metadata={"complexity": cc, "nloc": fn.nloc, "language": language},
            )
        )

    if fn.nloc >= _LONG_FUNC_NLOC:
        out.append(
            Finding(
                pillar=Pillar.QUALITY, engine=Engine.QUALITY,
                rule_id="quality/long-function", rule_name="Long function",
                severity=Severity.LOW,
                title=f"Function '{fn.name}' is {fn.nloc} lines long",
                description=(
                    f"'{fn.name}' spans {fn.nloc} lines (threshold {_LONG_FUNC_NLOC}). "
                    "Long functions tend to do too much; consider decomposition."
                ),
                file_path=rel_path, line_start=fn.start_line, line_end=fn.end_line,
                metadata={"nloc": fn.nloc, "language": language},
            )
        )

    if fn.parameter_count >= _MANY_PARAMS:
        out.append(
            Finding(
                pillar=Pillar.QUALITY, engine=Engine.QUALITY,
                rule_id="quality/too-many-parameters", rule_name="Too many parameters",
                severity=Severity.LOW,
                title=f"Function '{fn.name}' has {fn.parameter_count} parameters",
                description=(
                    f"'{fn.name}' takes {fn.parameter_count} parameters (threshold "
                    f"{_MANY_PARAMS}). Consider grouping related arguments into an object."
                ),
                file_path=rel_path, line_start=fn.start_line, line_end=fn.end_line,
                metadata={"parameter_count": fn.parameter_count, "language": language},
            )
        )
    return out


# ── Duplication ──────────────────────────────────────────────────────────────

def _duplication(files: list[tuple[str, str]], root: str) -> tuple[float, list[Finding]]:
    """Block-level duplication via a sliding window of normalized lines.

    Returns the duplicated-line percentage and a finding per duplicated file.
    """
    block_locations: dict[str, list[tuple[str, int]]] = {}
    per_file_lines: dict[str, list[str]] = {}
    total_lines = 0

    for path, _lang in files:
        lines = _read_normalized_lines(path)
        if not lines:
            continue
        rel = normalizer.relative_path(path, root)
        per_file_lines[rel] = lines
        total_lines += len(lines)
        for i in range(0, max(0, len(lines) - _DUP_WINDOW + 1)):
            window = "\n".join(lines[i : i + _DUP_WINDOW])
            digest = hashlib.sha1(window.encode("utf-8")).hexdigest()
            block_locations.setdefault(digest, []).append((rel, i))

    duplicated_lines = 0
    files_with_dupes: dict[str, int] = {}
    for locations in block_locations.values():
        if len(locations) > 1:
            # Count the redundant copies (all but the first occurrence).
            for rel, _idx in locations[1:]:
                duplicated_lines += _DUP_WINDOW
                files_with_dupes[rel] = files_with_dupes.get(rel, 0) + 1

    dup_pct = (duplicated_lines / total_lines * 100.0) if total_lines else 0.0
    dup_pct = min(dup_pct, 100.0)

    findings: list[Finding] = []
    for rel, blocks in sorted(files_with_dupes.items(), key=lambda kv: -kv[1])[:50]:
        findings.append(
            Finding(
                pillar=Pillar.QUALITY, engine=Engine.QUALITY,
                rule_id="quality/duplicated-code", rule_name="Duplicated code",
                severity=Severity.LOW,
                title=f"{blocks} duplicated block(s) detected in {rel}",
                description=(
                    f"{blocks} block(s) of {_DUP_WINDOW}+ consecutive lines in '{rel}' "
                    "appear elsewhere in the codebase. Extract shared logic to reduce "
                    "maintenance cost and drift."
                ),
                file_path=rel,
                metadata={"duplicate_blocks": blocks, "window": _DUP_WINDOW},
            )
        )
    return dup_pct, findings


def _read_normalized_lines(path: str) -> list[str]:
    """Read a file and return stripped, non-trivial lines for duplication hashing."""
    try:
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            return []
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            raw = fh.readlines()
    except OSError:
        return []
    out = []
    for line in raw:
        stripped = line.strip()
        # Ignore blank lines and braces-only lines — they create noise.
        if len(stripped) > 3 and stripped not in ("});", "});"):
            out.append(stripped)
    return out


# ── Documentation / tests / coverage ─────────────────────────────────────────

def _comment_density(files: list[tuple[str, str]]) -> float:
    comment_lines = 0
    code_lines = 0
    for path, language in files:
        marker = _LINE_COMMENT.get(language)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    s = line.strip()
                    if not s:
                        continue
                    if marker and s.startswith(marker):
                        comment_lines += 1
                    elif s.startswith(("/*", "*", '"""', "'''")):
                        comment_lines += 1
                    else:
                        code_lines += 1
        except OSError:
            continue
    denom = comment_lines + code_lines
    return (comment_lines / denom) if denom else 0.0


def _has_tests(files: list[tuple[str, str]]) -> bool:
    for path, _lang in files:
        low = path.lower()
        if any(hint in low for hint in _TEST_HINTS):
            return True
    return False


def _coverage_percentage(root: str) -> float | None:
    """Best-effort: read a coverage summary if the project ships one."""
    candidates = ["coverage/coverage-summary.json", "coverage-summary.json"]
    for rel in candidates:
        path = os.path.join(root, rel)
        if os.path.isfile(path):
            try:
                import json

                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                pct = data.get("total", {}).get("lines", {}).get("pct")
                if isinstance(pct, (int, float)):
                    return float(pct)
            except (OSError, ValueError):
                continue
    return None


# ── Metrics / scoring ────────────────────────────────────────────────────────

def _build_metrics(
    *, avg_cc: float, max_cc: int, total_functions: int, total_code_lines: int,
    smell_count: int, dup_pct: float, comment_density: float,
    has_tests: bool, coverage_pct: float | None,
) -> QualityMetrics:
    # Complexity: 100 when avg <= 5, decaying ~6 pts per point of avg CC above 5.
    complexity_score = _clamp(100.0 - max(0.0, avg_cc - 5.0) * 6.0)

    # Duplication: directly inverse of duplicated-line percentage.
    duplication_score = _clamp(100.0 - dup_pct)

    # Maintainability: penalize smell density (smells per 1k LOC).
    kloc = max(total_code_lines / 1000.0, 0.001)
    smell_density = smell_count / kloc
    maintainability_score = _clamp(100.0 - smell_density * 8.0)

    # Documentation: target ~15% comment density = full marks.
    documentation_score = _clamp((comment_density / 0.15) * 100.0)

    # Coverage: use real % if known; otherwise a heuristic from test presence.
    if coverage_pct is not None:
        test_coverage_score = _clamp(coverage_pct)
    else:
        test_coverage_score = 60.0 if has_tests else 0.0

    return QualityMetrics(
        complexity_score=round(complexity_score, 2),
        duplication_score=round(duplication_score, 2),
        maintainability_score=round(maintainability_score, 2),
        test_coverage_score=round(test_coverage_score, 2),
        documentation_score=round(documentation_score, 2),
        avg_cyclomatic_complexity=round(avg_cc, 2),
        max_cyclomatic_complexity=max_cc,
        duplicated_line_percentage=round(dup_pct, 2),
        comment_density=round(comment_density, 4),
        total_functions=total_functions,
        total_code_lines=total_code_lines,
        has_tests=has_tests,
    )


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


# ── File collection ──────────────────────────────────────────────────────────

def _collect_files(root: str, max_files: int = 20_000) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for name in filenames:
            _, ext = os.path.splitext(name)
            language = _EXTENSION_MAP.get(ext.lower())
            if language:
                out.append((os.path.join(dirpath, name), language))
                if len(out) >= max_files:
                    return out
    return out
