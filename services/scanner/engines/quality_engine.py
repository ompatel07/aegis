"""Code quality engine.

Combines:
  * lizard  — multi-language cyclomatic complexity, function length, params,
  * radon   — Python maintainability index (when Python files are present),
  * custom  — block-level duplication detection + comment/documentation density.

Produces both a `QualityMetrics` block (sub-scores 0-100 feeding the pillar
score) and individual `Finding`s for the worst offenders.
"""
from __future__ import annotations

import os
import re

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
from utils import duplication, normalizer
from utils.language_detector import IGNORED_DIRS, _EXTENSION_MAP

log = get_logger("quality")

# Thresholds.
_CC_WARN = 11           # cyclomatic complexity considered a smell
_CC_HIGH = 21           # high-severity complexity
_LONG_FUNC_NLOC = 80    # function length (lines of code) considered too long
_GOD_FUNC_NLOC = 500    # "god function" — far too large, high severity
_MANY_PARAMS = 6        # parameter count considered a smell (>5)
_MAX_NESTING = 4        # nesting depth beyond this is a smell
_MAGIC_MIN = 6          # magic-number count per file before we flag it
_CLONE_SEV_HIGH = 250   # clone token length at/above which duplication is medium sev
_MAX_FILE_BYTES = 1_500_000

# "Unremarkable" numeric literals that are not magic numbers.
_ALLOWED_NUMS = {"0", "1", "2", "-1", "0.0", "1.0", "0x0", "100", "1000"}
_NUM_RE = re.compile(r"(?<![\w.$#])-?\d+(?:\.\d+)?(?![\w.])")
# Everything inside an <svg>…</svg> element is coordinate/path/filter geometry (the
# glyph itself: `d="M26 0V314…"`, viewBox, width/x/y/dy/stdDeviation/feColorMatrix
# values), not extractable constants. SVG icon components (Vector.js, Instagram.js,
# Arrow.js, …) would otherwise report dozens of "magic numbers" that are pure noise.
# We mask out the line-span of each <svg> element before counting, so genuine magic
# numbers in the surrounding JS/TS logic — even in the same file — are still caught.
# A real SVG element: an opening <svg …> through its matching </svg>. Non-greedy so
# sibling <svg> blocks match independently; DOTALL so it spans lines. A self-closing
# <svg/> in a string literal has no </svg> and correctly matches nothing.
_SVG_ELEMENT_RE = re.compile(r"<svg\b.*?</svg\s*>", re.I | re.S)


def _svg_line_mask(file_lines: list[str]) -> set[int]:
    """1-based line numbers that fall inside an <svg>…</svg> element."""
    code = "\n".join(file_lines)
    masked: set[int] = set()
    for m in _SVG_ELEMENT_RE.finditer(code):
        start = code.count("\n", 0, m.start()) + 1
        end = code.count("\n", 0, m.end()) + 1
        masked.update(range(start, end + 1))
    return masked
_CONST_DEF_RE = re.compile(
    r"^\s*(?:export\s+)?(?:public\s+|private\s+|protected\s+)?"
    r"(?:const|final|static|readonly|val|let|var|#define|enum)\b"
    r"|^\s*[A-Z_][A-Z0-9_]{2,}\s*[:=]"
)

# Tech-debt markers left in comments, and leftover debug output per language.
_TECH_DEBT_RE = re.compile(r"(?://|#|/\*|\*|<!--)\s*@?\s*\b(TODO|FIXME|HACK|XXX)\b")
_DEBUG_PATTERNS = {
    "javascript": re.compile(r"\bconsole\.(?:log|debug|trace)\s*\(|\bdebugger\b"),
    "typescript": re.compile(r"\bconsole\.(?:log|debug|trace)\s*\(|\bdebugger\b"),
    "python": re.compile(r"\b(?:pdb\.set_trace|breakpoint)\s*\("),
    "java": re.compile(r"\bSystem\.out\.print|\.printStackTrace\s*\("),
}

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
        file_lines = _read_lines(path)

        for fn in info.function_list:
            total_functions += 1
            total_cc += fn.cyclomatic_complexity
            max_cc = max(max_cc, fn.cyclomatic_complexity)
            findings.extend(_function_findings(fn, rel, language, file_lines))

        for maker in (_magic_number_finding, _tech_debt_finding, _debug_statement_finding):
            extra = maker(file_lines, rel, language)
            if extra:
                findings.append(extra)

    avg_cc = (total_cc / total_functions) if total_functions else 0.0

    dup_count, clones = duplication.find_clones(files, req.path)
    findings.extend(_duplication_findings(clones))
    dup_pct = min(100.0, (dup_count / total_code_lines * 100.0)) if total_code_lines else 0.0

    comment_density = _comment_density(files)
    has_tests = _has_tests(files)
    coverage_pct = _coverage_percentage(req.path)

    metrics = _build_metrics(
        avg_cc=avg_cc, max_cc=max_cc, total_functions=total_functions,
        total_code_lines=total_code_lines, smell_count=len(findings),
        dup_pct=dup_pct, comment_density=comment_density,
        has_tests=has_tests, coverage_pct=coverage_pct,
    )

    # Ruff — type-aware Python bugs (Q3), merged into the quality pillar. Added
    # AFTER metrics (bug findings must not inflate the maintainability smell
    # density) but BEFORE enrichment (so they get ownership tagging, inline
    # snippet, the content-based lifecycle fingerprint, issue_type and FP scoring
    # like every other finding).
    from engines import ruff_engine

    ruff_findings, ruff_raw = await ruff_engine.collect(req, settings)
    findings.extend(ruff_findings)

    from enrichment import enricher

    enricher.enrich_all(findings, req.path)

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
            "ruff": ruff_raw,
        },
        scan_id=req.scan_id,
    )


# ── Findings ─────────────────────────────────────────────────────────────────

# lizard has no real JSX/TSX grammar: on React components it frequently fails to
# find function boundaries and mislabels a merged span with a method-call chain it
# happened to see (e.g. `email.toLowerCase.trim` for the whole ForgotPasswordModal
# body). A genuine JS/TS function name is a single identifier or a 2-part
# `obj.method` — a 3+-segment dotted chain, or one whose tail is a built-in method,
# is an expression, not a definition. Such an entry is a parse artifact whose span
# and complexity can't be trusted, so we emit no finding for it (precision-first).
_JS_LANGS = {"javascript", "typescript", "jsx", "tsx"}
_JS_CHAIN_METHODS = {
    "trim", "tolowercase", "touppercase", "map", "filter", "foreach", "reduce",
    "then", "catch", "split", "join", "replace", "slice", "concat", "find",
    "includes", "tostring", "json", "parse", "stringify", "call", "apply", "bind",
}


def _is_misparsed_js_name(name: str, language: str) -> bool:
    if language not in _JS_LANGS or not name:
        return False
    segs = name.split(".")
    if len(segs) >= 3:
        return True  # a.b.c… is a property/method chain, never a definition name
    if len(segs) == 2 and segs[1].lower() in _JS_CHAIN_METHODS:
        return True  # obj.trim / x.map — a method call, not a defined function
    return False


def _function_findings(fn, rel_path: str, language: str, file_lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    if _is_misparsed_js_name(fn.name, language):
        return out  # lizard JSX misparse — untrustworthy boundaries/metrics
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

    # God function vs merely-long function are mutually exclusive (no double report).
    if fn.nloc >= _GOD_FUNC_NLOC:
        out.append(
            Finding(
                pillar=Pillar.QUALITY, engine=Engine.QUALITY,
                rule_id="quality/god-function", rule_name="God function",
                severity=Severity.HIGH,
                title=f"Function '{fn.name}' is {fn.nloc} lines long",
                description=(
                    f"'{fn.name}' spans {fn.nloc} lines (threshold {_GOD_FUNC_NLOC}). A function "
                    "this large is doing far too much and is nearly impossible to test in "
                    "isolation. Break it into cohesive units."
                ),
                file_path=rel_path, line_start=fn.start_line, line_end=fn.end_line,
                metadata={"nloc": fn.nloc, "language": language},
            )
        )
    elif fn.nloc >= _LONG_FUNC_NLOC:
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

    nesting = _max_nesting(file_lines, fn.start_line, fn.end_line, language)
    if nesting > _MAX_NESTING:
        out.append(
            Finding(
                pillar=Pillar.QUALITY, engine=Engine.QUALITY,
                rule_id="quality/deep-nesting", rule_name="Deeply nested code",
                severity=Severity.MEDIUM,
                title=f"Function '{fn.name}' nests {nesting} levels deep",
                description=(
                    f"'{fn.name}' reaches a nesting depth of {nesting} (threshold {_MAX_NESTING}). "
                    "Deep nesting hurts readability; use guard clauses / early returns or extract "
                    "the inner blocks into helpers."
                ),
                file_path=rel_path, line_start=fn.start_line, line_end=fn.end_line,
                metadata={"nesting_depth": nesting, "language": language},
            )
        )
    return out


# ── Duplication ──────────────────────────────────────────────────────────────

def _duplication_findings(clones: list[dict]) -> list[Finding]:
    """Build findings from token-normalized clone regions (severity by length)."""
    out: list[Finding] = []
    for c in clones[:60]:
        tokens = c["tokens"]
        # Duplication is a maintainability, not a security, smell — so even a large
        # clone caps at medium; everything shorter is low. (Our own aegis-bug-
        # identical-if-else-branches rule caught the previous elif/else here both
        # assigning LOW — a dead branch; collapsed.)
        severity = Severity.MEDIUM if tokens >= _CLONE_SEV_HIGH else Severity.LOW
        peers = c.get("peers") or []
        peer_txt = ("; also at " + ", ".join(peers)) if peers else ""
        out.append(
            Finding(
                pillar=Pillar.QUALITY, engine=Engine.QUALITY,
                rule_id="quality/duplicated-code", rule_name="Duplicated code",
                severity=severity,
                title=(
                    f"Duplicated block of {c['lines']} lines "
                    f"({c['occurrences']} copies) in {c['file']}"
                ),
                description=(
                    f"Lines {c['line_start']}-{c['line_end']} of '{c['file']}' are a "
                    f"token-for-token duplicate (identifiers/formatting aside) of "
                    f"{c['occurrences'] - 1} other location(s){peer_txt}. Extract the shared "
                    "logic to a single function to avoid drift and duplicated bug-fixes."
                ),
                file_path=c["file"],
                line_start=c["line_start"], line_end=c["line_end"],
                metadata={
                    "clone_tokens": tokens,
                    "clone_lines": c["lines"],
                    "occurrences": c["occurrences"],
                    "peers": peers,
                },
            )
        )
    return out


# ── Nesting depth ─────────────────────────────────────────────────────────────

def _max_nesting(file_lines: list[str], start_line: int, end_line: int, language: str) -> int:
    """Best-effort maximum control-flow nesting depth of a function body."""
    if not file_lines or start_line < 1:
        return 0
    body = file_lines[start_line - 1 : end_line]
    if not body:
        return 0
    if language in ("python", "ruby"):
        return _indent_nesting(body)
    return _brace_nesting(body)


def _indent_nesting(body: list[str]) -> int:
    base = None
    max_depth = 0
    for raw in body:
        line = raw.expandtabs(4)
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if base is None:  # the def line sets the baseline
            base = indent
            continue
        depth = max(0, (indent - base)) // 4
        max_depth = max(max_depth, depth)
    return max_depth


def _brace_nesting(body: list[str]) -> int:
    depth = 0
    max_depth = 0
    for raw in body:
        for ch in raw:
            if ch == "{":
                depth += 1
                max_depth = max(max_depth, depth)
            elif ch == "}":
                depth = max(0, depth - 1)
    # The function's own outermost block is depth 1; don't count it as nesting.
    return max(0, max_depth - 1)


# ── Magic numbers ─────────────────────────────────────────────────────────────

def _magic_number_finding(file_lines: list[str], rel: str, language: str) -> Finding | None:
    if any(hint in rel.lower() for hint in _TEST_HINTS):
        return None  # test fixtures legitimately contain many literals
    marker = _LINE_COMMENT.get(language)
    svg_lines = _svg_line_mask(file_lines) if "<svg" in "".join(file_lines).lower() else set()
    hits: list[int] = []
    for lineno, raw in enumerate(file_lines, start=1):
        if lineno in svg_lines:
            continue  # SVG geometry, not extractable constants
        s = raw.strip()
        if not s or (marker and s.startswith(marker)) or s.startswith(("/*", "*", '"""', "'''")):
            continue
        if _CONST_DEF_RE.search(s):
            continue
        for m in _NUM_RE.finditer(s):
            if m.group(0) not in _ALLOWED_NUMS:
                hits.append(lineno)
    if len(hits) < _MAGIC_MIN:
        return None
    sample = sorted(set(hits))[:10]
    return Finding(
        pillar=Pillar.QUALITY, engine=Engine.QUALITY,
        rule_id="quality/magic-numbers", rule_name="Magic numbers",
        severity=Severity.LOW,
        title=f"{len(hits)} unexplained numeric literals in {rel}",
        description=(
            f"'{rel}' uses {len(hits)} magic numbers (e.g. lines "
            f"{', '.join(map(str, sample))}). Extract them into named constants so their "
            "meaning is explicit and changes happen in one place."
        ),
        file_path=rel, line_start=sample[0] if sample else None,
        metadata={"magic_number_count": len(hits), "sample_lines": sample, "language": language},
    )


def _tech_debt_finding(file_lines: list[str], rel: str, language: str) -> Finding | None:
    hits = [i for i, line in enumerate(file_lines, start=1) if _TECH_DEBT_RE.search(line)]
    if not hits:
        return None
    sample = hits[:10]
    return Finding(
        pillar=Pillar.QUALITY, engine=Engine.QUALITY,
        rule_id="quality/tech-debt-marker", rule_name="Unresolved tech-debt marker",
        severity=Severity.LOW,
        title=f"{len(hits)} TODO/FIXME marker(s) in {rel}",
        description=(
            f"'{rel}' contains {len(hits)} unresolved TODO/FIXME/HACK marker(s) (lines "
            f"{', '.join(map(str, sample))}). Track these as issues and resolve them rather "
            "than leaving reminders in the code."
        ),
        file_path=rel, line_start=sample[0],
        metadata={"marker_count": len(hits), "sample_lines": sample, "language": language},
    )


def _debug_statement_finding(file_lines: list[str], rel: str, language: str) -> Finding | None:
    if any(hint in rel.lower() for hint in _TEST_HINTS):
        return None  # tests legitimately produce console output
    pattern = _DEBUG_PATTERNS.get(language)
    if pattern is None:
        return None
    hits = [i for i, line in enumerate(file_lines, start=1) if pattern.search(line)]
    if not hits:
        return None
    sample = hits[:10]
    return Finding(
        pillar=Pillar.QUALITY, engine=Engine.QUALITY,
        rule_id="quality/leftover-debug", rule_name="Leftover debug output",
        severity=Severity.LOW,
        title=f"{len(hits)} leftover debug statement(s) in {rel}",
        description=(
            f"'{rel}' has {len(hits)} leftover debug statement(s) (e.g. console.log / "
            f"debugger, lines {', '.join(map(str, sample))}). Remove them or route through "
            "a structured logger so production output is controlled."
        ),
        file_path=rel, line_start=sample[0],
        metadata={"debug_count": len(hits), "sample_lines": sample, "language": language},
    )


def _read_lines(path: str) -> list[str]:
    try:
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            return []
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


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


# Coverage report locations we look for, in priority order, each paired with the
# parser for its format. We report a coverage number ONLY when a real report is
# found and parses; otherwise coverage is UNKNOWN (None) — never fabricated.
_COVERAGE_CANDIDATES: list[tuple[str, str]] = [
    ("coverage/coverage-summary.json", "istanbul_summary"),
    ("coverage-summary.json", "istanbul_summary"),
    ("coverage/lcov.info", "lcov"),
    ("lcov.info", "lcov"),
    ("coverage/lcov-report/lcov.info", "lcov"),
    ("coverage/cobertura-coverage.xml", "cobertura"),
    ("coverage.xml", "cobertura"),
    ("cobertura.xml", "cobertura"),
    ("coverage/cobertura.xml", "cobertura"),
    ("target/site/jacoco/jacoco.xml", "jacoco"),
    ("build/reports/jacoco/test/jacocoTestReport.xml", "jacoco"),
    ("build/reports/jacoco/jacocoTestReport.xml", "jacoco"),
    ("jacoco.xml", "jacoco"),
    ("coverage/coverage-final.json", "istanbul_final"),
    ("coverage-final.json", "istanbul_final"),
    ("coverage.json", "coveragepy_json"),
    (".coverage/coverage.json", "coveragepy_json"),
    ("htmlcov/coverage.json", "coveragepy_json"),
    ("coverage.out", "go_coverprofile"),
    ("coverage.cov", "go_coverprofile"),
]


def _coverage_percentage(root: str) -> float | None:
    """Real line/statement coverage from a shipped report, or None if unknown.

    Parses lcov, Cobertura, JaCoCo, Istanbul (summary + final), coverage.py JSON
    and Go coverprofile from their common locations. Returns None — NOT 0, NOT a
    fabricated constant — when no parseable report exists, so the composite score
    can exclude an unmeasured metric rather than punish it."""
    for rel, fmt in _COVERAGE_CANDIDATES:
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            continue
        try:
            pct = _parse_coverage_report(path, fmt)
        except Exception as exc:  # noqa: BLE001 — a malformed report must not fail a scan
            log.debug("coverage.parse_failed", path=path, fmt=fmt, error=str(exc))
            continue
        if pct is not None:
            return _clamp(pct)
    return None


def _parse_coverage_report(path: str, fmt: str) -> float | None:
    import json
    import xml.etree.ElementTree as ET

    if fmt == "istanbul_summary":
        with open(path, encoding="utf-8") as fh:
            pct = (json.load(fh).get("total", {}).get("lines", {}) or {}).get("pct")
        return float(pct) if isinstance(pct, (int, float)) else None

    if fmt == "lcov":
        lf = lh = 0
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.startswith("LF:"):
                    lf += int(line[3:].strip() or 0)
                elif line.startswith("LH:"):
                    lh += int(line[3:].strip() or 0)
        return (lh / lf * 100.0) if lf else None

    if fmt == "cobertura":
        r = ET.parse(path).getroot()
        lr = r.get("line-rate")
        if lr is not None:
            return float(lr) * 100.0
        lc, lv = r.get("lines-covered"), r.get("lines-valid")
        if lc and lv and int(lv):
            return int(lc) / int(lv) * 100.0
        return None

    if fmt == "jacoco":
        # Report-level LINE counter (direct child of <report>).
        for c in ET.parse(path).getroot().findall("counter"):
            if c.get("type") == "LINE":
                covered = int(c.get("covered", 0))
                total = covered + int(c.get("missed", 0))
                return (covered / total * 100.0) if total else None
        return None

    if fmt == "istanbul_final":
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        total = covered = 0
        for fdata in data.values():
            for hit in (fdata.get("s", {}) or {}).values():
                total += 1
                if isinstance(hit, (int, float)) and hit > 0:
                    covered += 1
        return (covered / total * 100.0) if total else None

    if fmt == "coveragepy_json":
        with open(path, encoding="utf-8") as fh:
            pct = (json.load(fh).get("totals", {}) or {}).get("percent_covered")
        return float(pct) if isinstance(pct, (int, float)) else None

    if fmt == "go_coverprofile":
        total = covered = 0
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.startswith("mode:") or not line.strip():
                    continue
                parts = line.rsplit(" ", 2)
                if len(parts) != 3:
                    continue
                try:
                    numstmt, count = int(parts[1]), int(parts[2])
                except ValueError:
                    continue
                total += numstmt
                if count > 0:
                    covered += numstmt
        return (covered / total * 100.0) if total else None

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

    # Coverage: a real % ONLY when a coverage report was parsed. If none exists,
    # coverage is UNKNOWN → None (never a fabricated 60 or a punitive 0). None is
    # excluded from the composite quality score by the orchestrator, and
    # `has_tests` carries the honest "are there tests at all" signal separately.
    test_coverage_score = round(_clamp(coverage_pct), 2) if coverage_pct is not None else None

    return QualityMetrics(
        complexity_score=round(complexity_score, 2),
        duplication_score=round(duplication_score, 2),
        maintainability_score=round(maintainability_score, 2),
        test_coverage_score=test_coverage_score,
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
            low = name.lower()
            if ".min." in low or low.endswith((".bundle.js", ".bundle.css")):
                continue  # generated/minified — not human-authored source
            _, ext = os.path.splitext(low)
            language = _EXTENSION_MAP.get(ext)
            if not language:
                continue
            path = os.path.join(dirpath, name)
            if _looks_minified(path):
                continue
            out.append((path, language))
            if len(out) >= max_files:
                return out
    return out


def _looks_minified(path: str) -> bool:
    """Cheap heuristic: files with very long lines are bundled/minified, not
    source we should assess for quality or duplication."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            head = fh.read(20_000)
    except OSError:
        return False
    if not head:
        return False
    lines = head.splitlines() or [head]
    longest = max((len(line) for line in lines), default=0)
    avg = sum(len(line) for line in lines) / len(lines)
    return longest > 2000 or avg > 300
