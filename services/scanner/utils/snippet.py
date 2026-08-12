"""Inline code snippet + stable finding fingerprint (P1a/P1c).

Two responsibilities, sharing one file read:

  * ``code_snippet`` — the flagged line(s) plus a couple of context lines, shown
    inline for EVERY finding type (SCA, secrets, quality, IaC — not just taint).
  * ``fingerprint`` — a deterministic, line-shift-resilient identity for a
    finding, so the lifecycle tracker can tell "same finding" from "new finding"
    across scans. It hashes the rule + file + *normalized flagged code* (never
    the raw line number), so a finding that moved down because code was inserted
    above it keeps the same fingerprint.

Precision-first: every function is best-effort. If a file can't be read or a
finding has no line, the snippet is omitted and the fingerprint falls back to a
still-deterministic rule+file(+cve) basis. Nothing here ever raises into a scan.
"""
from __future__ import annotations

import hashlib
import os
import re

from logging_config import get_logger
from models.scan_result import Finding

log = get_logger("snippet")

_CONTEXT = 2          # lines of context shown before/after the flagged line
_MAX_SNIPPET_LINES = 12
_MAX_LINE_LEN = 400
_WS = re.compile(r"\s+")
# A run of secret-like characters (base64 / hex / token bodies). For secret
# findings the snippet is redacted so we show the offending line WITHOUT
# persisting the plaintext secret (matching how Snyk / GitGuardian display it).
_SECRET_RUN = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")
# Unit separator — safe join char that won't appear in code, keeps basis fields
# unambiguous so distinct findings can't accidentally collide.
_SEP = "\x1f"

# Bounded per-scan cache of file line lists, keyed by absolute path. A scan reads
# the same handful of vulnerable files many times (one finding per line); caching
# keeps snippet extraction from re-reading them.
_FileCache = dict[str, list[str] | None]


def attach(findings: list[Finding], root: str) -> None:
    """Attach code_snippet + fingerprint to every finding, in place. Best-effort."""
    cache: _FileCache = {}
    # Ordinal disambiguation: two findings with an identical (rule, file, code)
    # basis (e.g. the same vulnerable call duplicated on two lines) get a stable
    # per-basis ordinal so their fingerprints differ deterministically. Ordering
    # by line keeps ordinals stable when the whole block shifts together.
    basis_counts: dict[str, int] = {}
    for f in sorted(findings, key=lambda x: (x.file_path or "", x.line_start or 0)):
        try:
            lines = _read(cache, root, f.file_path)
            flagged = _normalized_flagged(lines, f.line_start, f.line_end)
            if lines is not None and f.line_start:
                snippet, start = _snippet(lines, f.line_start, f.line_end)
                if _is_secret(f):
                    snippet = _redact(snippet)
                f.code_snippet = snippet
                f.snippet_start_line = start
            basis = _basis(f, flagged)
            ordinal = basis_counts.get(basis, 0)
            basis_counts[basis] = ordinal + 1
            f.fingerprint = _hash(basis, ordinal)
        except Exception as exc:  # noqa: BLE001 — snippet/fingerprint never fail a scan
            log.debug("snippet.attach_failed", rule_id=getattr(f, "rule_id", "?"), error=str(exc))
            if not f.fingerprint:
                f.fingerprint = _hash(_basis(f, ""), 0)


def _read(cache: _FileCache, root: str, file_path: str) -> list[str] | None:
    if not file_path:
        return None
    abs_path = file_path if os.path.isabs(file_path) else os.path.join(root or "", file_path)
    if abs_path in cache:
        return cache[abs_path]
    data: list[str] | None = None
    try:
        if os.path.isfile(abs_path) and os.path.getsize(abs_path) <= 5_000_000:
            with open(abs_path, encoding="utf-8", errors="replace") as fh:
                data = fh.read().splitlines()
    except Exception:  # noqa: BLE001
        data = None
    cache[abs_path] = data
    return data


def _snippet(lines: list[str], line_start: int, line_end: int | None) -> tuple[str, int]:
    """The flagged line(s) + _CONTEXT lines around them, as text. 1-based lines."""
    end = line_end or line_start
    if end < line_start:
        end = line_start
    lo = max(1, line_start - _CONTEXT)
    hi = min(len(lines), end + _CONTEXT)
    if hi - lo + 1 > _MAX_SNIPPET_LINES:
        hi = lo + _MAX_SNIPPET_LINES - 1
    out = [ln[:_MAX_LINE_LEN] for ln in lines[lo - 1:hi]]
    return "\n".join(out), lo


def _normalized_flagged(lines: list[str] | None, line_start: int | None, line_end: int | None) -> str:
    """The flagged line(s) with whitespace normalized — the fingerprint's code
    component. Whitespace-insensitive so reformatting/indent changes (e.g. code
    moving into a block) don't spuriously re-key the finding."""
    if not lines or not line_start:
        return ""
    end = line_end or line_start
    if end < line_start:
        end = line_start
    picked = lines[line_start - 1:end][:_MAX_SNIPPET_LINES]
    norm = [_WS.sub(" ", ln).strip() for ln in picked]
    return " ".join(p for p in norm if p)


def _basis(f: Finding, flagged: str) -> str:
    """Stable fingerprint basis: rule + file (+cve for SCA) + normalized code.
    Deliberately excludes the line number so the id survives line shifts."""
    parts = [f.rule_id or "", f.file_path or ""]
    if f.cve_id:
        parts.append(f.cve_id)
    parts.append(flagged)
    return _SEP.join(parts)


def _is_secret(f: Finding) -> bool:
    eng = f.engine.value if hasattr(f.engine, "value") else str(f.engine)
    return eng == "gitleaks"


def _redact(text: str) -> str:
    """Mask secret-like runs, keeping a 4-char prefix so the line stays readable
    but the plaintext secret is never persisted."""
    def mask(m: "re.Match[str]") -> str:
        s = m.group(0)
        return s[:4] + "…REDACTED" if len(s) > 8 else "…REDACTED"
    return _SECRET_RUN.sub(mask, text)


def _hash(basis: str, ordinal: int) -> str:
    h = hashlib.sha256(f"{basis}{_SEP}{ordinal}".encode("utf-8", errors="replace"))
    return h.hexdigest()[:32]
