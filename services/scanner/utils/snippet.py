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
# For secret findings the snippet is redacted so we show the offending line WITHOUT
# persisting the plaintext secret (matching how Snyk / GitGuardian display it).
# Three layers, all masked via the single secret_context._redact:
#   1. a token-shaped run (base64 / hex / token body)
_SECRET_RUN = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")
#   2. an assignment RHS: password/token/api_key/... = "value"  (catches
#      non-token-shaped secrets like `DB_PASSWORD = "summer2024"` that layer 1 misses)
_ASSIGN_SECRET = re.compile(
    r"""(?ix)
    ( (?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key
        |client[_-]?secret|auth[_-]?token|credentials?|private[_-]?key)
      \s*[:=]\s* )
    ( "[^"\n]{3,}" | '[^'\n]{3,}' | [^\s"'(){}\[\];,]{3,} )
    """
)
#   3. the credential segment of a URI: scheme://user:PASSWORD@host
_URI_CRED = re.compile(r"(?i)([a-z][a-z0-9+.\-]*://[^\s:@/]+:)([^@\s/]{1,})(@)")

# A finding needs snippet redaction if it exposes a credential. Capability check,
# not an engine check — semgrep rules that flag hardcoded creds (node_secret,
# node_password, detected-bcrypt-hash, detected-jwt-token, hardcoded-*, …, and any
# CWE-798/259 rule) leak their raw source line otherwise. Hints grounded in the
# rule ids actually present in the Validation V1 corpus.
_SECRET_RULE_HINTS = (
    "secret", "password", "passwd", "pwd", "credential", "token", "api-key",
    "api_key", "apikey", "access-key", "access_key", "private-key", "private_key",
    "jwt", "bcrypt", "hardcoded",
)
_SECRET_CWES = {"798", "259"}  # CWE-798 hardcoded creds, CWE-259 hardcoded password
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
                # NOTE: redaction is NOT done here. Secret snippets/lines are held
                # in memory and scrubbed at the single egress chokepoint
                # (EngineResult serialization -> enrichment.egress), so no engine can
                # emit plaintext regardless of whether it ran this enrichment.
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


def is_secret_capability(engine: str, rule_id: str, cwe_id: str, category: str) -> bool:
    """Capability check: does this finding expose a credential (so its line text must
    be redacted)? True for gitleaks, for any rule id naming a secret, and for
    CWE-798/259 — NOT an engine check (semgrep credential rules leak otherwise).
    Works from primitives so both Finding objects and serialized dicts can use it."""
    if (engine or "").lower() == "gitleaks":
        return True
    rid = (rule_id or "").lower()
    if any(h in rid for h in _SECRET_RULE_HINTS):
        return True
    cwe = "".join(ch for ch in (cwe_id or "") if ch.isdigit())
    if cwe in _SECRET_CWES:
        return True
    return "secret" in (category or "").lower()


def _is_secret(f: Finding) -> bool:
    eng = f.engine.value if hasattr(f.engine, "value") else str(f.engine)
    meta = f.metadata if isinstance(f.metadata, dict) else {}
    return is_secret_capability(eng, f.rule_id or "", f.cwe_id or "",
                                str(meta.get("category") or ""))


def is_secret_dict(d: dict) -> bool:
    """Same check over a serialized finding/result dict (used by the egress
    chokepoint). Tolerates gitleaks/semgrep raw key spellings."""
    if not isinstance(d, dict):
        return False
    engine = d.get("engine") or ""
    rule = d.get("rule_id") or d.get("RuleID") or d.get("check_id") or d.get("CheckID") or ""
    cwe = d.get("cwe_id") or ""
    if not cwe:
        cwes = d.get("CweIDs") or d.get("cwe") or []
        cwe = (cwes[0] if isinstance(cwes, list) and cwes else str(cwes or ""))
    meta = d.get("metadata") if isinstance(d.get("metadata"), dict) else {}
    return is_secret_capability(str(engine), str(rule), str(cwe),
                                str(meta.get("category") or ""))


def _mask(s: str) -> str:
    """The one masker — delegates to secret_context._redact (single impl)."""
    from enrichment.secret_context import _redact as _sc_redact
    return _sc_redact(s)


# Metadata keys that carry raw source text and therefore the secret: semgrep puts
# the matched line in `lines`; other engines use these too. The egress chokepoint
# shape-scrubs these inside secret-ish subtrees.
_META_LINE_KEYS = ("lines", "line", "code", "snippet", "matched", "context")


def _redact(text: str, value: str | None = None) -> str:
    """Scrub a snippet, keeping surrounding code readable. Layered:
      a) value-based (primary): if the exact secret value is known (gitleaks),
         replace just that string — surgical, no heuristics.
      b) regex (fallback): assignment RHS, URI credential segment, and token-shaped
         runs — covers findings with no value (the semgrep credential rules) and
         non-token-shaped secrets (`password = "hunter2"`).
    Only secret-shaped substrings are masked; the rest of the line survives."""
    out = text
    if value and len(value) >= 3 and value in out:
        out = out.replace(value, _mask(value))

    def _assign(m: "re.Match[str]") -> str:
        rhs = m.group(2)
        quote = rhs[0] if rhs[:1] in "\"'" and rhs[-1:] == rhs[:1] else ""
        body = rhs[1:-1] if quote else rhs
        # skip env lookups / function calls — not literal secrets
        if not body or "(" in body or body.lower().startswith(("os.", "process.", "env.")):
            return m.group(0)
        return m.group(1) + quote + _mask(body) + quote

    out = _ASSIGN_SECRET.sub(_assign, out)
    out = _URI_CRED.sub(lambda m: m.group(1) + _mask(m.group(2)) + m.group(3), out)
    out = _SECRET_RUN.sub(lambda m: _mask(m.group(0)), out)
    return out


def _hash(basis: str, ordinal: int) -> str:
    h = hashlib.sha256(f"{basis}{_SEP}{ordinal}".encode("utf-8", errors="replace"))
    return h.hexdigest()[:32]
