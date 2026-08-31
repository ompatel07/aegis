"""Separate secret findings by what a signal actually MEANS (precision passes S1, P1).

Validation V1 found ~500 of 630 secret findings were test fixtures, `.env.example`
placeholders, or expired JWTs — none of them live credentials, yet all reported
CRITICAL, which drowned the real ones and corrupted every downstream severity count.
S1 down-ranked all three to LOW. But a down-ranked false positive is still a false
positive. P1 splits them by what they DEFINITIVELY are:

  1. placeholder  — the value is definitively NOT a credential (repeated char,
                    changeme/your-*/xxx/<...>/${...}/example/dummy/…, entropy < 3.0).
                    SUPPRESSED from findings; counted in the returned stats.
  2. expired JWT  — the exp claim is in the past, so the token is definitively
                    unusable. SUPPRESSED from findings; counted.
  3. documentation path — a key in an API-doc example (.md/.mdx/.rst, docs/, …) is
                    closer to a placeholder, but docs occasionally paste a real key
                    by mistake. DOWN-RANKED to LOW + tagged `documentation` (P2).
  4. test-fixture path — a real credential CAN be committed to a test file, so this
                    is only a prior, not proof. KEPT, capped at LOW and tagged
                    `secret_context=test-fixture` so a human still triages it. This
                    is the S1 behaviour, deliberately UNCHANGED.

`annotate` returns a stats dict — {"placeholder": n, "expired_jwt": n} — so the scan
can report "N placeholder matches filtered / M expired JWTs filtered" instead of
silently dropping them. Suppression is auditable, not invisible.

MANDATORY OVERRIDE: a value matching a known live-format provider credential (AWS
AKIA, GitHub ghp_, Stripe sk_live_, a real PEM key body, …) is NEVER suppressed or
down-ranked, in any path — checked first, wins over every other signal. An AWS key
in testdata/ is a real leak.

JWTs: the exp check governs them. Expired ⇒ suppressed anywhere. A JWT with a
future/absent/undecodable exp could be live, so it is treated like any other secret
— the fixture-path prior can cap it to LOW, but outside a fixture path it stays at
full severity.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
import time

from logging_config import get_logger
from models.scan_result import SEVERITY_ORDER, Finding, Severity

log = get_logger("secret_context")

# ── which findings this applies to ───────────────────────────────────────────
# gitleaks secrets, plus the SAST detected-bcrypt-hash rule (seeded hashes in
# database/factories/*). Scoped deliberately narrow.
_BCRYPT_RULE = "detected-bcrypt-hash"


def _is_secret_finding(f: Finding) -> bool:
    rid = (f.rule_id or "").lower()
    return f.engine.value == "gitleaks" or _BCRYPT_RULE in rid


# ── signal 1: fixture / example path prior ───────────────────────────────────
_FIXTURE_PATH = re.compile(
    r"(?ix)"
    r"( _test\.| \.test\. | _spec\. | \.spec\. "
    r"| (^|/)(test|tests|spec|specs|fixtures?|factories|mocks?|__mocks__"
    r"|testdata|seeds?|examples?|sample|samples|e2e|cypress)(/|$) "
    r"| \.example($|\.) | \.sample($|\.) | \.template($|\.) "
    r"| (^|/)\.env\.(example|sample|template|local|dist)(\.|$) )"
)


def _in_fixture_path(path: str | None) -> bool:
    return bool(path) and bool(_FIXTURE_PATH.search(path.replace("\\", "/")))


# ── signal 1b: documentation path prior (P2) ─────────────────────────────────
# A key in an API-doc example (`token: "sk_..."` in a .mdx) is closer to a
# placeholder than to a fixture secret — V1 found ≥23 such generic-api-key matches
# in documentation that the fixture prior missed. We DOWN-RANK (not suppress): docs
# occasionally paste a real key by mistake, so a human should still see it at LOW.
_DOC_PATH = re.compile(
    r"(?ix)"
    r"( \.md($|\.) | \.mdx($|\.) | \.rst($|\.) | \.adoc($|\.) | \.ipynb($|\.) "
    r"| (^|/)(docs?|documentation|website|guide|guides|handbook|wiki)(/) "
    r"| (^|/)[^/]*/docs?/ )"
)


def _in_doc_path(path: str | None) -> bool:
    return bool(path) and bool(_DOC_PATH.search(path.replace("\\", "/")))


# ── signal 2: placeholder shape ──────────────────────────────────────────────
_PLACEHOLDER_TOKENS = re.compile(
    r"(?i)(change[-_ ]?me|change[-_ ]?this|your[-_].*|my[-_]secret|xxx+|"
    r"example|dummy|placeholder|sample|redacted|foobar|test[-_]?(key|token|secret)|"
    r"<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|not[-_]?a[-_]?real|todo|fixme)"
)


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_placeholder(value: str, entropy: float | None) -> bool:
    if not value:
        return False
    v = value.strip().strip("'\"")
    if not v:
        return False
    # all one repeated character (e.g. "aaaaaaaa", "00000000")
    if len(v) >= 6 and len(set(v)) == 1:
        return True
    if _PLACEHOLDER_TOKENS.search(v):
        return True
    # low information content — placeholders / connection templates read as prose,
    # real tokens do not. Use gitleaks' own entropy when present, else compute it.
    ent = entropy if isinstance(entropy, (int, float)) else _shannon(v)
    if len(v) >= 8 and ent < 3.0:
        return True
    return False


# ── signal 3: expired-JWT check ──────────────────────────────────────────────
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _jwt_exp_status(value: str) -> str:
    """'expired' | 'live' | 'unknown'. Decodes the payload and reads `exp`.
    Malformed / undecodable / no-exp => 'unknown' (never down-rank on a guess)."""
    if not value:
        return "unknown"
    m = _JWT_RE.search(value)
    if not m:
        return "unknown"
    parts = m.group(0).split(".")
    if len(parts) < 2:
        return "unknown"
    payload = parts[1]
    try:
        pad = "=" * (-len(payload) % 4)
        data = base64.urlsafe_b64decode(payload + pad)
        claims = json.loads(data)
    except (binascii.Error, ValueError, json.JSONDecodeError):
        return "unknown"
    if not isinstance(claims, dict) or "exp" not in claims:
        return "unknown"
    try:
        exp = float(claims["exp"])
    except (TypeError, ValueError):
        return "unknown"
    return "expired" if exp < time.time() else "live"


# ── mandatory override: known live-format provider credentials ───────────────
_PROVIDER_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("stripe-key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("openai-key", re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b|\bsk-[A-Za-z0-9]{48}\b")),
    ("twilio-key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi-token", re.compile(r"\bpypi-[A-Za-z0-9_\-]{16,}\b")),
]
# a PEM block with an ACTUAL key body (>=1 long base64 line, not just the header)
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?[A-Za-z0-9+/=]{40,}", re.MULTILINE
)


def _provider_key(value: str) -> str | None:
    if not value:
        return None
    for name, pat in _PROVIDER_PATTERNS:
        if pat.search(value):
            return name
    if _PEM_RE.search(value):
        return "private-key-pem"
    return None


def _lines_of(meta: dict) -> str:
    v = meta.get("lines")
    return str(v) if v else ""


def _tag(f: Finding, context: str, reason: str) -> None:
    """Tag a finding's context without changing severity — used for the suppressed
    (placeholder / expired) findings, which are about to be removed but are tagged
    first so a caller holding a reference can see why."""
    if not isinstance(f.metadata, dict):
        f.metadata = {}
    f.metadata["secret_context"] = context
    f.metadata["secret_context_reason"] = reason


def _cap_low(f: Finding, context: str, reason: str) -> None:
    # SEVERITY_ORDER: lower rank = more severe (CRITICAL=0 … LOW=3). Cap only when
    # the finding is currently MORE severe than LOW.
    if SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[Severity.LOW]:
        f.severity = Severity.LOW
    _tag(f, context, reason)


def _redact(value: str) -> str:
    """Mask a secret for storage — reveal only a short identifying prefix (AKIA,
    ghp_, eyJ…) + length, never the body. gitleaks runs WITHOUT --redact so we can
    classify; this is where the value is scrubbed before it is stored anywhere.
    THE single redaction implementation — do not add another."""
    if not value:
        return ""
    v = value.strip()
    return (v[:4] + "…[" + str(len(v)) + "c]") if len(v) > 8 else "***"


def annotate(findings: list[Finding]) -> dict[str, int]:
    """Classify secret findings in place and return a stats dict of what was
    SUPPRESSED — {"placeholder": n, "expired_jwt": n}.

    Placeholder-shaped and expired-JWT findings are definitively not live
    credentials, so they are removed from `findings` (mutated in place) and counted.
    A test-fixture-path secret MIGHT be real, so it is kept, capped at LOW, and
    tagged. A live-format provider credential is never touched — checked first."""
    stats = {"placeholder": 0, "expired_jwt": 0}
    suppressed: set[int] = set()  # id() of findings to drop after the loop

    for f in findings:
        if not _is_secret_finding(f):
            continue
        meta = f.metadata if isinstance(f.metadata, dict) else {}
        value = str(meta.get("match") or f.code_snippet or _lines_of(meta) or "")
        entropy = meta.get("entropy")

        try:
            # mandatory override — a real provider credential wins over every other
            # signal, in any path. Never suppressed, never down-ranked.
            prov = _provider_key(value)
            if prov:
                if isinstance(f.metadata, dict):
                    f.metadata["secret_context"] = "live-format"
                    f.metadata["secret_context_reason"] = f"matches {prov} live format"
                continue

            rid = (f.rule_id or "").lower()
            # Expired JWT: definitively unusable (exp in the past) → SUPPRESS anywhere.
            if "jwt" in rid and _jwt_exp_status(value) == "expired":
                _tag(f, "expired", "JWT exp claim is in the past — cannot be live")
                suppressed.add(id(f))
                stats["expired_jwt"] += 1
                continue

            # Placeholder shape: definitively not a credential → SUPPRESS.
            if _is_placeholder(value, entropy):
                _tag(f, "placeholder", "value has placeholder shape / low entropy")
                suppressed.add(id(f))
                stats["placeholder"] += 1
                continue

            # Documentation path: an API-doc example key is closer to a placeholder,
            # but docs occasionally hold a real key by mistake → DOWN-RANK, not
            # suppress (P2). Checked before the fixture prior so docs read as "docs".
            if _in_doc_path(f.file_path):
                _cap_low(f, "documentation", "secret sits in a documentation/example path")
            # Test-fixture path: only a prior — a real secret can live in a test file.
            # KEEP at LOW + tag so a human still triages it (S1 behaviour, unchanged).
            elif _in_fixture_path(f.file_path):
                _cap_low(f, "test-fixture", "secret sits in a test/fixture/example path")
        except Exception as exc:  # noqa: BLE001 — one finding must not stop the rest
            log.debug("secret_context.classify_failed", rule_id=f.rule_id, error=str(exc))
        # NOTE: no redaction here. The plaintext value stays on the in-memory finding
        # (match / code_snippet) and is scrubbed at the single egress chokepoint
        # (EngineResult serialization -> enrichment.egress).

    if suppressed:
        findings[:] = [f for f in findings if id(f) not in suppressed]
    return stats
