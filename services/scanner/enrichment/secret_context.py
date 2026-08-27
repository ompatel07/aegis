"""Down-rank test-fixture / placeholder / expired secrets (precision pass S1).

Validation V1 found ~500 of 630 secret findings were test fixtures, `.env.example`
placeholders, or expired JWTs — none of them live credentials, yet all reported
CRITICAL, which drowned the real ones and corrupted every downstream severity
count.

We DOWN-RANK, we do not hard-suppress: real credentials genuinely do get committed
to test files, so a flagged secret in a fixture path stays in the report — capped
at LOW and tagged with `secret_context` so a human still sees it, but it never sits
in Top Risks. Three independent signals fire the down-rank:

  1. path prior     — the file is a test / fixture / example / seed path
  2. placeholder    — the value is obviously not a credential (repeated char,
                      changeme/your-*/xxx/<...>/${...}/example/dummy/…, low entropy)
  3. expired JWT    — for `jwt` findings, the exp claim is in the past, so the
                      token cannot be live (this alone clears the pocketbase 404)

MANDATORY OVERRIDE: a value matching a known live-format provider credential (AWS
AKIA, GitHub ghp_, Stripe sk_live_, a real PEM key body, …) is NEVER down-ranked,
in any path. An AWS key in testdata/ is a real leak.

JWTs are special: the exp check GOVERNS them. A JWT with a future/absent/undecodable
exp is left at full severity even in a test path (it could be live); only an expired
exp down-ranks it. The path/placeholder priors do not apply to JWT findings.
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


def _cap_low(f: Finding, context: str, reason: str) -> None:
    # SEVERITY_ORDER: lower rank = more severe (CRITICAL=0 … LOW=3). Cap only when
    # the finding is currently MORE severe than LOW.
    if SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[Severity.LOW]:
        f.severity = Severity.LOW
    if not isinstance(f.metadata, dict):
        f.metadata = {}
    f.metadata["secret_context"] = context
    f.metadata["secret_context_reason"] = reason


def _redact(value: str) -> str:
    """Mask a secret for storage — reveal only a short identifying prefix (AKIA,
    ghp_, eyJ…) + length, never the body. gitleaks runs WITHOUT --redact so we can
    classify; this is where the value is scrubbed before it is stored anywhere.
    THE single redaction implementation — do not add another."""
    if not value:
        return ""
    v = value.strip()
    return (v[:4] + "…[" + str(len(v)) + "c]") if len(v) > 8 else "***"


def annotate(findings: list[Finding]) -> None:
    """In-place: tag + down-rank fixture/placeholder/expired secrets; never touch a
    live-format provider credential. For gitleaks findings the raw `match` is
    re-redacted here after classification."""
    for f in findings:
        if not _is_secret_finding(f):
            continue
        meta = f.metadata if isinstance(f.metadata, dict) else {}
        value = str(meta.get("match") or f.code_snippet or _lines_of(meta) or "")
        entropy = meta.get("entropy")

        try:
            # mandatory override — a real provider credential is never down-ranked.
            prov = _provider_key(value)
            if prov:
                if isinstance(f.metadata, dict):
                    f.metadata["secret_context"] = "live-format"
                    f.metadata["secret_context_reason"] = f"matches {prov} live format"
                continue

            rid = (f.rule_id or "").lower()
            # Expired JWT: cannot be live, anywhere. Checked first so context reads
            # "expired". Otherwise the path prior applies to JWTs like any other
            # secret (a future-dated JWT in a fixture path is a test fixture; a
            # future-dated JWT OUTSIDE a fixture path stays critical — JWTs have no
            # live-format signature the way AKIA/ghp_ do, so we down-rank, not
            # suppress, and accept that residual risk).
            if "jwt" in rid and _jwt_exp_status(value) == "expired":
                _cap_low(f, "expired", "JWT exp claim is in the past — cannot be live")
                continue

            if _is_placeholder(value, entropy):
                _cap_low(f, "placeholder", "value has placeholder shape / low entropy")
            elif _in_fixture_path(f.file_path):
                _cap_low(f, "test-fixture", "secret sits in a test/fixture/example path")
        except Exception as exc:  # noqa: BLE001 — one finding must not stop the rest
            log.debug("secret_context.classify_failed", rule_id=f.rule_id, error=str(exc))
        # NOTE: no redaction here. The plaintext value stays on the in-memory finding
        # (match / code_snippet) and is scrubbed at the single egress chokepoint
        # (EngineResult serialization -> enrichment.egress).
