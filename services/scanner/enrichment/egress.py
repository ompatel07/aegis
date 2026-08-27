"""THE redaction chokepoint.

Every EngineResult is scrubbed here, at serialization (see EngineResult's
model_serializer), so no engine can emit plaintext — including engines we have not
thought of yet, and ones added later. Redaction is a boundary guarantee, not a
per-engine responsibility (see PRECISION_S1.md for why: four carriers were found
one at a time, each fix scoped to one engine while the same defect sat in the next).

Two mechanisms, applied to the whole serialized tree (raw, findings, metadata,
deployment_report, nested dicts/lists):

  VALUE scrub (primary): replace every KNOWN secret value (recovered by gitleaks /
    trivy's secret scanner, held scan-scoped in secret_registry) with its redacted
    form. Exact-string → zero false masking; covers every field of every engine.

  SHAPE scrub (secondary): inside a secret-ish finding/result, regex-redact the
    line-carrying fields (code_snippet, metadata.lines, gitleaks Match, semgrep
    extra.lines, deployment output) — for values we never held (the semgrep cases).
"""
from __future__ import annotations

from enrichment import secret_registry
from utils import snippet

# keys whose value is raw source / tool line text (shape-scrubbed inside secret-ish
# subtrees). Superset of snippet._META_LINE_KEYS plus egress-only carriers.
_LINE_KEYS = set(snippet._META_LINE_KEYS) | {
    "match", "Match", "code_snippet", "output", "output_tail", "abstract_content",
}


def scrub(data: dict, scan_id: str | None) -> dict:
    """In-place scrub of a serialized EngineResult dict.

    FAILS CLOSED: if the full walk raises, we make ONE genuine second attempt
    (flat value-scrub); if THAT also raises, we re-raise. A leaked credential is
    unrecoverable, so redaction failure must never return the payload — the caller
    (EngineResult serializer) turns a raise here into a withheld, failed result.
    A None scan_id falls back to every live value, never to an empty set."""
    live = secret_registry.values(scan_id) if scan_id else secret_registry.all_values()
    vals = sorted((v for v in live if v), key=len, reverse=True)
    try:
        _walk(data, vals, secretish=False, shape=False)
    except Exception:  # noqa: BLE001 — one genuine retry, then fail closed
        _flat_value_scrub(data, vals)  # if this raises too, it propagates → fail closed
    return data


def _value_scrub(s: str, vals: list[str]) -> str:
    for v in vals:
        if v in s:
            s = s.replace(v, snippet._mask(v))
    return s


def _walk(node, vals: list[str], secretish: bool, shape: bool) -> None:
    if isinstance(node, dict):
        sub = secretish or snippet.is_secret_dict(node)
        for k, v in list(node.items()):
            sh = sub and k in _LINE_KEYS  # this key carries source/tool line text
            if isinstance(v, str):
                nv = _value_scrub(v, vals)
                if sh:
                    nv = snippet._redact(nv)
                node[k] = nv
            else:
                _walk(v, vals, sub, sh)  # carry the line-key context into subtrees
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str):
                nv = _value_scrub(v, vals)
                if shape:  # a list UNDER a line-key (e.g. lines: [..]) — shape-scrub
                    nv = snippet._redact(nv)
                node[i] = nv
            else:
                _walk(v, vals, secretish, shape)


def _flat_value_scrub(node, vals: list[str]) -> None:
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if isinstance(v, str):
                node[k] = _value_scrub(v, vals)
            else:
                _flat_value_scrub(v, vals)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str):
                node[i] = _value_scrub(v, vals)
            else:
                _flat_value_scrub(v, vals)
