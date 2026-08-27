"""Scan-scoped plaintext secret VALUES, held only in memory for the egress
value-scrub (enrichment.egress). Populated by the engines that actually recover a
value (gitleaks; trivy's secret scanner if enabled), keyed by scan_id.

NEVER persisted, NEVER logged. Entries expire on a TTL — a scan's several engine
requests all land within it — and the store is size-bounded, so a value cannot
outlive its scan or accumulate unbounded. This is the only place raw secret values
live across the scanner's per-engine requests, and they exist solely to be scrubbed
back out at egress.
"""
from __future__ import annotations

import threading
import time

_LOCK = threading.Lock()
_TTL_SECONDS = 3600          # one scan's engine calls all land well within an hour
_MAX_SCANS = 512             # bound the store
_MIN_LEN = 4                 # ignore trivially short "values"

# scan_id -> (last_touch_epoch, {values})
_store: dict[str, tuple[float, set[str]]] = {}


def record(scan_id: str | None, values) -> None:
    if not scan_id:
        return
    vals = {v for v in values if isinstance(v, str) and len(v) >= _MIN_LEN}
    if not vals:
        return
    with _LOCK:
        _purge_locked()
        _, existing = _store.get(scan_id, (0.0, set()))
        existing |= vals
        _store[scan_id] = (time.time(), existing)


def values(scan_id: str | None) -> set[str]:
    if not scan_id:
        return set()
    with _LOCK:
        _purge_locked()
        entry = _store.get(scan_id)
        return set(entry[1]) if entry else set()


def all_values() -> set[str]:
    """Union of every live scan's values. Used when a result has no scan_id (e.g. a
    failed EngineResult) and by the log-path scrub, where exact-string replacement
    makes over-scrubbing harmless."""
    with _LOCK:
        _purge_locked()
        out: set[str] = set()
        for _, vs in _store.values():
            out |= vs
        return out


def drop(scan_id: str | None) -> None:
    if not scan_id:
        return
    with _LOCK:
        _store.pop(scan_id, None)


def _purge_locked() -> None:
    now = time.time()
    for k in [k for k, (ts, _) in _store.items() if now - ts > _TTL_SECONDS]:
        _store.pop(k, None)
    if len(_store) > _MAX_SCANS:  # drop oldest
        for k in sorted(_store, key=lambda k: _store[k][0])[: len(_store) - _MAX_SCANS]:
            _store.pop(k, None)
