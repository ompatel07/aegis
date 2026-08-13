"""EPSS (Exploit Prediction Scoring System) scores (P2b).

EPSS (first.org) gives each CVE a probability [0,1] that it will be exploited in
the next 30 days, plus a percentile rank among all CVEs. It complements CISA KEV:
KEV = *confirmed* actively exploited (binary), EPSS = *probability* of exploitation
(continuous) — together they let a user triage the long tail of "high CVSS but
who's actually attacking it?".

Unlike KEV (~1.6k entries, fully preloadable), EPSS covers ~280k CVEs, so we query
on demand: collect a scan's CVE IDs and batch-fetch just those from the API, with a
24 h per-CVE cache (EPSS refreshes daily). Best-effort — a fetch failure just means
findings carry no EPSS field; a scan never fails over it.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.parse
import urllib.request

from logging_config import get_logger

log = get_logger("epss")

_API = "https://api.first.org/data/v1/epss"
_TIMEOUT = 20
_TTL = 24 * 3600           # EPSS updates daily
_BATCH = 90                # CVEs per request (keep the URL well under limits)

_lock = threading.Lock()
_cache: dict[str, tuple[dict, float]] = {}   # CVE -> (info, fetched_at)


def scores_for(cve_ids: list[str]) -> dict[str, dict]:
    """Return {CVE: {epss_score, epss_percentile}} for the given CVEs. Served from
    cache where fresh; missing/stale CVEs are batch-fetched. Best-effort: CVEs that
    can't be fetched (or that EPSS doesn't score) are simply absent from the result.
    """
    out: dict[str, dict] = {}
    stale: list[str] = []
    now = time.time()
    seen: set[str] = set()
    for raw in cve_ids:
        cve = (raw or "").strip().upper()
        if not cve or cve in seen:
            continue
        seen.add(cve)
        cached = _cache.get(cve)
        if cached and (now - cached[1]) < _TTL:
            if cached[0]:
                out[cve] = cached[0]
        else:
            stale.append(cve)

    for i in range(0, len(stale), _BATCH):
        _fetch_batch(stale[i:i + _BATCH], out)
    return out


def _fetch_batch(cves: list[str], out: dict[str, dict]) -> None:
    if not cves:
        return
    url = _API + "?" + urllib.parse.urlencode({"cve": ",".join(cves), "pretty": "false"})
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "aegis-scanner"})
        data = json.loads(urllib.request.urlopen(req, timeout=_TIMEOUT).read())
    except Exception as exc:  # noqa: BLE001 — never fail a scan over EPSS
        log.warning("epss.fetch_failed", count=len(cves), error=str(exc))
        return
    found: dict[str, dict] = {}
    for e in data.get("data", []) or []:
        cve = (e.get("cve") or "").strip().upper()
        if not cve:
            continue
        try:
            info = {
                "epss_score": round(float(e.get("epss")), 6),
                "epss_percentile": round(float(e.get("percentile")), 6),
            }
        except (TypeError, ValueError):
            continue
        found[cve] = info
    now = time.time()
    with _lock:
        # Cache hits AND misses: a CVE EPSS doesn't score is cached as {} so we
        # don't re-query it every scan.
        for cve in cves:
            info = found.get(cve, {})
            _cache[cve] = (info, now)
            if info:
                out[cve] = info


def epss_info(cve_id: str | None) -> dict:
    """Single-CVE convenience lookup (uses the same cache)."""
    if not cve_id:
        return {}
    return scores_for([cve_id]).get(cve_id.strip().upper(), {})
