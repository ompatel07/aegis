"""CISA KEV (Known Exploited Vulnerabilities) catalog (P1b).

A CVE appearing on CISA's KEV list means it is being **actively exploited in the
wild** — the single strongest triage signal there is, stronger than CVSS alone.
We flag any SCA/CVE finding whose CVE is on the list with a prominent marker + the
date CISA added it, and weight it up in prioritization/scoring.

The catalog is a single free, authoritative JSON feed (~1 MB, ~1.6k entries). It's
fetched into an in-memory map on boot and refreshed on the same cadence as the
CVE-intelligence feeds (see main.py). Every lookup is O(1); every network op is
best-effort — if the feed is unreachable, findings simply carry no KEV flag (we
never fail a scan over enrichment data).
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request

from logging_config import get_logger

log = get_logger("kev")

_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_TIMEOUT = 30
_STALE_AFTER = 6 * 3600  # refresh cadence (matches the CVE-intel / trivy-DB loops)

_lock = threading.Lock()
_catalog: dict[str, dict] = {}   # CVE-ID -> {date_added, name, ransomware, description}
_loaded_at: float = 0.0
_catalog_version: str = ""


def refresh(force: bool = False) -> int:
    """Fetch the KEV catalog into memory. Best-effort; returns entry count (or the
    current count if the fetch fails). Thread-safe; skips if recently refreshed."""
    global _catalog, _loaded_at, _catalog_version
    with _lock:
        if not force and _catalog and (time.time() - _loaded_at) < _STALE_AFTER:
            return len(_catalog)
        try:
            req = urllib.request.Request(_FEED_URL, headers={"User-Agent": "aegis-scanner"})
            data = json.loads(urllib.request.urlopen(req, timeout=_TIMEOUT).read())
        except Exception as exc:  # noqa: BLE001 — never fail a scan over KEV
            log.warning("kev.refresh_failed", error=str(exc))
            return len(_catalog)
        built: dict[str, dict] = {}
        for v in data.get("vulnerabilities", []) or []:
            cve = (v.get("cveID") or "").strip().upper()
            if not cve:
                continue
            built[cve] = {
                "date_added": v.get("dateAdded"),
                "name": v.get("vulnerabilityName"),
                "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
                "description": v.get("shortDescription"),
                "due_date": v.get("dueDate"),
            }
        _catalog = built
        _loaded_at = time.time()
        _catalog_version = str(data.get("catalogVersion") or "")
        log.info("kev.refreshed", entries=len(built), version=_catalog_version)
        return len(built)


def _ensure_loaded() -> None:
    if not _catalog:
        refresh()


def kev_info(cve_id: str | None) -> dict:
    """KEV metadata for a CVE, or {} if it's not actively exploited / unknown.

    Returns keys ready to merge into a finding's metadata:
      kev (True), kev_date_added, kev_name, kev_ransomware, kev_due_date.
    """
    if not cve_id:
        return {}
    _ensure_loaded()
    entry = _catalog.get(cve_id.strip().upper())
    if not entry:
        return {}
    return {
        "kev": True,
        "kev_date_added": entry.get("date_added"),
        "kev_name": entry.get("name"),
        "kev_ransomware": entry.get("ransomware", False),
        "kev_due_date": entry.get("due_date"),
    }


def is_kev(cve_id: str | None) -> bool:
    if not cve_id:
        return False
    _ensure_loaded()
    return cve_id.strip().upper() in _catalog


def status() -> dict:
    """Diagnostics for the health endpoint / logs."""
    return {"entries": len(_catalog), "version": _catalog_version, "loaded_at": _loaded_at}
