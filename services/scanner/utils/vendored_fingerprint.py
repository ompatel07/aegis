"""Vendored-library fingerprinting for SCA.

Aegis's SCA (Trivy) is manifest-based: libraries a project VENDORS by copying the
source in (no composer.json / package.json) are invisible to it. A repo bundling an
old PHPMailer (RCE-era 5.2.x) would get a clean "0 vulnerable dependencies" while
sitting on real RCEs.

This module closes that gap for a CURATED set of commonly-vendored libraries where
the version can be read RELIABLY and UNAMBIGUOUSLY. It is PRECISION-FIRST:

  * A library is only recognised when its distinctive file, an identity marker,
    AND an exact version all match — otherwise it is skipped (a wrong version read
    would flag CVEs that do not apply, which is worse than the gap).
  * It skips manifest-managed dirs (vendor/, node_modules/, …) so it never
    double-counts a dependency Trivy already resolves from a lockfile.
  * CVEs come from OSV for the exact package@version — never guessed.

Adding a library means adding a verified signature below; do not fingerprint
libraries whose version cannot be extracted with confidence.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request

from logging_config import get_logger

log = get_logger("fingerprint")

# Each signature must match all three of file_re (the library's distinctive file),
# marker_re (confirms identity — not just a same-named app file), and version_re
# (extracts the exact version). Verified against real library files.
_SIGNATURES: list[dict] = [
    {
        "lib": "PHPMailer", "ecosystem": "Packagist", "package": "phpmailer/phpmailer",
        "file_re": re.compile(r"(^|/)PHPMailer\.php$"),
        "marker_re": re.compile(r"namespace\s+PHPMailer\\PHPMailer|class\s+PHPMailer\b"),
        "version_re": re.compile(r"const\s+VERSION\s*=\s*'([0-9]+\.[0-9]+\.[0-9]+)'"),
    },
    {
        "lib": "FPDF", "ecosystem": "Packagist", "package": "setasign/fpdf",
        "file_re": re.compile(r"(^|/)fpdf\.php$", re.I),
        "marker_re": re.compile(r"class\s+FPDF\b"),
        "version_re": re.compile(r"(?:const\s+VERSION|FPDF_VERSION)\s*(?:=|,)\s*'([0-9]+\.[0-9]+(?:\.[0-9]+)?)'"),
    },
    {
        "lib": "jQuery", "ecosystem": "npm", "package": "jquery",
        "file_re": re.compile(r"(^|/)jquery[-.][^/]*\.js$|(^|/)jquery\.js$", re.I),
        "marker_re": re.compile(r"jQuery(?:\s+JavaScript\s+Library)?\s+v[0-9]"),
        "version_re": re.compile(r"jQuery(?:\s+JavaScript\s+Library)?\s+v([0-9]+\.[0-9]+\.[0-9]+)"),
    },
    {
        "lib": "Bootstrap", "ecosystem": "npm", "package": "bootstrap",
        "file_re": re.compile(r"(^|/)bootstrap([-.][^/]*)?\.(css|js)$", re.I),
        "marker_re": re.compile(r"Bootstrap\s+v[0-9]"),
        "version_re": re.compile(r"Bootstrap\s+v([0-9]+\.[0-9]+\.[0-9]+)"),
    },
]

# Dirs already covered by Trivy's manifest scan (skip so we never double-count) or
# that never contain hand-vendored libraries.
_SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "site-packages", ".next"}
_MAX_READ = 3_000_000  # read at most ~3MB of a candidate file


def detect_libraries(root: str) -> list[dict]:
    """Walk the tree and return confidently-identified vendored libraries:
    [{lib, package, ecosystem, version, file}]. Only libs matching a full signature
    (file + marker + exact version) are returned."""
    out: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            for sig in _SIGNATURES:
                if not sig["file_re"].search(rel):
                    continue
                text = _read(full)
                if not text:
                    continue
                if not sig["marker_re"].search(text):
                    continue  # same filename but not actually this library → skip
                m = sig["version_re"].search(text)
                if not m:
                    continue  # can't read an exact version with confidence → skip
                out.append({
                    "lib": sig["lib"], "package": sig["package"],
                    "ecosystem": sig["ecosystem"], "version": m.group(1), "file": rel,
                })
                break  # one signature per file
    return out


def _read(path: str) -> str | None:
    try:
        if os.path.getsize(path) > _MAX_READ:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                return fh.read(_MAX_READ)
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None


_osv_cache: dict[tuple[str, str], list[dict]] = {}


def osv_vulns(package: str, ecosystem: str, version: str) -> list[dict]:
    """Query OSV for CVEs affecting exactly package@version. Best-effort: any error
    returns [] (fingerprinting must never fail SCA), and results are cached."""
    key = (package.lower(), version)
    if key in _osv_cache:
        return _osv_cache[key]
    try:
        body = json.dumps({"package": {"name": package, "ecosystem": ecosystem}, "version": version}).encode()
        req = urllib.request.Request("https://api.osv.dev/v1/query", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=15) as r:
            vulns = json.loads(r.read()).get("vulns") or []
    except Exception as exc:  # noqa: BLE001
        log.warning("fingerprint.osv_failed", package=package, version=version, error=str(exc))
        vulns = []
    _osv_cache[key] = vulns
    return vulns


_SEV_MAP = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}


def vuln_severity(vuln: dict) -> str:
    ds = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(ds, str) and ds.lower() in _SEV_MAP:
        return _SEV_MAP[ds.lower()]
    return "high"  # a known CVE with no severity band → conservative (not silent)


def cve_id(vuln: dict) -> str:
    for a in vuln.get("aliases") or []:
        if a.startswith("CVE-"):
            return a
    return vuln.get("id", "")


def fixed_version(vuln: dict, package: str) -> str | None:
    for aff in vuln.get("affected") or []:
        if (aff.get("package") or {}).get("name", "").lower() != package.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    return ev["fixed"]
    return None
