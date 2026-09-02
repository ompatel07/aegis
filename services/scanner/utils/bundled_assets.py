"""Detect bundled / minified third-party JS/TS assets so SAST can skip them.

T1 (docs/SAST_TIMEOUT_DIAGNOSIS.md) root-caused the semgrep timeout to large bundled
libraries that live OUTSIDE node_modules/vendor (so aren't excluded) — one 720 KB file
(ace.js) cost 239 s under p/nodejsscan. These are third-party code, not the customer's
own — SAST findings in them are noise (ownership already recesses them), and their
dependency CVEs are covered by SCA + vendored-fingerprinting (utils.vendored_fingerprint),
which still scans them. So we exclude them from SAST ONLY.

PRINCIPLED, not a path list — the offenders were outside vendor/, which is the whole
point. Two content signals, calibrated against the real T1 files:

  1. MINIFIED — enormous lines / almost no newlines. jquery.min.js: mean line 29,381 B,
     newline/byte 0.0000. Hand-written code tops out ~50 B mean, ~0.02 newline/byte.
  2. LARGE bundled library — a single JS/TS file ≥ 300 KB. The T1 offenders ace.js
     (720 KB, mean line 32 — formatted, NOT minified), jquery-ui-1.10.4.js (436 KB),
     wysihtml5 (331 KB) are indistinguishable from hand-written code by line metrics;
     only SIZE separates them. Across the whole V2 corpus (15 repos) no hand-written
     source file exceeded ~40 KB; every scanned JS/TS file ≥ 300 KB was a vendored
     library. A hand-written file that big is itself pathological for semgrep. The
     negative fixture (a 200 KB normally-formatted hand-written file) is NOT excluded.
"""
from __future__ import annotations

import os

# JS-family extensions semgrep's JS/TS + nodejsscan rules run on (the T1 hot path).
_JS_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")

# A single JS/TS file this big is, empirically (V2 corpus), always a vendored/bundled
# library — never hand-written app code.
SIZE_EXCLUDE_BYTES = 300 * 1024
# Below this, even a minified file is cheap enough to scan; don't bother reading it.
_MINIFIED_MIN_SIZE = 20 * 1024
# A single leading window is enough to tell minified from formatted.
_SAMPLE_BYTES = 64 * 1024
# Minified thresholds.
_MEAN_LINE_MINIFIED = 300.0     # bytes/line; hand-written ~30–50
_NEWLINE_RATIO_MINIFIED = 0.005  # newlines/byte; hand-written ~0.02–0.035


def classify(path: str, size: int | None = None) -> str | None:
    """Return a short reason ('minified' | 'large-bundled') if this file is a
    bundled/minified asset to exclude from SAST, else None. Content-based."""
    ext = os.path.splitext(path)[1].lower()
    if ext not in _JS_EXTS:
        return None
    try:
        size = size if size is not None else os.path.getsize(path)
    except OSError:
        return None
    if size >= SIZE_EXCLUDE_BYTES:
        return "large-bundled"
    if size < _MINIFIED_MIN_SIZE:
        return None
    try:
        with open(path, "rb") as fh:
            data = fh.read(_SAMPLE_BYTES)
    except OSError:
        return None
    if not data:
        return None
    newlines = data.count(b"\n")
    mean_line = len(data) / (newlines + 1)
    if mean_line >= _MEAN_LINE_MINIFIED or (newlines / len(data)) < _NEWLINE_RATIO_MINIFIED:
        return "minified"
    return None


def find_bundled(root: str, skip_dirs: set[str]) -> tuple[list[str], int, dict]:
    """Walk `root` (skipping `skip_dirs`, the same dirs semgrep already excludes) and
    return (relative_paths, total_bytes, reason_counts) for every bundled/minified
    JS/TS asset. The relative paths are suitable to hand to semgrep's --exclude."""
    paths: list[str] = []
    total = 0
    reasons: dict[str, int] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() not in _JS_EXTS:
                continue
            full = os.path.join(dirpath, fn)
            try:
                sz = os.path.getsize(full)
            except OSError:
                continue
            reason = classify(full, sz)
            if reason:
                rel = os.path.relpath(full, root).replace("\\", "/")
                paths.append(rel)
                total += sz
                reasons[reason] = reasons.get(reason, 0) + 1
    return paths, total, reasons
