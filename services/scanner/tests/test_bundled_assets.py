"""Bundled/minified-asset detector tests (T2).

The detector decides which JS/TS files SAST skips (docs/SAST_TIMEOUT_DIAGNOSIS.md:
one 720 KB bundled lib cost 239 s under p/nodejsscan). It MUST be principled — content
signals, not a path list — because the real offenders lived OUTSIDE node_modules/vendor.
The load-bearing test is the NEGATIVE one: a genuinely large, genuinely hand-written
source file must NOT be excluded.
"""
from __future__ import annotations

import os

from utils import bundled_assets


def _write(tmp_path, name, content: bytes | str):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content if isinstance(content, bytes) else content.encode())
    return str(p)


# ── MINIFIED: enormous lines / almost no newlines ────────────────────────────────
def test_minified_single_line_excluded(tmp_path):
    # One 60 KB line, no newlines — the classic minified shape.
    path = _write(tmp_path, "app.min.js", b"var x=1;" + b"a=a+1;" * 10000)
    assert bundled_assets.classify(path) == "minified"


def test_minified_below_min_size_kept(tmp_path):
    # Minified in shape but tiny — cheap to scan, so not worth excluding.
    path = _write(tmp_path, "tiny.min.js", b"var x=1;" + b"a=a+1;" * 100)
    assert os.path.getsize(path) < 20 * 1024
    assert bundled_assets.classify(path) is None


# ── LARGE bundled library: formatted but big (only SIZE separates it) ─────────────
def test_large_formatted_library_excluded(tmp_path):
    # ~400 KB of normally-formatted lines (mean line ~30 B) — indistinguishable from
    # hand-written by line metrics, like ace.js. Only the size signal catches it.
    line = "  this.value = this.value + someHelper(i);\n"
    path = _write(tmp_path, "vendor-lib.js", line * 9000)
    assert os.path.getsize(path) >= bundled_assets.SIZE_EXCLUDE_BYTES
    assert bundled_assets.classify(path) == "large-bundled"


# ── NEGATIVE FIXTURE (load-bearing): large HAND-WRITTEN source is NOT excluded ─────
def test_large_handwritten_source_not_excluded(tmp_path):
    # A 200 KB genuinely hand-written, normally-formatted TS file — well above any
    # file in the V2 corpus (max ~40 KB) yet under the 300 KB size gate. It must be
    # KEPT: excluding real source is the failure mode this detector must avoid.
    body = (
        "export function handler(req: Request, res: Response): void {\n"
        "  const id = req.params.id;\n"
        "  if (!id) { res.status(400).send('missing id'); return; }\n"
        "  logger.info('processing', { id });\n"
        "}\n\n"
    )
    path = _write(tmp_path, "big_handwritten.ts", body * 1100)
    size = os.path.getsize(path)
    assert 150 * 1024 < size < bundled_assets.SIZE_EXCLUDE_BYTES
    assert bundled_assets.classify(path) is None


def test_small_handwritten_kept(tmp_path):
    path = _write(tmp_path, "component.tsx", "const App = () => <div>hi</div>;\n" * 50)
    assert bundled_assets.classify(path) is None


def test_non_js_ignored(tmp_path):
    # A huge non-JS file is not our concern (semgrep's JS hot path is what stalls).
    path = _write(tmp_path, "data.json", b'{"k":1}' * 100000)
    assert bundled_assets.classify(path) is None


# ── find_bundled walks the tree, skips excluded dirs, returns the right tuple ──────
def test_find_bundled_reports_and_skips_dirs(tmp_path):
    _write(tmp_path, "src/app.min.js", b"var x=1;" + b"a=a+1;" * 10000)          # minified
    _write(tmp_path, "src/big.js", "  a = a + b(i);\n" * 25000)                   # large-bundled
    _write(tmp_path, "src/main.ts", "const x = 1;\n" * 20)                        # kept
    _write(tmp_path, "node_modules/dep.min.js", b"a=1;" * 20000)                  # skipped dir
    paths, total, reasons = bundled_assets.find_bundled(str(tmp_path), {"node_modules"})
    rels = sorted(paths)
    assert rels == ["src/app.min.js", "src/big.js"]
    assert reasons.get("minified") == 1 and reasons.get("large-bundled") == 1
    assert total > 0
    assert all(not p.startswith("node_modules") for p in paths)
