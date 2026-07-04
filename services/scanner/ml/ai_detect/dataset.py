"""Build the AI-detection training dataset as a metadata feature CSV.

Human (label 0) samples are **real** source files from pinned pre-2021 OSS
commits (predating widespread LLM code assistants). AI (label 1) samples are
synthesised (synth.py) to exhibit the documented LLM tells. Only the extracted
feature vectors are written to the CSV — no source code is committed, preserving
the privacy invariant (see PRIVACY.md).

    python -m ml.ai_detect.dataset build     # clone repos + synth → features CSV

The resulting CSV is committed so training is reproducible without re-cloning.
"""
from __future__ import annotations

import csv
import os
import random
import subprocess
import tempfile

from ml.ai_detect import features as F
from ml.ai_detect import transform

CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai_detect_features.csv")

# Well-known repos pinned to pre-2021 tags (human, pre-LLM-assistant era).
HUMAN_REPOS = [
    ("https://github.com/django/django.git", "2.2.24", "python", (".py",)),
    ("https://github.com/pallets/flask.git", "1.1.2", "python", (".py",)),
    ("https://github.com/psf/requests.git", "v2.22.0", "python", (".py",)),
    ("https://github.com/pallets/click.git", "7.0", "python", (".py",)),
    ("https://github.com/pallets/werkzeug.git", "0.16.0", "python", (".py",)),
    ("https://github.com/expressjs/express.git", "4.16.4", "javascript", (".js",)),
    ("https://github.com/lodash/lodash.git", "4.17.15", "javascript", (".js",)),
    ("https://github.com/vuejs/vue.git", "v2.6.11", "javascript", (".js",)),
]

_SKIP_DIR = {"test", "tests", "node_modules", ".git", "docs", "vendor", "dist", "perf"}
_MAX_PER_REPO = 250


def _iter_source(root: str, exts: tuple[str, ...]):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in _SKIP_DIR]
        for fn in filenames:
            if fn.endswith(exts) and not fn.endswith((".min.js", ".test.js", "_test.py")):
                yield os.path.join(dirpath, fn)


def _clone(url: str, ref: str, dest: str) -> bool:
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref, url, dest],
            check=True, capture_output=True, timeout=180,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"  ! clone failed {url}@{ref}: {exc}")
        return False


def _collect_files(exts_by_repo=True) -> list[tuple[str, str]]:
    """Return (text, language) for real source files from the pinned repos."""
    samples: list[tuple[str, str]] = []
    with tempfile.TemporaryDirectory() as tmp:
        for i, (url, ref, lang, exts) in enumerate(HUMAN_REPOS):
            dest = os.path.join(tmp, f"repo{i}")
            print(f"  cloning {url}@{ref} …")
            if not _clone(url, ref, dest):
                continue
            taken = 0
            for path in _iter_source(dest, exts):
                if taken >= _MAX_PER_REPO:
                    break
                try:
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                except Exception:  # noqa: BLE001
                    continue
                if text.count("\n") < 8:      # skip trivial stubs
                    continue
                samples.append((text, lang))
                taken += 1
            print(f"    +{taken} files from {url.rsplit('/', 1)[-1]}")
    return samples


def build() -> str:
    """Human (0) and AI (1) samples are drawn from the SAME real files, split
    50/50; the AI half is refactored with documented tells (transform.py) so the
    classes overlap and the metric reflects real signal, not synthetic artifacts."""
    print("Collecting real source files (pre-2021 OSS)…")
    samples = _collect_files()
    rng = random.Random(42)
    rng.shuffle(samples)
    mid = len(samples) // 2
    human_files, ai_files = samples[:mid], samples[mid:]

    rows: list[dict] = []
    for text, lang in human_files:
        rows.append({**F.extract(text, lang), "label": 0})
    for text, lang in ai_files:
        ai_text = transform.to_ai_style(text, lang, rng)
        rows.append({**F.extract(ai_text, lang), "label": 1})

    with open(CSV_PATH, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=[*F.FEATURE_NAMES, "label"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows ({len(human_files)} human / {len(ai_files)} AI, "
          f"same-distribution split) → {CSV_PATH}")
    return CSV_PATH


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "build":
        build()
    else:
        print(__doc__)
