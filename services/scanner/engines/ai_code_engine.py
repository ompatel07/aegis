"""AI-generated-code engine (Phase 2C TASK 3a).

Walks a checked-out repository, scores each source file on likelihood of being
AI-generated (locally, via ml.ai_detect — no code leaves the scanner), and
returns a repository-level `AICodeResult`. The orchestrator uses `file_scores`
to tag findings that sit in AI-generated files and assembles the scan's AI-code
report from these stats + the finding breakdown.
"""
from __future__ import annotations

import os
import time

from logging_config import get_logger
from ml.ai_detect import classifier
from models.scan_request import ScanRequest
from models.scan_result import AICodeResult, EngineStatus

log = get_logger("engine.ai_code")

# Extension → language for the files we extract features from.
_LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".java": "java",
    ".rb": "ruby", ".php": "php",
}
_SKIP_DIR = {".git", "node_modules", "vendor", "dist", "build", ".next", "venv",
             ".venv", "__pycache__", "site-packages", "third_party", "migrations"}
_MAX_FILE_BYTES = 400_000
_MAX_FILES = 20_000            # bound work on very large repos
_KEEP_SCORE_FLOOR = 0.3       # only return scores at/above this (bounds payload)

# Which elevated features explain an AI classification (for the report's "why").
_SIGNAL_LABELS = [
    ("doc_boilerplate_ratio", 1.5, "boilerplate docstrings (Args:/Returns:/@param)"),
    ("generic_name_ratio", 0.28, "generic variable naming (result/data/output)"),
    ("bare_except_ratio", 0.5, "broad exception handling (except Exception / catch(e))"),
    ("sentence_comment_ratio", 0.55, "narrating full-sentence comments"),
    ("quote_consistency", 0.92, "unusually uniform quoting/style"),
    ("todo_density", 0.0, None),  # placeholder; handled inversely below
]


def run(req: ScanRequest, settings=None) -> AICodeResult:
    from ml.ai_detect import features as F

    start = time.time()
    root = req.path
    scores: dict[str, float] = {}
    signal_tally: dict[str, int] = {}
    files_scored = 0
    ai_count = 0

    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIR]
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                lang = _LANG_BY_EXT.get(ext)
                if not lang:
                    continue
                full = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(full) > _MAX_FILE_BYTES:
                        continue
                    with open(full, encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                except OSError:
                    continue
                if text.count("\n") < 5:
                    continue

                feats = F.extract(text, lang)
                prob = classifier.score_text(text, lang)
                files_scored += 1
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                if prob >= _KEEP_SCORE_FLOOR:
                    scores[rel] = round(prob, 3)
                if prob > 0.7:
                    ai_count += 1
                    for name, thresh, label in _SIGNAL_LABELS:
                        if label and feats.get(name, 0.0) >= thresh:
                            signal_tally[label] = signal_tally.get(label, 0) + 1
                if files_scored >= _MAX_FILES:
                    break
            if files_scored >= _MAX_FILES:
                break
    except Exception as exc:  # noqa: BLE001 — never fail the scan on this pass
        log.exception("ai_code.error", scan_id=req.scan_id)
        return AICodeResult(status=EngineStatus.FAILED, error=str(exc),
                            scan_id=req.scan_id, duration_seconds=time.time() - start)

    pct = (ai_count / files_scored * 100.0) if files_scored else 0.0
    top_signals = [s for s, _ in sorted(signal_tally.items(), key=lambda kv: -kv[1])[:4]]

    log.info("ai_code.done", scan_id=req.scan_id, files=files_scored, ai=ai_count,
             pct=round(pct, 1), model=classifier.model_available())
    return AICodeResult(
        status=EngineStatus.COMPLETED,
        files_scored=files_scored,
        ai_file_count=ai_count,
        ai_generated_pct=round(pct, 2),
        threshold=0.7,
        model_available=classifier.model_available(),
        file_scores=scores,
        top_signals=top_signals,
        scan_id=req.scan_id,
        duration_seconds=round(time.time() - start, 3),
    )
