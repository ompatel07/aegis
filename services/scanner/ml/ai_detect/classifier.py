"""AI-generated-code classifier — inference + heuristic fallback.

`score_text` returns a probability in [0, 1] that a file was AI-generated. It
uses the trained LightGBM model when present; otherwise it falls back to a
transparent weighted-heuristic over the same features so the engine always
produces a usable score (and so the platform works before any model is built).

Everything runs locally on file text already in the scanner — no code leaves.
"""
from __future__ import annotations

import os

from logging_config import get_logger
from ml.ai_detect import features as F

log = get_logger("ml.ai_detect")

MODEL_PATH = os.getenv("AI_DETECT_MODEL_PATH", "/opt/aegis/models/ai_detect.txt")

_model = None            # loaded LightGBM Booster
_load_attempted = False


def _try_load() -> None:
    global _model, _load_attempted
    if _load_attempted:
        return
    _load_attempted = True
    try:
        import lightgbm as lgb  # noqa: F401

        if os.path.exists(MODEL_PATH):
            import lightgbm as lgb

            _model = lgb.Booster(model_file=MODEL_PATH)
            log.info("ai_detect.model_loaded", path=MODEL_PATH)
    except Exception as exc:  # noqa: BLE001 — inference must never break a scan
        log.warning("ai_detect.model_load_failed", error=str(exc))
        _model = None


# ── Heuristic fallback ────────────────────────────────────────────────────────
# Weighted signals (calibrated to the documented AI tells). Used when no model is
# present; also a sanity floor. Positive weight → raises AI probability.
_H_WEIGHTS = {
    "doc_boilerplate_ratio": 0.16,
    "sentence_comment_ratio": 0.9,
    "generic_name_ratio": 1.4,
    "template_name_ratio": 0.10,
    "bare_except_ratio": 0.8,
    "quote_consistency": 0.7,
    "indent_consistency": 0.5,
    "comment_ratio": 0.4,
    "todo_density": -0.6,   # humans leave TODOs; AI rarely does
}
_H_BIAS = -1.6


def _sigmoid(x: float) -> float:
    import math

    if x < -30:
        return 0.0
    if x > 30:
        return 1.0
    return 1.0 / (1.0 + math.exp(-x))


def heuristic_score(feats: dict[str, float]) -> float:
    z = _H_BIAS
    for name, w in _H_WEIGHTS.items():
        z += w * float(feats.get(name, 0.0))
    return _sigmoid(z)


def score_text(text: str, language: str | None = None) -> float:
    """Probability [0,1] that this file's text was AI-generated."""
    if not text or not text.strip():
        return 0.0
    feats = F.extract(text, language)
    _try_load()
    if _model is not None:
        try:
            pred = _model.predict([F.vector(feats)])
            return float(max(0.0, min(1.0, pred[0])))
        except Exception as exc:  # noqa: BLE001
            log.debug("ai_detect.predict_failed", error=str(exc))
    return heuristic_score(feats)


def model_available() -> bool:
    _try_load()
    return _model is not None


def ensure_model() -> None:
    """Load the model, or train it from the committed feature CSV if absent, so a
    fresh deploy self-provisions. Best-effort: on failure, scoring uses the
    heuristic fallback."""
    global _load_attempted, _model
    _try_load()
    if _model is not None:
        return
    try:
        from ml.ai_detect.dataset import CSV_PATH
        from ml.ai_detect.train import train_and_save

        if os.path.exists(CSV_PATH):
            train_and_save()
            _load_attempted = False
            _try_load()
            log.info("ai_detect.model_trained_on_startup")
    except Exception as exc:  # noqa: BLE001
        log.warning("ai_detect.ensure_failed", error=str(exc))
