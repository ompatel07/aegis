"""False-positive classifier inference — loaded once, scores findings.

The scanner loads the model on startup (training it from the seed if none exists
yet) and scores every finding with P(false positive). The score is ADVISORY: it
is attached to the finding and used for sorting / a "likely false positive"
badge — findings are never hidden.
"""
from __future__ import annotations

import os
import threading

from logging_config import get_logger
from ml.features import featurize, record_from_finding

log = get_logger("ml.classifier")

_MODEL_PATH = os.environ.get("FP_MODEL_PATH", "/opt/aegis/models/fp_classifier.joblib")
_lock = threading.Lock()
_state: dict = {"model": None, "loaded": False}


def ensure_model() -> None:
    """Load the model; if it does not exist yet, train it from the seed."""
    with _lock:
        if _state["loaded"]:
            return
        if not os.path.isfile(_MODEL_PATH):
            _train_seed()
        _state["model"] = _load()
        _state["loaded"] = True


def _load():
    try:
        import joblib

        payload = joblib.load(_MODEL_PATH)
        log.info("ml.model_loaded", path=_MODEL_PATH, version=payload.get("version"))
        return payload["model"]
    except Exception as exc:  # noqa: BLE001 — inference is best-effort
        log.warning("ml.model_load_failed", error=str(exc))
        return None


def _train_seed() -> None:
    try:
        from ml import train
        from ml.seed import generate_seed

        train.train(generate_seed(), _MODEL_PATH)
        log.info("ml.seed_model_trained", path=_MODEL_PATH)
    except Exception as exc:  # noqa: BLE001
        log.warning("ml.seed_train_failed", error=str(exc))


def score_finding(finding: dict, project: dict | None = None) -> float | None:
    """Return P(false positive) in [0,1], or None if no model is available."""
    model = _state.get("model")
    if model is None:
        return None
    try:
        vec = featurize(record_from_finding(finding, project))
        proba = model.predict_proba([vec])[0][1]
        return round(float(proba), 4)
    except Exception as exc:  # noqa: BLE001
        log.debug("ml.score_failed", error=str(exc))
        return None


def score_findings(findings, project: dict | None = None) -> int:
    """Score a list of Finding models in place (sets .false_positive_probability).
    Returns how many were scored."""
    if _state.get("model") is None:
        return 0
    scored = 0
    for f in findings:
        p = score_finding(
            {
                "rule_id": f.rule_id, "engine": f.engine, "severity": f.severity,
                "file_path": f.file_path, "cwe_id": f.cwe_id,
                "owasp_category": f.owasp_category, "metadata": f.metadata,
            },
            project,
        )
        if p is not None:
            f.false_positive_probability = p
            scored += 1
    return scored
