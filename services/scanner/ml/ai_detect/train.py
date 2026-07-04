"""Train + cross-validate the AI-generated-code classifier (LightGBM).

    python -m ml.ai_detect.train        # 5-fold CV metrics + fit + save model

Reports precision / recall / ROC-AUC (5-fold stratified CV) on the committed
feature CSV, then fits on all rows and saves the model to AI_DETECT_MODEL_PATH.
Metrics are written next to the model as ai_detect_metrics.json for the report.
"""
from __future__ import annotations

import csv
import json
import os

from ml.ai_detect import features as F
from ml.ai_detect.classifier import MODEL_PATH
from ml.ai_detect.dataset import CSV_PATH

METRICS_PATH = os.path.join(os.path.dirname(MODEL_PATH), "ai_detect_metrics.json")

_PARAMS = {
    "objective": "binary",
    "metric": "binary_logloss",
    "num_leaves": 15,
    "learning_rate": 0.05,
    "min_data_in_leaf": 10,
    "feature_fraction": 0.9,
    "verbose": -1,
}


def _load_csv() -> tuple[list[list[float]], list[int]]:
    X, y = [], []
    with open(CSV_PATH, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            X.append([float(row[name]) for name in F.FEATURE_NAMES])
            y.append(int(row["label"]))
    return X, y


def cross_validate(X, y) -> dict:
    import lightgbm as lgb
    import numpy as np
    from sklearn.metrics import precision_score, recall_score, roc_auc_score
    from sklearn.model_selection import StratifiedKFold

    Xn, yn = np.array(X), np.array(y)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    precs, recs, aucs = [], [], []
    for tr, te in skf.split(Xn, yn):
        dtrain = lgb.Dataset(Xn[tr], label=yn[tr])
        booster = lgb.train(_PARAMS, dtrain, num_boost_round=120)
        proba = booster.predict(Xn[te])
        pred = (proba >= 0.5).astype(int)
        precs.append(precision_score(yn[te], pred, zero_division=0))
        recs.append(recall_score(yn[te], pred, zero_division=0))
        aucs.append(roc_auc_score(yn[te], proba))
    return {
        "precision": round(float(np.mean(precs)), 4),
        "recall": round(float(np.mean(recs)), 4),
        "roc_auc": round(float(np.mean(aucs)), 4),
        "samples": int(len(yn)),
        "positives": int(yn.sum()),
    }


def train_and_save() -> dict:
    import lightgbm as lgb
    import numpy as np

    X, y = _load_csv()
    metrics = cross_validate(X, y)
    print(f"CV: precision={metrics['precision']} recall={metrics['recall']} "
          f"roc_auc={metrics['roc_auc']} (n={metrics['samples']}, pos={metrics['positives']})")

    dtrain = lgb.Dataset(np.array(X), label=np.array(y))
    booster = lgb.train(_PARAMS, dtrain, num_boost_round=150)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    booster.save_model(MODEL_PATH)
    with open(METRICS_PATH, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"Saved model → {MODEL_PATH}")
    return metrics


if __name__ == "__main__":
    train_and_save()
