"""Train the false-positive classifier (LightGBM) from the seed + real feedback.

Reads metadata-only training rows (seed always; plus an exported feedback JSONL
if provided), trains a gradient-boosted-tree classifier, reports cross-validated
precision/recall/ROC-AUC, and writes the model artifact to the shared models dir.

Run:  python -m ml.train  [--data /path/feedback.jsonl]  [--out /opt/aegis/models/fp_classifier.joblib]

NO SOURCE CODE is read at any point — only metadata feature rows.
"""
from __future__ import annotations

import argparse
import json
import os

from ml.features import FEATURE_NAMES, featurize, label_to_binary
from ml.seed import generate_seed

DEFAULT_MODEL_PATH = os.environ.get("FP_MODEL_PATH", "/opt/aegis/models/fp_classifier.joblib")


def _rows_to_xy(rows: list[dict]):
    X = [featurize(r) for r in rows]
    y = [label_to_binary(r["label"]) for r in rows]
    return X, y


def cross_validate(rows: list[dict]) -> dict:
    """5-fold CV precision/recall/ROC-AUC on the training rows."""
    import numpy as np
    from lightgbm import LGBMClassifier
    from sklearn.metrics import precision_score, recall_score, roc_auc_score
    from sklearn.model_selection import StratifiedKFold

    X, y = _rows_to_xy(rows)
    X, y = np.array(X), np.array(y)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    prec, rec, auc = [], [], []
    for train_idx, test_idx in skf.split(X, y):
        clf = _new_model()
        clf.fit(X[train_idx], y[train_idx])
        pred = clf.predict(X[test_idx])
        proba = clf.predict_proba(X[test_idx])[:, 1]
        prec.append(precision_score(y[test_idx], pred, zero_division=0))
        rec.append(recall_score(y[test_idx], pred, zero_division=0))
        try:
            auc.append(roc_auc_score(y[test_idx], proba))
        except ValueError:
            pass
    return {
        "precision": round(float(sum(prec) / len(prec)), 4),
        "recall": round(float(sum(rec) / len(rec)), 4),
        "roc_auc": round(float(sum(auc) / len(auc)), 4) if auc else None,
        "n_samples": len(rows),
        "fp_rate": round(float(sum(y) / len(y)), 4),
    }


def _new_model():
    from lightgbm import LGBMClassifier

    return LGBMClassifier(
        n_estimators=200, num_leaves=31, learning_rate=0.05,
        min_child_samples=10, subsample=0.9, colsample_bytree=0.9,
        random_state=42, verbose=-1,
    )


def train(rows: list[dict], out_path: str) -> dict:
    import joblib

    X, y = _rows_to_xy(rows)
    model = _new_model()
    model.fit(X, y)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    joblib.dump({"model": model, "features": FEATURE_NAMES, "version": 1}, out_path)
    return {"out": out_path, "n": len(rows)}


def load_feedback_rows(path: str | None) -> list[dict]:
    if not path or not os.path.isfile(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=None, help="optional exported feedback JSONL")
    ap.add_argument("--out", default=DEFAULT_MODEL_PATH)
    args = ap.parse_args()

    rows = generate_seed() + load_feedback_rows(args.data)
    metrics = cross_validate(rows)
    train(rows, args.out)
    print(json.dumps({"trained": True, "model": args.out, "metrics": metrics}, indent=2))


if __name__ == "__main__":
    main()
