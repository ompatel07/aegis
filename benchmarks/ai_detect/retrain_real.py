"""Retrain the AI-detect classifier on REAL data (5-fold CV) + save artifacts."""
import csv, glob, json, os
import numpy as np
from ml.ai_detect import features as F

def load(d, label):
    rows = []
    for p in glob.glob(os.path.join(d, "*.txt")):
        lang = os.path.basename(p).split("__")[-1].replace(".txt", "")
        try:
            txt = open(p, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        if len(txt.strip()) < 30:
            continue
        rows.append((F.vector(F.extract(txt, lang)), label))
    return rows

data = load("/samples/ai", 1) + load("/samples/human", 0)
X = np.array([r[0] for r in data]); y = np.array([r[1] for r in data])
print(f"real dataset: n={len(y)} AI={int(y.sum())} human={int((y==0).sum())}")

import lightgbm as lgb
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold

PARAMS = {"objective": "binary", "metric": "binary_logloss", "num_leaves": 15,
          "learning_rate": 0.05, "min_data_in_leaf": 10, "feature_fraction": 0.9, "verbose": -1}
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
P, R, Fs, A = [], [], [], []
for tr, te in skf.split(X, y):
    b = lgb.train(PARAMS, lgb.Dataset(X[tr], label=y[tr]), num_boost_round=120)
    proba = b.predict(X[te]); pred = (proba >= 0.5).astype(int)
    P.append(precision_score(y[te], pred, zero_division=0))
    R.append(recall_score(y[te], pred, zero_division=0))
    Fs.append(f1_score(y[te], pred, zero_division=0))
    A.append(roc_auc_score(y[te], proba))
print(f"REAL-DATA 5-fold CV: precision={np.mean(P):.3f} recall={np.mean(R):.3f} "
      f"F1={np.mean(Fs):.3f} ROC-AUC={np.mean(A):.3f}")

# feature importance (which metadata signals, if any, separate real AI from human)
full = lgb.train(PARAMS, lgb.Dataset(X, label=y), num_boost_round=150)
imp = sorted(zip(F.FEATURE_NAMES, full.feature_importance()), key=lambda t: -t[1])
print("top features:", [f"{n}={v}" for n, v in imp[:6]])

# save artifacts (feature CSV + model) for the repo
os.makedirs("/v/artifacts", exist_ok=True)
with open("/v/artifacts/ai_detect_real_features.csv", "w", newline="") as fh:
    w = csv.writer(fh); w.writerow(F.FEATURE_NAMES + ["label"])
    for vec, lab in data:
        w.writerow([f"{x:.6f}" for x in vec] + [lab])
full.save_model("/v/artifacts/ai_detect_real.txt")
json.dump({"cv_precision": round(float(np.mean(P)), 4), "cv_recall": round(float(np.mean(R)), 4),
           "cv_f1": round(float(np.mean(Fs)), 4), "cv_roc_auc": round(float(np.mean(A)), 4),
           "n": int(len(y)), "ai": int(y.sum()), "human": int((y == 0).sum())},
          open("/v/artifacts/ai_detect_real_metrics.json", "w"), indent=2)
print("saved artifacts to /v/artifacts/")
