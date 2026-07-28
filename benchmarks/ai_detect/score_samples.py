"""Score collected real samples with the TRAINED AI-detect model + report metrics."""
import glob, os, sys
from ml.ai_detect import classifier as C

def load(d, label):
    out = []
    for p in glob.glob(os.path.join(d, "*.txt")):
        lang = os.path.basename(p).split("__")[-1].replace(".txt", "")
        try:
            with open(p, encoding="utf-8", errors="ignore") as f:
                txt = f.read()
        except OSError:
            continue
        if len(txt.strip()) < 30:
            continue
        out.append((txt, lang, label))
    return out

samples = load("/samples/ai", 1) + load("/samples/human", 0)
print(f"model_available: {C.model_available()}  (must be True to validate the real model)")
print(f"samples: AI={sum(1 for s in samples if s[2]==1)}  human={sum(1 for s in samples if s[2]==0)}")

scores, labels = [], []
for txt, lang, lab in samples:
    scores.append(C.score_text(txt, lang))
    labels.append(lab)

import statistics as st
ai_scores = [s for s, l in zip(scores, labels) if l == 1]
hu_scores = [s for s, l in zip(scores, labels) if l == 0]
print(f"mean score  AI={st.mean(ai_scores):.3f}  human={st.mean(hu_scores):.3f}")

def metrics_at(thr):
    tp = sum(1 for s, l in zip(scores, labels) if s >= thr and l == 1)
    fp = sum(1 for s, l in zip(scores, labels) if s >= thr and l == 0)
    fn = sum(1 for s, l in zip(scores, labels) if s < thr and l == 1)
    tn = sum(1 for s, l in zip(scores, labels) if s < thr and l == 0)
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    acc = (tp + tn) / len(labels)
    return tp, fp, fn, tn, prec, rec, f1, acc

for thr in (0.5, 0.6, 0.7):
    tp, fp, fn, tn, prec, rec, f1, acc = metrics_at(thr)
    print(f"@thr={thr}: TP={tp} FP={fp} FN={fn} TN={tn} | precision={prec:.3f} recall={rec:.3f} F1={f1:.3f} acc={acc:.3f}")

# best-F1 threshold sweep
best = max(((metrics_at(t/100.0)[6], t/100.0) for t in range(5, 96)), key=lambda x: x[0])
print(f"best-F1 threshold: {best[1]:.2f} -> F1={best[0]:.3f}")

# ROC-AUC
try:
    from sklearn.metrics import roc_auc_score
    print(f"ROC-AUC: {roc_auc_score(labels, scores):.3f}")
except Exception as e:
    # manual AUC via rank statistic
    pos = [s for s, l in zip(scores, labels) if l == 1]
    neg = [s for s, l in zip(scores, labels) if l == 0]
    wins = sum((a > b) + 0.5 * (a == b) for a in pos for b in neg)
    print(f"ROC-AUC (manual): {wins/(len(pos)*len(neg)):.3f}")
