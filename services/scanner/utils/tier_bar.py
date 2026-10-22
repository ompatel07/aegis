"""The STRONG bar, computed from measured evidence (Pass N5).

WHY
---
N4 tiered Java STRONG at 15% recall. Its bar ("the taint pack caught something in two
or more corpora") was an existence test that 17 corpora make nearly impossible to fail,
and the tier itself was a hand-edited tuple. That is the hardcoded-list problem again.
Here the tier is computed from two files, and nothing else:

  accuracy/gt_items.json   every documented vulnerability in every qualifying
                           ground-truth corpus: in/out of scope, detected or missed,
                           the catching rule, and whether the corpus is held out
  accuracy/triage.json     every hand-triaged finding of a shipped rule, on real
                           repositories and on the ground-truth corpora

THE BAR
-------
A language is STRONG only if ALL hold:

  1. corpora   documented vulnerabilities caught by its shipped rules in at least
               STRONG_MIN_CORPORA corpora. A detection that was itself the evidence a rule
               was promoted on (`promotion_evidence`) does not count: that would be
               circular.
  2. recall    pooled in-scope recall on its HELD-OUT corpora is at least
               STRONG_MIN_RECALL. Held-out corpora are drawn before rules are written
               from the others (accuracy/holdout.json), so this recall cannot have been
               tuned. No held-out corpus means no held-out recall, so the criterion fails.
  3. precision TP / (TP + FP) over every triaged finding of its shipped rules is at
               least STRONG_MIN_PRECISION. UNCERTAIN is excluded from the rate (the N2b
               convention) and reported. A finding recorded as UNTRIAGED fails the
               criterion: an unread finding cannot support a precision claim.

A language with shipped rules that fails any criterion is LIMITED; one with none is NONE.
Only shipped rules that count as coverage are evidence (silent-clean rules are not), so
removing a rule moves the tier with no hand edit.
"""
from __future__ import annotations

import functools
import json
import logging
import os
from dataclasses import dataclass, field

STRONG_MIN_CORPORA = 2
STRONG_MIN_RECALL = 0.25
STRONG_MIN_PRECISION = 0.70

TIER_NONE = "none"
TIER_LIMITED = "limited"
TIER_STRONG = "strong"

ACCURACY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "accuracy")
HELD_OUT = "held_out"
TUNING = "tuning"


@dataclass
class LanguageEvidence:
    language: str
    tier: str = TIER_NONE
    corpora: list[str] = field(default_factory=list)            # qualifying GT corpora
    detection_corpora: list[str] = field(default_factory=list)  # criterion 1
    held_out: list[str] = field(default_factory=list)
    held_out_detected: int = 0
    held_out_in_scope: int = 0
    tuning_detected: int = 0
    tuning_in_scope: int = 0
    tp: int = 0
    fp: int = 0
    uncertain: int = 0
    untriaged: int = 0
    failed: list[str] = field(default_factory=list)              # criteria not met, with numbers

    @property
    def held_out_recall(self) -> float | None:
        return self.held_out_detected / self.held_out_in_scope if self.held_out_in_scope else None

    @property
    def tuning_recall(self) -> float | None:
        return self.tuning_detected / self.tuning_in_scope if self.tuning_in_scope else None

    @property
    def all_recall(self) -> float | None:
        n = self.held_out_in_scope + self.tuning_in_scope
        return (self.held_out_detected + self.tuning_detected) / n if n else None

    @property
    def precision(self) -> float | None:
        n = self.tp + self.fp
        return self.tp / n if n else None

    def as_dict(self) -> dict:
        r = lambda x: None if x is None else round(x, 4)
        return {
            "language": self.language, "tier": self.tier, "failed": self.failed,
            "corpora": len(self.corpora), "detection_corpora": len(self.detection_corpora),
            "held_out_corpora": len(self.held_out),
            "held_out_recall": r(self.held_out_recall),
            "held_out_detected": self.held_out_detected, "held_out_in_scope": self.held_out_in_scope,
            "tuning_recall": r(self.tuning_recall),
            "tuning_detected": self.tuning_detected, "tuning_in_scope": self.tuning_in_scope,
            "precision": r(self.precision), "tp": self.tp, "fp": self.fp,
            "uncertain": self.uncertain, "untriaged": self.untriaged,
        }


def evaluate(gt: dict, triage: list[dict], shipped: dict[str, set[str]],
             languages: set[str]) -> dict[str, LanguageEvidence]:
    """The tier of every language in `languages` (those with shipped rules), from data.

    gt:       corpus -> {"language", "role": held_out|tuning, "items": [...]}; an item
              has "scope" ("IN" counts), "status" ("DET" is a detection), "rules" (the
              catching rule ids) and optionally "promotion_evidence".
    triage:   [{"language", "rule", "verdict": TP|FP|UNCERTAIN|UNTRIAGED}, ...]
    shipped:  rule id -> languages it runs on, for shipped coverage rules only.
    """
    out = {l: LanguageEvidence(language=l) for l in languages}

    def caught(item: dict, lang: str) -> bool:
        return item.get("status") == "DET" and any(lang in shipped.get(r, ()) for r in item.get("rules") or [])

    for corpus, c in sorted(gt.items()):
        ev = out.get(c["language"])
        if ev is None:
            continue
        ev.corpora.append(corpus)
        ins = [i for i in c["items"] if i.get("scope") == "IN"]
        det = [i for i in ins if caught(i, ev.language)]
        if any(not i.get("promotion_evidence") for i in det):
            ev.detection_corpora.append(corpus)
        if c.get("role") == HELD_OUT:
            ev.held_out.append(corpus)
            ev.held_out_in_scope += len(ins)
            ev.held_out_detected += len(det)
        else:
            ev.tuning_in_scope += len(ins)
            ev.tuning_detected += len(det)

    for t in triage:
        ev = out.get(t.get("language"))
        if ev is None or ev.language not in shipped.get(t.get("rule"), ()):
            continue  # a rule that no longer ships is not evidence either way
        v = t.get("verdict")
        if v == "TP":
            ev.tp += 1
        elif v == "FP":
            ev.fp += 1
        elif v == "UNCERTAIN":
            ev.uncertain += 1
        else:
            ev.untriaged += 1

    for ev in out.values():
        if len(ev.detection_corpora) < STRONG_MIN_CORPORA:
            ev.failed.append(f"corpora: documented detections in {len(ev.detection_corpora)} "
                             f"corpus(es), needs {STRONG_MIN_CORPORA}")
        if ev.held_out_recall is None:
            ev.failed.append("recall: no held-out corpus")
        elif ev.held_out_recall < STRONG_MIN_RECALL:
            ev.failed.append(f"recall: held-out {ev.held_out_detected}/{ev.held_out_in_scope} = "
                             f"{ev.held_out_recall:.0%}, needs {STRONG_MIN_RECALL:.0%}")
        if ev.untriaged:
            ev.failed.append(f"precision: {ev.untriaged} finding(s) untriaged")
        elif ev.precision is None:
            ev.failed.append("precision: no triaged finding")
        elif ev.precision < STRONG_MIN_PRECISION:
            ev.failed.append(f"precision: {ev.tp}/{ev.tp + ev.fp} = {ev.precision:.0%}, "
                             f"needs {STRONG_MIN_PRECISION:.0%}")
        ev.tier = TIER_LIMITED if ev.failed else TIER_STRONG
    return out


def _load(name: str):
    with open(os.path.join(ACCURACY_DIR, name), encoding="utf-8") as fh:
        return json.load(fh)


@functools.lru_cache(maxsize=1)
def ledger() -> tuple[dict, list[dict]]:
    """(gt_items, triage) as shipped in the image.

    Fails CLOSED: if the evidence is missing from the image, no language can clear the
    bar, so every language is LIMITED and security scores are withheld ("Not
    measured") rather than presented as confident. A scan never crashes on it, and
    tests/test_tier_bar.py fails loudly instead."""
    try:
        return _load("gt_items.json"), _load("triage.json")
    except (OSError, ValueError) as exc:
        logging.getLogger(__name__).error("tier evidence unavailable, every language LIMITED: %s", exc)
        return {}, []
