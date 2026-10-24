"""Two claims, two gates, computed from measured evidence (Pass N5, split in N6).

WHY
---
N5 made one bar certify two different claims, and it withheld every score. A CLEAN
result ("no significant issues") is only as good as our RECALL: had there been a
vulnerability, would we have found it? A PROBLEM result ("these issues exist") is only
as good as our PRECISION: when we report one, is it real? N6 gates each claim on its own
evidence (docs/SECURITY_GATES_N6.md, fixed before any number was recomputed). Every
number comes from files that ship in the image, and nothing is declared:

  accuracy/gt_items.json   every documented vulnerability in every qualifying
                           ground-truth corpus: scope, Aegis status, the catching rule,
                           the corpus's holdout role, and -- where CodeQL ran on it --
                           CodeQL's status on the same item
  accuracy/triage.json     every hand-triaged finding of a shipped rule, with its kind:
                           `real` (production OSS, with its precision-holdout role) or
                           `ground-truth` (teaching / tool-test corpora: the stress set)

THE RECALL GATE (certifies a clean result)
------------------------------------------
  1. corpora   documented vulnerabilities caught by shipped rules in >= MIN_CORPORA
               corpora (a promotion's own evidence excluded: that would be circular).
  2. recall    on HELD-OUT corpora, the Wilson 95% lower bound of Aegis's in-scope
               recall is at least CodeQL's (security-extended) recall on the same items
               -- parity with the market reference. Where CodeQL ran on no held-out
               corpus of the language (unsupported language; no OSI-licensed corpus),
               the floor is the absolute UNCALIBRATED_MIN_RECALL and the gate says it is
               uncalibrated. No held-out corpus at all fails the gate.

THE PRECISION GATE (certifies a reported problem)
-------------------------------------------------
  The Wilson 95% lower bound of TP / (TP + FP) >= MIN_PRECISION over every triaged
  finding of the language's shipped rules on the HELD-OUT half of the REAL-repository
  corpus. UNCERTAIN is excluded from the rate (N2b) and reported; an UNTRIAGED finding
  fails the gate, and so does a language with no triaged finding there (a problem claim
  with no evidence is not certified). A finding that is not in every repeat scan of its
  commit (D2, `"stable": false`) is counted apart and kept out of the rate. Teaching
  corpora are built to trap tools: their precision is reported as a stress figure and
  gates nothing.

WHY A LOWER BOUND (P3)
----------------------
A point estimate cannot tell 4/5 from 400/500. Both gates compare the Wilson score
interval's 95% lower bound with the floor, so a small sample has to be very good to pass
and a large one passes on its rate. This replaces a minimum-sample rule: there is none.
(MIN_CORPORA is not one -- it asks for detections in two independent codebases.)

QUADRANTS
---------
  recall + precision  -> full      score and grade
  precision only      -> problem   findings and an unfavourable result; never A/B
  recall only         -> clean     a clean result may show; findings carry a caveat
  neither             -> withheld  "Not measured" (the N2 contract)

Only shipped coverage rules are evidence (silent-clean rules are not), so removing a
rule moves both gates with no hand edit.
"""
from __future__ import annotations

import functools
import json
import logging
import math
import os
from dataclasses import dataclass, field

MIN_CORPORA = 2
UNCALIBRATED_MIN_RECALL = 0.25
MIN_PRECISION = 0.70
WILSON_Z = 1.959964  # two-sided 95%

TIER_NONE = "none"
TIER_LIMITED = "limited"
TIER_STRONG = "strong"

Q_FULL, Q_PROBLEM, Q_CLEAN, Q_WITHHELD = "full", "problem-only", "clean-only", "withheld"

ACCURACY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "accuracy")
HELD_OUT = "held_out"
TUNING = "tuning"
REAL = "real"
GROUND_TRUTH = "ground-truth"


def wilson(k: int, n: int, z: float = WILSON_Z) -> tuple[float, float] | None:
    """Wilson score interval for k successes in n trials; None when n is 0."""
    if n <= 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (c - r) / d), min(1.0, (c + r) / d)


def lower_bound(k: int, n: int) -> float | None:
    w = wilson(k, n)
    return None if w is None else w[0]


def _pct(x: float) -> str:
    return f"{x:.0%}"


def quadrant(recall_ok: bool, precision_ok: bool) -> str:
    if recall_ok and precision_ok:
        return Q_FULL
    if precision_ok:
        return Q_PROBLEM
    if recall_ok:
        return Q_CLEAN
    return Q_WITHHELD


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    uncertain: int = 0
    untriaged: int = 0
    unstable: int = 0   # D2: not in every repeat scan of its commit; reported, not rated

    def add(self, verdict: str | None) -> None:
        if verdict == "TP":
            self.tp += 1
        elif verdict == "FP":
            self.fp += 1
        elif verdict == "UNCERTAIN":
            self.uncertain += 1
        else:
            self.untriaged += 1

    @property
    def precision(self) -> float | None:
        n = self.tp + self.fp
        return self.tp / n if n else None

    @property
    def precision_interval(self) -> tuple[float, float] | None:
        return wilson(self.tp, self.tp + self.fp)


@dataclass
class LanguageEvidence:
    language: str
    tier: str = TIER_NONE
    corpora: list[str] = field(default_factory=list)            # qualifying GT corpora
    detection_corpora: list[str] = field(default_factory=list)
    held_out: list[str] = field(default_factory=list)
    held_out_detected: int = 0
    held_out_in_scope: int = 0
    tuning_detected: int = 0
    tuning_in_scope: int = 0
    # the CodeQL comparison: held-out items in corpora CodeQL ran on
    reference_corpora: list[str] = field(default_factory=list)
    reference_in_scope: int = 0
    reference_aegis: int = 0
    reference_codeql: int = 0
    real: Counts = field(default_factory=Counts)          # real repos, held-out half: the gate
    real_tuning: Counts = field(default_factory=Counts)   # real repos, tuning half: reported
    stress: Counts = field(default_factory=Counts)        # ground-truth corpora: reported
    recall_failed: list[str] = field(default_factory=list)
    precision_failed: list[str] = field(default_factory=list)

    @property
    def held_out_recall(self) -> float | None:
        return self.held_out_detected / self.held_out_in_scope if self.held_out_in_scope else None

    @property
    def held_out_recall_interval(self) -> tuple[float, float] | None:
        return wilson(self.held_out_detected, self.held_out_in_scope)

    @property
    def reference_aegis_interval(self) -> tuple[float, float] | None:
        return wilson(self.reference_aegis, self.reference_in_scope)

    @property
    def tuning_recall(self) -> float | None:
        return self.tuning_detected / self.tuning_in_scope if self.tuning_in_scope else None

    @property
    def calibrated(self) -> bool:
        return self.reference_in_scope > 0

    @property
    def reference_recall(self) -> float | None:
        return self.reference_codeql / self.reference_in_scope if self.reference_in_scope else None

    @property
    def recall_ok(self) -> bool:
        return not self.recall_failed

    @property
    def precision_ok(self) -> bool:
        return not self.precision_failed

    @property
    def quadrant(self) -> str:
        return quadrant(self.recall_ok, self.precision_ok)

    @property
    def failed(self) -> list[str]:
        return self.recall_failed + self.precision_failed

    @property
    def precision(self) -> float | None:  # the gated figure
        return self.real.precision

    # N5 field names, kept for callers and stored scans
    @property
    def tp(self) -> int:
        return self.real.tp

    @property
    def fp(self) -> int:
        return self.real.fp

    @property
    def uncertain(self) -> int:
        return self.real.uncertain

    @property
    def untriaged(self) -> int:
        return self.real.untriaged

    def as_dict(self) -> dict:
        r = lambda x: None if x is None else round(x, 4)
        ci = lambda w: None if w is None else [round(w[0], 4), round(w[1], 4)]
        c = lambda k: {"tp": k.tp, "fp": k.fp, "uncertain": k.uncertain, "unstable": k.unstable,
                       "precision": r(k.precision),
                       "precision_interval": ci(k.precision_interval)}
        return {
            "language": self.language, "tier": self.tier, "quadrant": self.quadrant,
            "recall_gate": self.recall_ok, "precision_gate": self.precision_ok,
            "failed": self.failed, "recall_failed": self.recall_failed, "precision_failed": self.precision_failed,
            "corpora": len(self.corpora), "detection_corpora": len(self.detection_corpora),
            "held_out_corpora": len(self.held_out),
            "held_out_recall": r(self.held_out_recall),
            "held_out_recall_interval": ci(self.held_out_recall_interval),
            "held_out_detected": self.held_out_detected, "held_out_in_scope": self.held_out_in_scope,
            "tuning_recall": r(self.tuning_recall),
            "tuning_detected": self.tuning_detected, "tuning_in_scope": self.tuning_in_scope,
            "calibrated": self.calibrated, "reference": "codeql security-extended" if self.calibrated else None,
            "reference_in_scope": self.reference_in_scope, "reference_aegis": self.reference_aegis,
            "reference_codeql": self.reference_codeql, "reference_recall": r(self.reference_recall),
            "reference_aegis_interval": ci(self.reference_aegis_interval),
            "precision": r(self.precision), "precision_interval": ci(self.real.precision_interval),
            "tp": self.tp, "fp": self.fp,
            "uncertain": self.uncertain, "untriaged": self.untriaged, "unstable": self.real.unstable,
            "real_tuning": c(self.real_tuning), "stress": c(self.stress),
        }


def evaluate(gt: dict, triage: list[dict], shipped: dict[str, set[str]],
             languages: set[str]) -> dict[str, LanguageEvidence]:
    """Both gates for every language in `languages` (those with shipped rules).

    gt:       corpus -> {"language", "role": held_out|tuning, "codeql": {"ran": bool},
              "items": [...]}; an item has "scope" ("IN" counts), "status" ("DET"),
              "rules" (catching rule ids), optionally "promotion_evidence", and, where
              CodeQL ran on the corpus, "codeql": "DET"|"MISS".
    triage:   [{"language", "rule", "verdict", "kind": real|ground-truth,
              "role": held_out|tuning (real only)}, ...]
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
            if (c.get("codeql") or {}).get("ran"):
                ev.reference_corpora.append(corpus)
                ev.reference_in_scope += len(ins)
                ev.reference_aegis += len(det)
                ev.reference_codeql += sum(1 for i in ins if i.get("codeql") == "DET")
        else:
            ev.tuning_in_scope += len(ins)
            ev.tuning_detected += len(det)

    for t in triage:
        ev = out.get(t.get("language"))
        if ev is None or ev.language not in shipped.get(t.get("rule"), ()):
            continue  # a rule that no longer ships is not evidence either way
        if t.get("kind") == REAL:
            counts = ev.real if t.get("role") == HELD_OUT else ev.real_tuning
            if t.get("stable") is False:
                counts.unstable += 1
            else:
                counts.add(t.get("verdict"))
        else:
            ev.stress.add(t.get("verdict"))

    for ev in out.values():
        if len(ev.detection_corpora) < MIN_CORPORA:
            ev.recall_failed.append(f"corpora: documented detections in {len(ev.detection_corpora)} "
                                    f"corpus(es), needs {MIN_CORPORA}")
        if ev.calibrated:
            n, a, q = ev.reference_in_scope, ev.reference_aegis, ev.reference_codeql
            lo = lower_bound(a, n)
            if lo < q / n:
                ev.recall_failed.append(f"recall: held-out {a}/{n}, 95% lower bound {_pct(lo)}, below "
                                        f"CodeQL's {q}/{n} = {_pct(q / n)} on the same items")
        elif ev.held_out_recall is None:
            ev.recall_failed.append("recall: no held-out corpus")
        else:
            lo = lower_bound(ev.held_out_detected, ev.held_out_in_scope)
            if lo < UNCALIBRATED_MIN_RECALL:
                ev.recall_failed.append(f"recall: held-out {ev.held_out_detected}/{ev.held_out_in_scope}, "
                                        f"95% lower bound {_pct(lo)}, needs {_pct(UNCALIBRATED_MIN_RECALL)} "
                                        f"(uncalibrated: no CodeQL reference)")
        if ev.real.untriaged:
            ev.precision_failed.append(f"precision: {ev.real.untriaged} real-repo finding(s) untriaged")
        elif ev.real.precision is None:
            ev.precision_failed.append("precision: no triaged finding on held-out real repositories")
        else:
            k, n = ev.real.tp, ev.real.tp + ev.real.fp
            lo = lower_bound(k, n)
            if lo < MIN_PRECISION:
                ev.precision_failed.append(f"precision: {k}/{n} = {_pct(k / n)}, 95% lower bound {_pct(lo)}, "
                                           f"on held-out real repositories, needs {_pct(MIN_PRECISION)}")
        ev.tier = TIER_STRONG if not ev.failed else TIER_LIMITED
    return out


def _load(name: str):
    with open(os.path.join(ACCURACY_DIR, name), encoding="utf-8") as fh:
        return json.load(fh)


@functools.lru_cache(maxsize=1)
def ledger() -> tuple[dict, list[dict]]:
    """(gt_items, triage) as shipped in the image.

    Fails CLOSED: if the evidence is missing from the image, no language passes either
    gate, so every security result is withheld ("Not measured") rather than presented as
    confident. A scan never crashes on it, and tests/test_tier_bar.py fails loudly
    instead."""
    try:
        return _load("gt_items.json"), _load("triage.json")
    except (OSError, ValueError) as exc:
        logging.getLogger(__name__).error("tier evidence unavailable, every language LIMITED: %s", exc)
        return {}, []
