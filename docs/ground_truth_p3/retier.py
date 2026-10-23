"""P3 Part A: both gates on the shipped evidence, with Wilson 95% intervals, under the
point-estimate gates (N6) and the lower-bound gates (P3). No rule has changed.

usage (scanner container, from /app): python3 retier.py
"""
import copy
import sys

sys.path.insert(0, "/app")
from utils import rule_coverage as rc  # noqa: E402
from utils import tier_bar as tb  # noqa: E402

gt, triage = tb.ledger()
shipped = rc.shipped_rule_languages()
langs = sorted({l for ls in shipped.values() for l in ls if l not in rc._NON_APPLICATION})
ev = tb.evaluate(copy.deepcopy(gt), copy.deepcopy(triage), shipped, set(langs))


def ci(k, n):
    w = tb.wilson(k, n)
    return "-" if w is None else f"{k}/{n} = {k / n:.0%} [{w[0]:.0%}, {w[1]:.0%}]"


def n6(e):
    """The N6 point-estimate gates, recomputed on the same evidence."""
    recall = len(e.detection_corpora) >= tb.MIN_CORPORA and (
        e.reference_aegis >= e.reference_codeql if e.calibrated
        else (e.held_out_recall or 0) >= tb.UNCALIBRATED_MIN_RECALL)
    precision = not e.real.untriaged and e.real.precision is not None and e.real.precision >= tb.MIN_PRECISION
    return tb.quadrant(recall, precision)


print("| language | held-out recall (95% CI) | CodeQL, same items | real held-out precision (95% CI) "
      "| N6 quadrant | P3 quadrant |")
print("|---|---|---|---|---|---|")
for l in langs:
    e = ev[l]
    ref = f"{e.reference_codeql}/{e.reference_in_scope} = {e.reference_recall:.0%}" if e.calibrated else "not run"
    rec = ci(e.reference_aegis, e.reference_in_scope) if e.calibrated else ci(e.held_out_detected, e.held_out_in_scope)
    print(f"| {l} | {rec} | {ref} | {ci(e.real.tp, e.real.tp + e.real.fp)} | {n6(e)} | {e.quadrant} |")
print()
for l in langs:
    for f in ev[l].failed:
        print(f"- {l}: {f}")
