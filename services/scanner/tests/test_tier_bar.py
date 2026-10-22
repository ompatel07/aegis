"""N5: the STRONG bar is computed from evidence, and it can fail.

N4 tiered Java STRONG at 15% recall because its bar ("caught something in two
corpora") was an existence test 17 corpora make nearly impossible to fail, and the
tier itself was a hand-edited tuple. These tests plant evidence that clears every
criterion, then drop each criterion just below its line and assert the tier drops,
naming the criterion. Then they hold the shipped tiers to the shipped evidence.
"""
from __future__ import annotations

import copy

from utils import rule_coverage as rc
from utils import tier_bar as tb

LANG = "planted"
SHIPPED = {"r-sql": {LANG}, "r-xss": {LANG}}


def _corpus(role, det, total, rule="r-sql", **extra):
    items = [{"id": f"d{i}", "scope": "IN", "status": "DET", "rules": [rule], **extra} for i in range(det)]
    items += [{"id": f"m{i}", "scope": "IN", "status": "GAP", "rules": []} for i in range(total - det)]
    items += [{"id": "o", "scope": "OUT:logic", "status": "n/a", "rules": []}]  # never counted
    return {"language": LANG, "role": role, "items": items}


def _triage(tp, fp, unc=0, untriaged=0, rule="r-sql"):
    return ([{"language": LANG, "rule": rule, "verdict": "TP"}] * tp
            + [{"language": LANG, "rule": rule, "verdict": "FP"}] * fp
            + [{"language": LANG, "rule": rule, "verdict": "UNCERTAIN"}] * unc
            + [{"language": LANG, "rule": rule, "verdict": "UNTRIAGED"}] * untriaged)


def _passing():
    gt = {"a": _corpus(tb.HELD_OUT, 5, 20),   # 25% held-out recall, exactly on the line
          "b": _corpus(tb.TUNING, 1, 10)}
    return gt, _triage(tp=70, fp=30)          # 70% precision, exactly on the line


def _tier(gt, triage, shipped=SHIPPED):
    return tb.evaluate(gt, triage, shipped, {LANG})[LANG]


def test_planted_evidence_on_every_line_is_strong():
    ev = _tier(*_passing())
    assert ev.tier == tb.TIER_STRONG, ev.failed
    assert ev.held_out_recall == 0.25 and ev.precision == 0.70
    assert ev.detection_corpora == ["a", "b"] and ev.failed == []


# ── criterion 1: documented detections in >= 2 corpora ──────────────────────────
def test_detections_in_one_corpus_fail_the_bar():
    gt, triage = _passing()
    gt["b"] = _corpus(tb.TUNING, 0, 10)
    ev = _tier(gt, triage)
    assert ev.tier == tb.TIER_LIMITED
    assert any(f.startswith("corpora:") for f in ev.failed), ev.failed


def test_a_promotions_own_evidence_does_not_count_as_a_corpus():
    """N4's circularity rule, now enforced: the detection a rule was promoted on cannot
    also prove the language."""
    gt, triage = _passing()
    gt["b"] = _corpus(tb.TUNING, 1, 10, promotion_evidence=True)
    ev = _tier(gt, triage)
    assert ev.tier == tb.TIER_LIMITED and ev.detection_corpora == ["a"]
    assert ev.tuning_detected == 1, "it still counts as a detection for recall"


# ── criterion 2: held-out recall >= 25% ─────────────────────────────────────────
def test_held_out_recall_below_the_line_fails_the_bar():
    gt, triage = _passing()
    gt["a"] = _corpus(tb.HELD_OUT, 4, 17)  # 23.5%
    ev = _tier(gt, triage)
    assert ev.tier == tb.TIER_LIMITED
    assert any(f.startswith("recall:") for f in ev.failed), ev.failed


def test_tuning_recall_cannot_stand_in_for_held_out_recall():
    """A language tuned to 100% on the corpora its rules were written from, with
    nothing held out, is not STRONG: that recall is inflated by construction."""
    gt = {"a": _corpus(tb.TUNING, 10, 10), "b": _corpus(tb.TUNING, 10, 10)}
    ev = _tier(gt, _triage(tp=100, fp=0))
    assert ev.tier == tb.TIER_LIMITED
    assert "recall: no held-out corpus" in ev.failed


def test_out_of_scope_items_do_not_dilute_or_pad_recall():
    gt, triage = _passing()
    for _ in range(50):
        gt["a"]["items"].append({"id": "x", "scope": "OUT:authorization", "status": "n/a", "rules": []})
    assert _tier(gt, triage).held_out_recall == 0.25


# ── criterion 3: precision >= 70% over every triaged finding ────────────────────
def test_precision_below_the_line_fails_the_bar():
    gt, _ = _passing()
    ev = _tier(gt, _triage(tp=69, fp=31))
    assert ev.tier == tb.TIER_LIMITED
    assert any(f.startswith("precision:") for f in ev.failed), ev.failed


def test_an_untriaged_finding_fails_the_bar():
    """An unread finding cannot support a precision claim, however good the rest is."""
    gt, _ = _passing()
    ev = _tier(gt, _triage(tp=100, fp=0, untriaged=1))
    assert ev.tier == tb.TIER_LIMITED
    assert "precision: 1 finding(s) untriaged" in ev.failed


def test_no_triaged_finding_fails_the_bar():
    gt, _ = _passing()
    ev = _tier(gt, [])
    assert ev.tier == tb.TIER_LIMITED and "precision: no triaged finding" in ev.failed


def test_uncertain_is_reported_but_not_in_the_rate():
    gt, _ = _passing()
    ev = _tier(gt, _triage(tp=70, fp=30, unc=40))
    assert ev.tier == tb.TIER_STRONG and ev.uncertain == 40 and ev.precision == 0.70


# ── the evidence moves with the shipped rule set ───────────────────────────────
def test_removing_the_catching_rule_drops_the_tier_with_no_hand_edit():
    gt, triage = _passing()
    shipped = {"r-xss": {LANG}}  # r-sql pruned
    ev = _tier(gt, triage, shipped)
    assert ev.tier == tb.TIER_LIMITED
    assert ev.held_out_detected == 0 and ev.detection_corpora == []
    assert "precision: no triaged finding" in ev.failed, "a pruned rule's findings stop counting too"


def test_a_rule_that_does_not_run_on_the_language_is_not_its_evidence():
    gt, triage = _passing()
    ev = _tier(gt, triage, {"r-sql": {"other"}, "r-xss": {LANG}})
    assert ev.tier == tb.TIER_LIMITED and ev.held_out_detected == 0


def test_every_criterion_failing_is_reported_not_just_the_first():
    gt = {"a": _corpus(tb.HELD_OUT, 0, 10)}
    ev = _tier(gt, _triage(tp=1, fp=9))
    assert [f.split(":")[0] for f in ev.failed] == ["corpora", "recall", "precision"]


# ── the shipped tiers are the computed ones ────────────────────────────────────
def test_no_tier_is_declared_in_rule_coverage():
    for name in ("STRONG", "LIMITED", "STRONG_EVIDENCE", "tier_evidence_gaps"):
        assert not hasattr(rc, name), f"rule_coverage.{name} is a hand-declared tier again"


def test_shipped_tiers_equal_the_bar_evaluated_on_the_shipped_evidence():
    gt, triage = tb.ledger()
    shipped = rc.shipped_rule_languages()
    langs = {l for ls in shipped.values() for l in ls if l not in rc._NON_APPLICATION}
    fresh = tb.evaluate(copy.deepcopy(gt), copy.deepcopy(triage), shipped, langs)
    for lang, ev in fresh.items():
        assert rc.tier_of(lang) == ev.tier, (lang, ev.failed)
        assert ev.tier == tb.TIER_STRONG or ev.failed, f"{lang} is limited with no failing criterion"


def test_every_rule_the_evidence_names_still_ships():
    """The N2b mechanism, kept: the evidence names the rules it was measured with. A
    prune of one of them must re-measure the ground truth, not silently shrink it."""
    gt, triage = tb.ledger()
    shipped = rc.shipped_rule_languages()
    silent = rc.silent_clean_rule_ids()
    named = {r for c in gt.values() for i in c["items"] for r in i.get("rules") or []}
    named |= {t["rule"] for t in triage if t.get("language") not in rc._NON_APPLICATION}
    stale = sorted(r for r in named if r not in shipped and r not in silent)
    assert not stale, f"evidence names rules that no longer ship -- re-measure: {stale}"


def test_the_evidence_ships_in_the_image():
    """ledger() fails closed (every language LIMITED) if the files are missing; this is
    the loud half, so a packaging mistake cannot silently withhold every score."""
    import os

    for name in ("gt_items.json", "triage.json", "holdout.json"):
        assert os.path.exists(os.path.join(tb.ACCURACY_DIR, name)), name
    gt, triage = tb.ledger()
    assert gt and triage


def test_missing_evidence_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(tb, "ACCURACY_DIR", str(tmp_path))
    tb.ledger.cache_clear()
    try:
        gt, triage = tb.ledger()
        assert gt == {} and triage == []
        ev = tb.evaluate(gt, triage, SHIPPED, {LANG})[LANG]
        assert ev.tier == tb.TIER_LIMITED
    finally:
        tb.ledger.cache_clear()


def test_every_ground_truth_corpus_has_a_role_and_a_commit():
    gt, _ = tb.ledger()
    for name, c in gt.items():
        assert c.get("role") in (tb.HELD_OUT, tb.TUNING), name
        assert c.get("commit"), f"{name}: ground truth without a recorded commit"
        assert c.get("documented_list"), f"{name}: ground truth without its published list"


def test_ledger_verdicts_are_known():
    _, triage = tb.ledger()
    assert {t["verdict"] for t in triage} <= {"TP", "FP", "UNCERTAIN", "UNTRIAGED"}


# ── the coverage line carries the measured recall, every tier ───────────────────
def test_coverage_line_shows_recall_next_to_every_language():
    for lang in ("java", "python", "go", "php", "javascript", "typescript"):
        cov = rc.summarise({lang: 5000})
        line = cov["summary"]
        assert "recall" in line, f"{lang}: tier shown without its measured recall: {line!r}"
        assert cov["languages"][0]["evidence"] is not None


def test_recall_phrase_formats():
    assert rc.recall_phrase({"corpora": 6, "held_out_corpora": 2, "held_out_recall": 0.1176,
                             "tuning_recall": 0.15}) == "12% held-out recall on 2 corpora"
    assert rc.recall_phrase({"corpora": 1, "held_out_corpora": 1, "held_out_recall": 0.5,
                             "tuning_recall": None}) == "50% held-out recall on 1 corpus"
    assert rc.recall_phrase({"corpora": 2, "held_out_corpora": 0, "held_out_recall": None,
                             "tuning_recall": 0.58}) == "58% recall on 2 tuning corpora, none held out"
    assert rc.recall_phrase(None) == "recall not measured"
    assert rc.language_line({"language": "ruby", "tier": rc.TIER_NONE}) == "Ruby — none · no rules"


# ── the measured N5 outcome (docs/GROUND_TRUTH_N5.md). These pin the shipped evidence's
# verdict; they change when the evidence changes, never by editing a tier. ──────────
def test_java_leaves_strong_through_the_bar_not_by_hand():
    """N4 declared Java STRONG at 15% recall. The bar takes it out on recall alone: it
    has documented detections in >= 2 corpora and >= 70% precision."""
    ev = rc.evidence_of("java")
    assert ev.tier == tb.TIER_LIMITED
    assert [f.split(":")[0] for f in ev.failed] == ["recall"], ev.failed
    assert len(ev.detection_corpora) >= tb.STRONG_MIN_CORPORA
    assert ev.precision >= tb.STRONG_MIN_PRECISION
    assert ev.held_out_recall < tb.STRONG_MIN_RECALL


def test_php_is_measured_on_three_new_held_out_corpora_and_fails_on_precision():
    ev = rc.evidence_of("php")
    assert set(ev.held_out) == {"bwapp", "mutillidae", "xvwa"}
    assert "dvwa" in ev.corpora and "dvwa" not in ev.held_out
    assert ev.held_out_recall >= tb.STRONG_MIN_RECALL
    assert [f.split(":")[0] for f in ev.failed] == ["precision"], ev.failed


def test_held_out_corpora_are_the_ones_drawn_before_any_rule_change():
    import json
    import os

    drawn = json.load(open(os.path.join(tb.ACCURACY_DIR, "holdout.json"), encoding="utf-8"))
    gt, _ = tb.ledger()
    for lang, d in drawn["languages"].items():
        held = {c for c, v in gt.items() if v["language"] == lang and v["role"] == tb.HELD_OUT}
        assert held == set(d["held_out"]), (lang, held, d["held_out"])
