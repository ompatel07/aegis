"""N5/N6: two claims, two gates, computed from evidence -- and both can fail.

N5 made one bar certify a clean result and a reported problem at once, and it withheld
every score. N6 gates each claim on its own evidence (docs/SECURITY_GATES_N6.md):

  recall gate     documented detections in >= 2 corpora, and held-out recall at least
                  CodeQL's on the same items (or an uncalibrated 25% where CodeQL could
                  not run) -> certifies a CLEAN result
  precision gate  >= 70% on the held-out half of the REAL-repository corpus
                  -> certifies a reported PROBLEM

These tests plant evidence that clears each gate, then drop each criterion just below
its line and assert that gate -- and only that gate -- fails. Then they hold the shipped
tiers to the shipped evidence.
"""
from __future__ import annotations

import copy

from utils import rule_coverage as rc
from utils import tier_bar as tb

LANG = "planted"
SHIPPED = {"r-sql": {LANG}, "r-xss": {LANG}}


def _corpus(role, det, total, rule="r-sql", codeql=None, **extra):
    """`codeql`: None (CodeQL did not run on this corpus) or the number of in-scope
    items CodeQL detected."""
    items = [{"id": f"d{i}", "scope": "IN", "status": "DET", "rules": [rule], **extra} for i in range(det)]
    items += [{"id": f"m{i}", "scope": "IN", "status": "GAP", "rules": []} for i in range(total - det)]
    if codeql is not None:
        for i, it in enumerate(items):
            it["codeql"] = "DET" if i < codeql else "MISS"
    items += [{"id": "o", "scope": "OUT:logic", "status": "n/a", "rules": []}]  # never counted
    return {"language": LANG, "role": role, "codeql": {"ran": codeql is not None}, "items": items}


def _triage(tp, fp, unc=0, untriaged=0, rule="r-sql", kind=tb.REAL, role=tb.HELD_OUT):
    def one(v):
        return {"language": LANG, "rule": rule, "verdict": v, "kind": kind, "role": role}
    return [one("TP")] * tp + [one("FP")] * fp + [one("UNCERTAIN")] * unc + [one("UNTRIAGED")] * untriaged


def _passing():
    gt = {"a": _corpus(tb.HELD_OUT, 5, 20),   # 25% held-out recall, uncalibrated, on the line
          "b": _corpus(tb.TUNING, 1, 10)}
    return gt, _triage(tp=70, fp=30)          # 70% real held-out precision, on the line


def _ev(gt, triage, shipped=SHIPPED):
    return tb.evaluate(gt, triage, shipped, {LANG})[LANG]


def _gates(ev):
    return [f.split(":")[0] for f in ev.recall_failed], [f.split(":")[0] for f in ev.precision_failed]


def test_planted_evidence_on_every_line_passes_both_gates():
    ev = _ev(*_passing())
    assert ev.recall_ok and ev.precision_ok, ev.failed
    assert ev.quadrant == tb.Q_FULL and ev.tier == tb.TIER_STRONG
    assert ev.held_out_recall == 0.25 and ev.precision == 0.70 and not ev.calibrated


# ── the recall gate: certifies a CLEAN result ───────────────────────────────────
def test_detections_in_one_corpus_fail_the_recall_gate_only():
    gt, triage = _passing()
    gt["b"] = _corpus(tb.TUNING, 0, 10)
    ev = _ev(gt, triage)
    assert _gates(ev) == (["corpora"], [])
    assert ev.quadrant == tb.Q_PROBLEM


def test_a_promotions_own_evidence_does_not_count_as_a_corpus():
    gt, triage = _passing()
    gt["b"] = _corpus(tb.TUNING, 1, 10, promotion_evidence=True)
    ev = _ev(gt, triage)
    assert not ev.recall_ok and ev.detection_corpora == ["a"]
    assert ev.tuning_detected == 1, "it still counts as a detection for recall"


def test_uncalibrated_recall_below_25_fails_the_recall_gate():
    gt, triage = _passing()
    gt["a"] = _corpus(tb.HELD_OUT, 4, 17)  # 23.5%, no CodeQL reference
    ev = _ev(gt, triage)
    assert _gates(ev) == (["recall"], []) and "uncalibrated" in ev.recall_failed[0]


def test_calibrated_recall_below_codeql_fails_even_above_25():
    """The floor is the market reference, not a constant: 40% fails where CodeQL got 45%."""
    gt, triage = _passing()
    gt["a"] = _corpus(tb.HELD_OUT, 8, 20, codeql=9)
    ev = _ev(gt, triage)
    assert ev.calibrated and ev.reference_recall == 0.45
    assert _gates(ev) == (["recall"], []) and "CodeQL" in ev.recall_failed[0]


def test_calibrated_recall_at_codeql_parity_passes_even_below_25():
    """Parity with the reference passes, whatever the absolute number: 10% vs CodeQL's 10%."""
    gt, triage = _passing()
    gt["a"] = _corpus(tb.HELD_OUT, 2, 20, codeql=2)
    ev = _ev(gt, triage)
    assert ev.recall_ok and ev.calibrated and ev.held_out_recall == 0.10


def test_only_corpora_codeql_ran_on_are_the_comparison():
    gt, triage = _passing()
    gt["a"] = _corpus(tb.HELD_OUT, 1, 10, codeql=1)      # parity here...
    gt["c"] = _corpus(tb.HELD_OUT, 0, 10)                 # ...a held-out corpus CodeQL could not run on
    ev = _ev(gt, triage)
    assert ev.reference_in_scope == 10 and ev.reference_corpora == ["a"]
    assert ev.held_out_in_scope == 20 and ev.recall_ok


def test_tuning_recall_cannot_stand_in_for_held_out_recall():
    gt = {"a": _corpus(tb.TUNING, 10, 10), "b": _corpus(tb.TUNING, 10, 10)}
    ev = _ev(gt, _triage(tp=100, fp=0))
    assert "recall: no held-out corpus" in ev.recall_failed and ev.precision_ok


def test_out_of_scope_items_do_not_dilute_or_pad_recall():
    gt, triage = _passing()
    for _ in range(50):
        gt["a"]["items"].append({"id": "x", "scope": "OUT:authorization", "status": "n/a", "rules": []})
    assert _ev(gt, triage).held_out_recall == 0.25


# ── the precision gate: certifies a reported PROBLEM ────────────────────────────
def test_real_precision_below_the_line_fails_the_precision_gate_only():
    gt, _ = _passing()
    ev = _ev(gt, _triage(tp=69, fp=31))
    assert _gates(ev) == ([], ["precision"])
    assert ev.quadrant == tb.Q_CLEAN


def test_stress_precision_gates_nothing():
    """Teaching corpora are built to trap tools: perfect or terrible precision there
    moves neither gate."""
    gt, real = _passing()
    for stress in (_triage(tp=0, fp=500, kind=tb.GROUND_TRUTH), _triage(tp=500, fp=0, kind=tb.GROUND_TRUTH)):
        ev = _ev(gt, real + stress)
        assert ev.precision_ok and ev.precision == 0.70
    ev = _ev(gt, _triage(tp=500, fp=0, kind=tb.GROUND_TRUTH))
    assert "precision: no triaged finding on held-out real repositories" in ev.precision_failed
    assert ev.stress.tp == 500


def test_the_tuning_half_of_the_real_corpus_gates_nothing():
    """Precision fixes are written from the tuning half, so it cannot certify them."""
    gt, real = _passing()
    ev = _ev(gt, real + _triage(tp=0, fp=1000, role=tb.TUNING))
    assert ev.precision_ok and ev.real_tuning.fp == 1000
    ev = _ev(gt, _triage(tp=1000, fp=0, role=tb.TUNING))
    assert not ev.precision_ok


def test_an_untriaged_real_finding_fails_the_precision_gate():
    gt, _ = _passing()
    ev = _ev(gt, _triage(tp=100, fp=0, untriaged=1))
    assert ev.precision_failed == ["precision: 1 real-repo finding(s) untriaged"]


def test_uncertain_is_reported_but_not_in_the_rate():
    gt, _ = _passing()
    ev = _ev(gt, _triage(tp=70, fp=30, unc=40))
    assert ev.precision_ok and ev.uncertain == 40 and ev.precision == 0.70


# ── the four quadrants ───────────────────────────────────────────────────────────
def test_the_four_quadrants():
    assert tb.quadrant(True, True) == tb.Q_FULL
    assert tb.quadrant(False, True) == tb.Q_PROBLEM
    assert tb.quadrant(True, False) == tb.Q_CLEAN
    assert tb.quadrant(False, False) == tb.Q_WITHHELD
    gt = {"a": _corpus(tb.HELD_OUT, 0, 10)}
    ev = _ev(gt, _triage(tp=1, fp=9))
    assert _gates(ev) == (["corpora", "recall"], ["precision"]) and ev.quadrant == tb.Q_WITHHELD


# ── the evidence moves with the shipped rule set ───────────────────────────────
def test_removing_the_catching_rule_moves_both_gates_with_no_hand_edit():
    gt, triage = _passing()
    ev = _ev(gt, triage, {"r-xss": {LANG}})  # r-sql pruned
    assert ev.held_out_detected == 0 and ev.detection_corpora == []
    assert not ev.recall_ok and not ev.precision_ok


def test_a_rule_that_does_not_run_on_the_language_is_not_its_evidence():
    gt, triage = _passing()
    ev = _ev(gt, triage, {"r-sql": {"other"}, "r-xss": {LANG}})
    assert ev.held_out_detected == 0 and not ev.recall_ok


# ── the repository-level claims (rule_coverage.summarise) ──────────────────────
def _plant(monkeypatch, gates, recall=0.15, precision=0.25):
    fake = {}
    for lang, (r, p) in gates.items():
        ev = tb.LanguageEvidence(language=lang)
        ev.held_out_detected, ev.held_out_in_scope = int(recall * 100), 100
        ev.held_out.append("x")
        ev.corpora.append("x")
        ev.real.tp, ev.real.fp = int(precision * 100), 100 - int(precision * 100)
        if not r:
            ev.recall_failed.append("recall: planted")
        if not p:
            ev.precision_failed.append("precision: planted")
        ev.tier = tb.TIER_STRONG if r and p else tb.TIER_LIMITED
        fake[lang] = ev
    monkeypatch.setattr(rc, "measured_tiers", lambda: fake)


def test_repository_quadrant_follows_the_majority_of_its_code_per_gate(monkeypatch):
    _plant(monkeypatch, {"java": (False, True), "php": (True, False)})
    assert rc.summarise({"java": 7000, "php": 3000})["quadrant"] == tb.Q_PROBLEM
    assert rc.summarise({"java": 3000, "php": 7000})["quadrant"] == tb.Q_CLEAN
    assert rc.summarise({"java": 5000, "php": 5000})["quadrant"] == tb.Q_WITHHELD  # strict majority


def test_the_clean_label_states_what_we_checked_and_how_hard(monkeypatch):
    _plant(monkeypatch, {"java": (False, True)}, recall=0.15)
    cov = rc.summarise({"java": 5000})
    assert cov["quadrant"] == tb.Q_PROBLEM and cov["confident"] is False
    assert cov["clean_label"] == "No issues found in what we check · Java 15% held-out recall"
    assert cov["precision_caveat"] is None


def test_the_precision_caveat_names_the_measured_precision(monkeypatch):
    _plant(monkeypatch, {"php": (True, False)}, precision=0.25)
    cov = rc.summarise({"php": 5000})
    assert cov["quadrant"] == tb.Q_CLEAN
    assert "PHP 25% precise (25/100)" in cov["precision_caveat"]


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
        assert rc.evidence_of(lang).quadrant == ev.quadrant, lang


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

    for name in ("gt_items.json", "triage.json", "holdout.json", "holdout_n6.json"):
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



# ── the evidence was drawn before it was used (docs/SECURITY_GATES_N6.md §0) ─────
def test_held_out_corpora_are_the_ones_drawn_before_any_rule_change():
    import json
    import os

    gt, _ = tb.ledger()
    for fname in ("holdout.json", "holdout_n6.json"):
        drawn = json.load(open(os.path.join(tb.ACCURACY_DIR, fname), encoding="utf-8"))
        for lang, d in drawn["languages"].items():
            held = {c for c, v in gt.items() if v["language"] == lang and v["role"] == tb.HELD_OUT}
            assert set(d["held_out"]) <= held, (fname, lang, held, d["held_out"])


def test_real_findings_carry_the_precision_holdout_drawn_first():
    import json
    import os

    drawn = json.load(open(os.path.join(tb.ACCURACY_DIR, "holdout_n6.json"), encoding="utf-8"))["precision"]
    held, tuning = set(drawn["held_out"]), set(drawn["tuning"])
    _, triage = tb.ledger()
    for t in triage:
        if t["kind"] == tb.REAL:
            assert t["corpus"] in held | tuning, t["corpus"]
            assert t["role"] == (tb.HELD_OUT if t["corpus"] in held else tb.TUNING), t


# ── the measured N6 outcome. These pin the shipped evidence's verdict; they change
# when the evidence changes, never by editing a tier. ─────────────────────────────
def test_n6_quadrants_are_the_measured_ones():
    q = {l: rc.evidence_of(l).quadrant for l in ("php", "python", "go", "java", "javascript", "typescript")}
    assert q == {"php": tb.Q_CLEAN, "python": tb.Q_CLEAN, "go": tb.Q_PROBLEM,
                 "java": tb.Q_WITHHELD, "javascript": tb.Q_WITHHELD, "typescript": tb.Q_WITHHELD}, q


def test_recall_is_calibrated_against_codeql_wherever_it_could_run():
    for lang in ("python", "java", "javascript", "typescript", "go"):
        ev = rc.evidence_of(lang)
        assert ev.calibrated and ev.reference_in_scope > 0, lang
    php = rc.evidence_of("php")
    assert not php.calibrated
    assert any("uncalibrated" in f for f in php.recall_failed) is False  # PHP passes the absolute floor
    assert php.held_out_recall >= tb.UNCALIBRATED_MIN_RECALL


def test_codeql_never_ran_where_its_license_does_not_reach():
    gt, _ = tb.ledger()
    for corpus in ("java-sec-code", "govwa"):
        assert gt[corpus]["codeql"]["ran"] is False and "license" in gt[corpus]["codeql"]["reason"]
    for corpus in ("bwapp", "mutillidae", "xvwa"):
        assert gt[corpus]["codeql"]["ran"] is False and "PHP" in gt[corpus]["codeql"]["reason"]
