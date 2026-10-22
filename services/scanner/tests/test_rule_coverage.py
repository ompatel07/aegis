"""N2: per-language coverage is measured from the shipped rule set, and the tier
table cannot drift away from it.

The whole point of coverage is that it is counted, not declared. These tests fail if
someone deletes a language's rules without re-tiering it, adds rules for a language
still listed as uncovered, or quietly raises the confidence threshold.
"""
from __future__ import annotations

from utils import rule_coverage as rc


def test_rule_index_is_measured_from_the_shipped_rules():
    idx = rc.rule_index()
    # Measured on the N2b rule set (njsscan pruned 114 -> 89). Floors, not
    # equalities: adding rules must not fail the suite. What a TIER depends on is
    # tested separately (test_every_strong_tier_still_ships_its_evidence) -- a count
    # floor cannot catch a prune that removes the one rule a tier was proven with.
    assert idx["javascript"].rules >= 100, idx["javascript"]
    assert idx["javascript"].families.get("vendor") == 89, "njsscan pack changed; re-run N2b"
    assert idx["php"].rules >= 5 and idx["java"].rules >= 7 and idx["python"].rules >= 12
    assert idx["go"].rules >= 7
    # Quality-pillar rules must not inflate security coverage.
    for cov in idx.values():
        assert "quality" not in cov.families, f"bug-pack rules counted as security: {cov}"


def test_javascript_rules_are_counted_for_typescript_because_semgrep_runs_them():
    """Semgrep runs a `languages: [javascript]` rule on .ts/.tsx (measured, semgrep
    1.97.0). Before N2b TypeScript was reported as 11 rules while all of njsscan ran
    on it -- juice-shop's njsscan findings are on .ts files."""
    idx = rc.rule_index()
    assert idx["typescript"].families.get("vendor") == idx["javascript"].families.get("vendor")
    assert idx["typescript"].rules >= idx["javascript"].rules - 1
    assert rc.applies_to({"languages": ["javascript"]}) == ["javascript", "typescript"]
    # ...and not the reverse: a typescript rule does not run on .js.
    assert rc.applies_to({"languages": ["typescript"]}) == ["typescript"]
    assert rc.applies_to({"languages": ["javascript", "typescript"]}) == ["javascript", "typescript"]


def test_every_strong_tier_still_ships_its_evidence():
    """STRONG means proven on documented vulnerabilities. If a prune removes a rule
    that proof rests on, the tier is no longer grounded and must be re-measured."""
    assert rc.tier_evidence_gaps() == []
    assert set(rc.STRONG_EVIDENCE) == set(rc.STRONG), "every STRONG tier must name its evidence"


def test_tier_evidence_check_catches_a_prune_that_counts_would_miss():
    """The N2b failure mode: drop node_ssrf (the only rule catching NodeGoat GT4) and
    add one unrelated rule. Every count is unchanged; the evidence check must fail."""
    shipped = rc.shipped_rule_languages()
    pruned = {k: v for k, v in shipped.items() if not k.endswith(".node_ssrf")}
    pruned["some-new-rule"] = {"javascript", "typescript"}
    assert len(pruned) == len(shipped)
    gaps = rc.tier_evidence_gaps(pruned)
    assert len(gaps) == 1 and "GT4" in gaps[0] and gaps[0].startswith("javascript")
    # A rule still shipped but no longer for that language is a gap too.
    narrowed = dict(shipped)
    narrowed["aegis-js-sql-injection"] = {"javascript"}
    assert any(g.startswith("typescript") for g in rc.tier_evidence_gaps(narrowed))


def test_every_tiered_language_actually_has_rules():
    """A language may not be called strong or limited if nothing runs against it."""
    idx = rc.rule_index()
    for lang in rc.STRONG + rc.LIMITED:
        assert idx.get(lang) and idx[lang].rules > 0, (
            f"{lang} is tiered {rc.tier_of(lang)} but ships 0 security rules"
        )


def test_no_language_with_rules_is_left_untiered():
    """The converse: new rules for a language must be tiered, not silently ignored.

    Without this, adding (say) a Ruby pack would leave Ruby reported as uncovered and
    its code counted against the confidence threshold forever.
    """
    idx = rc.rule_index()
    for lang, cov in idx.items():
        if lang in rc._NON_APPLICATION:
            continue  # cicd/iac rules run on YAML; YAML is not application code
        assert rc.tier_of(lang) != rc.TIER_NONE, (
            f"{lang} ships {cov.rules} security rules but is tiered 'none'; "
            f"add it to STRONG or LIMITED in utils/rule_coverage.py"
        )


def test_languages_we_do_no_sast_on_are_tiered_none():
    for lang in ("ruby", "csharp", "c", "cpp", "rust", "kotlin", "scala"):
        assert rc.tier_of(lang) == rc.TIER_NONE
        assert rc.rule_index().get(lang) is None, f"{lang} now has rules; re-tier it"


def test_limited_language_repo_is_not_confident():
    """The scanner half of the N2 gate (the orchestrator half is
    pipeline/coverage_confidence_test.go). N2 wrote it for Java; N4 moved Java to
    STRONG, so it now holds for Go, the language still LIMITED."""
    cov = rc.summarise({"go": 5000})
    assert cov is not None
    assert cov["confident"] is False
    assert cov["strong_fraction"] == 0.0
    # the gap names the MEASURED rule count, not a constant
    assert "Go" in cov["gap"] and f"{rc.rule_index()['go'].rules} rules" in cov["gap"]
    assert cov["summary"] == "Go limited"


def test_java_and_python_are_strong_on_n4_ground_truth():
    """N4: both taint packs caught documented vulnerabilities in more than one
    ground-truth corpus. The proof is named per rule in STRONG_EVIDENCE and must ship."""
    for lang in ("java", "python"):
        assert rc.tier_of(lang) == rc.TIER_STRONG
        assert rc.STRONG_EVIDENCE.get(lang), f"{lang} is STRONG with no named evidence"
    assert rc.summarise({"java": 5000})["confident"] is True
    assert rc.summarise({"python": 5000})["confident"] is True
    assert rc.tier_of("go") == rc.TIER_LIMITED


def test_strongly_covered_repos_are_confident():
    assert rc.summarise({"php": 11000})["confident"] is True
    assert rc.summarise({"typescript": 60000, "javascript": 12000})["confident"] is True


def test_uncovered_majority_is_not_confident():
    # mastodon-shaped: 79% Ruby (no rules), 21% JS.
    cov = rc.summarise({"ruby": 150000, "javascript": 40000})
    assert cov["confident"] is False
    assert cov["uncovered_fraction"] > 0.75
    assert "Ruby" in cov["gap"] and "no rules" in cov["gap"]


def test_threshold_is_a_strong_majority():
    """Half strong / half uncovered is NOT confident: the threshold is a strict
    majority of strongly-covered code, so a thin majority cannot hide behind a
    well-covered minority."""
    assert rc.summarise({"php": 1000, "ruby": 1000})["confident"] is False
    assert rc.summarise({"php": 1001, "ruby": 999})["confident"] is True
    assert rc.CONFIDENT_STRONG_FRACTION == 0.5


def test_non_application_languages_do_not_create_coverage():
    """A Kubernetes-heavy Java repo must not look covered because we read its YAML."""
    assert rc.summarise({"yaml": 5000}) is None
    assert rc.summarise({}) is None
    cov = rc.summarise({"go": 1000, "yaml": 9000})
    assert cov["total_code_lines"] == 1000 and cov["confident"] is False


def test_coverage_payload_is_json_serialisable_and_complete():
    import json

    cov = rc.summarise({"php": 900, "java": 100})
    json.dumps(cov)  # travels to the orchestrator as JSON
    for key in ("total_code_lines", "strong_fraction", "limited_fraction",
                "uncovered_fraction", "confident", "threshold", "languages",
                "summary", "gap", "always_on"):
        assert key in cov, key
    assert cov["always_on"], "a Ruby/C# repo must still be told what DID run"
