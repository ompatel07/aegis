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
    # Measured on the N1 rule set. These are floors, not equalities: adding rules
    # must not fail the suite, removing the ones a tier depends on must.
    assert idx["javascript"].rules >= 120, idx["javascript"]
    assert idx["javascript"].families.get("vendor") == 114, "njsscan pack missing"
    assert idx["php"].rules >= 5 and idx["java"].rules >= 7 and idx["python"].rules >= 12
    assert idx["go"].rules >= 7 and idx["typescript"].rules >= 11
    # Quality-pillar rules must not inflate security coverage.
    for cov in idx.values():
        assert "quality" not in cov.families, f"bug-pack rules counted as security: {cov}"


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


def test_java_only_repo_is_not_confident():
    """The scanner half of the N2 gate (the orchestrator half is
    pipeline/coverage_confidence_test.go)."""
    cov = rc.summarise({"java": 5000})
    assert cov is not None
    assert cov["confident"] is False
    assert cov["strong_fraction"] == 0.0
    assert "Java" in cov["gap"] and "7 rules" in cov["gap"]
    assert cov["summary"] == "Java limited"


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
    cov = rc.summarise({"java": 1000, "yaml": 9000})
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
