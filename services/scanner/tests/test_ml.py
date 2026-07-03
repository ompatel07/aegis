"""Tests for the privacy-safe false-positive classifier.

Asserts the privacy invariant (metadata-only features), the seed dataset, and —
when lightgbm/sklearn are present — that the model trains and cross-validates
with usable precision/recall, and that inference yields a probability.
"""
from __future__ import annotations

import pytest

from ml import features, seed

# The complete set of feature-record keys — all metadata, no source code.
_ALLOWED_KEYS = {
    "rule_id", "engine", "severity", "file_extension", "file_path_depth",
    "project_language", "project_size_bucket", "lines_of_code", "cwe",
    "owasp_category", "is_in_test_file", "is_in_generated_file", "is_direct_dependency",
}


def test_feature_record_is_metadata_only():
    finding = {
        "rule_id": "aegis-js-sql-injection", "engine": "semgrep", "severity": "critical",
        "file_path": "app/routes/x.js", "cwe_id": "CWE-89",
        "owasp_category": "A03:2021 - Injection",
        # A hostile finding that tries to smuggle code fields — must be ignored.
        "code": "db.query('SELECT ' + userId)", "lines": ["secret code here"],
        "metadata": {"nloc": 40, "lines": "db.query(...)"},
    }
    rec = features.record_from_finding(finding, {"language": "javascript", "size_bucket": "medium"})
    assert set(rec.keys()) == _ALLOWED_KEYS, "feature record leaked a non-metadata key"
    # No value in the record equals the raw code.
    assert "db.query('SELECT ' + userId)" not in rec.values()
    assert rec["is_in_test_file"] is False
    vec = features.featurize(rec)
    assert len(vec) == len(features.FEATURE_NAMES)


def test_test_and_generated_path_detection():
    assert features.is_test_path("test/e2e/login_spec.js")
    assert features.is_test_path("src/calc.test.ts")
    assert not features.is_test_path("src/app.js")
    assert features.is_generated_path("dist/bundle.js")
    assert features.is_generated_path("app/vendor/lib.min.js")
    assert not features.is_generated_path("app/routes/x.js")


def test_seed_has_both_classes():
    rows = seed.generate_seed(500)
    assert len(rows) == 500
    labels = {features.label_to_binary(r["label"]) for r in rows}
    assert labels == {0, 1}
    # A meaningful minority of false positives (not degenerate).
    fp_rate = sum(features.label_to_binary(r["label"]) for r in rows) / len(rows)
    assert 0.2 < fp_rate < 0.8


def _ml_available() -> bool:
    try:
        import lightgbm  # noqa: F401
        import sklearn  # noqa: F401

        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _ml_available(), reason="lightgbm/sklearn not installed")
def test_train_cross_validates_and_scores(tmp_path):
    from ml import train

    rows = seed.generate_seed(500)
    metrics = train.cross_validate(rows)
    # The seed has real structure (test-file / transitive / severity priors), so a
    # gradient-boosted model should learn it well above chance.
    assert metrics["precision"] >= 0.65, metrics
    assert metrics["recall"] >= 0.6, metrics
    assert metrics["roc_auc"] is None or metrics["roc_auc"] >= 0.7, metrics

    out = str(tmp_path / "model.joblib")
    train.train(rows, out)

    import os

    os.environ["FP_MODEL_PATH"] = out
    from ml import classifier

    classifier._state.update({"model": None, "loaded": False})
    classifier.ensure_model()
    p = classifier.score_finding({
        "rule_id": "quality/magic-numbers", "engine": "quality", "severity": "low",
        "file_path": "test/util.test.js", "metadata": {},
    })
    assert p is not None and 0.0 <= p <= 1.0
