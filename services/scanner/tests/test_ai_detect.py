"""Tests for the AI-generated-code detector (Phase 2C TASK 3a)."""
from __future__ import annotations

import os

from ml.ai_detect import classifier, features


AI_STYLE = '''\
"""Utility module for data processing operations."""
import logging

logger = logging.getLogger(__name__)


def process_data(data):
    """This function processes the given data and returns the result.

    Args:
        data (dict): The input data to process.

    Returns:
        dict: The processed data.
    """
    # Initialize the result variable to store the output.
    result = {}
    try:
        for key, value in data.items():
            result[key] = value
    except Exception as e:
        logger.error("An error occurred: %s", e)
    # Return the final processed result.
    return result
'''

HUMAN_STYLE = '''\
import os, re

def _split(p):
    # FIXME handle windows paths
    return [x for x in re.split(r'[\\\\/]', p) if x]

def load(cfg_path, *, strict=True):
    with open(cfg_path) as fh:
        raw = fh.read()
    if strict and not raw:
        raise ValueError('empty cfg: %s' % cfg_path)
    return _split(raw)
'''


def test_feature_vector_is_complete():
    feats = features.extract(AI_STYLE, "python")
    assert set(feats.keys()) == set(features.FEATURE_NAMES)
    assert features.vector(feats) and len(features.vector(feats)) == len(features.FEATURE_NAMES)


def test_ai_style_scores_higher_than_human():
    ai = classifier.score_text(AI_STYLE, "python")
    human = classifier.score_text(HUMAN_STYLE, "python")
    assert 0.0 <= human <= 1.0 and 0.0 <= ai <= 1.0
    # The AI-style snippet must score materially higher than the terse human one.
    assert ai > human
    assert ai > 0.5


def test_empty_text_scores_zero():
    assert classifier.score_text("", "python") == 0.0


def test_heuristic_fallback_is_bounded():
    # Even without a model, the heuristic must return a valid probability.
    feats = features.extract(AI_STYLE, "python")
    p = classifier.heuristic_score(feats)
    assert 0.0 <= p <= 1.0


def test_engine_scores_a_directory(tmp_path):
    from engines import ai_code_engine
    from models.scan_request import ScanRequest

    (tmp_path / "ai_file.py").write_text(AI_STYLE, encoding="utf-8")
    (tmp_path / "human_file.py").write_text(HUMAN_STYLE, encoding="utf-8")
    result = ai_code_engine.run(ScanRequest(path=str(tmp_path), scan_id="t"))
    assert result.files_scored == 2
    assert 0.0 <= result.ai_generated_pct <= 100.0
    # file_scores holds scores >= 0.3; the AI file should be present + high.
    assert any(v >= 0.5 for v in result.file_scores.values())
