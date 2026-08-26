"""CVSS source-precedence tests (S1 Defect 2).

Never take max() across CVSS sources — that inflated scores. Pick by precedence:
NVD, then GHSA, then vendor. Record the source. Never fabricate.
"""
from __future__ import annotations

from engines.trivy_engine import _select_cvss


def test_nvd_wins_over_higher_vendor():
    cvss = {
        "nvd": {"V3Score": 7.2, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"},
        "ghsa": {"V3Score": 9.8, "V3Vector": "X"},
        "redhat": {"V3Score": 10.0, "V3Vector": "Y"},
    }
    score, source, vector = _select_cvss(cvss)
    assert score == 7.2 and source == "nvd"
    assert vector.endswith("A:N")


def test_ghsa_when_no_nvd():
    score, source, _ = _select_cvss({"ghsa": {"V3Score": 6.1}, "redhat": {"V3Score": 9.9}})
    assert score == 6.1 and source == "ghsa"


def test_vendor_when_no_nvd_or_ghsa():
    score, source, _ = _select_cvss({"redhat": {"V3Score": 5.5}, "oracle": {"V3Score": 8.0}})
    # deterministic: remaining sources sorted -> "oracle" < "redhat"
    assert source == "oracle" and score == 8.0


def test_v2_fallback_within_source():
    score, source, _ = _select_cvss({"nvd": {"V2Score": 5.0}})
    assert score == 5.0 and source == "nvd"


def test_no_score_returns_none_but_keeps_vector():
    score, source, vector = _select_cvss({"nvd": {"V3Vector": "CVSS:3.1/AV:N/..."}})
    assert score is None and source == "nvd" and vector.startswith("CVSS")


def test_empty_is_all_none():
    assert _select_cvss({}) == (None, None, None)
    assert _select_cvss(None) == (None, None, None)
