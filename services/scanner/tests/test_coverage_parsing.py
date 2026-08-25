"""Coverage-report parsing (Q1 Defect 2).

We report a coverage number ONLY from a real, parsed report. These tests prove
each supported format parses to the right percentage, and — critically — that a
project with NO coverage report yields None (coverage UNKNOWN), never a
fabricated 60 and never a punitive 0.
"""
from __future__ import annotations

import pytest

from engines import quality_engine as q


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_no_report_is_unknown_not_zero_not_sixty(tmp_path):
    # A repo that ships no coverage report → UNKNOWN. This is the whole point:
    # not 0, not the old fabricated 60.
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text("export const x = 1;\n", encoding="utf-8")
    assert q._coverage_percentage(str(tmp_path)) is None


def test_lcov(tmp_path):
    _write(tmp_path, "coverage/lcov.info",
           "TN:\nSF:a.js\nLF:10\nLH:8\nend_of_record\n"
           "TN:\nSF:b.js\nLF:10\nLH:7\nend_of_record\n")  # 15/20 = 75%
    assert q._coverage_percentage(str(tmp_path)) == pytest.approx(75.0)


def test_cobertura_line_rate(tmp_path):
    _write(tmp_path, "coverage.xml",
           '<?xml version="1.0"?>\n<coverage line-rate="0.834" branch-rate="0.5"></coverage>\n')
    assert q._coverage_percentage(str(tmp_path)) == pytest.approx(83.4)


def test_jacoco_report_line_counter(tmp_path):
    _write(tmp_path, "target/site/jacoco/jacoco.xml",
           '<?xml version="1.0"?>\n<report name="app">'
           '<counter type="INSTRUCTION" missed="100" covered="300"/>'
           '<counter type="LINE" missed="20" covered="80"/>'  # 80/100 = 80%
           '</report>\n')
    assert q._coverage_percentage(str(tmp_path)) == pytest.approx(80.0)


def test_istanbul_summary(tmp_path):
    _write(tmp_path, "coverage/coverage-summary.json",
           '{"total": {"lines": {"total": 100, "covered": 92, "pct": 92.0}}}')
    assert q._coverage_percentage(str(tmp_path)) == pytest.approx(92.0)


def test_istanbul_final(tmp_path):
    # 3 statements, 2 hit = 66.67%
    _write(tmp_path, "coverage/coverage-final.json",
           '{"/x/a.js": {"s": {"0": 1, "1": 0}}, "/x/b.js": {"s": {"0": 5}}}')
    assert q._coverage_percentage(str(tmp_path)) == pytest.approx(66.6667, abs=0.01)


def test_coveragepy_json(tmp_path):
    _write(tmp_path, "coverage.json",
           '{"meta": {}, "totals": {"percent_covered": 73.5, "num_statements": 200}}')
    assert q._coverage_percentage(str(tmp_path)) == pytest.approx(73.5)


def test_go_coverprofile(tmp_path):
    # numstmt/count columns; covered stmts (count>0) / total stmts
    _write(tmp_path, "coverage.out",
           "mode: set\n"
           "app/x.go:1.1,3.2 5 1\n"   # 5 stmts, covered
           "app/x.go:5.1,7.2 5 0\n")  # 5 stmts, not covered  -> 5/10 = 50%
    assert q._coverage_percentage(str(tmp_path)) == pytest.approx(50.0)


def test_build_metrics_coverage_none_when_no_report(tmp_path):
    m = q._build_metrics(
        avg_cc=3.0, max_cc=5, total_functions=10, total_code_lines=1000,
        smell_count=2, dup_pct=0.0, comment_density=0.15,
        has_tests=True, coverage_pct=None,
    )
    assert m.test_coverage_score is None  # not 60, not 0
    assert m.has_tests is True            # honest separate signal


def test_build_metrics_coverage_uses_real_value(tmp_path):
    m = q._build_metrics(
        avg_cc=3.0, max_cc=5, total_functions=10, total_code_lines=1000,
        smell_count=2, dup_pct=0.0, comment_density=0.15,
        has_tests=True, coverage_pct=82.5,
    )
    assert m.test_coverage_score == pytest.approx(82.5)
