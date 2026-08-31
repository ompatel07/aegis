"""B1 (Pass D1): the structural guard itself must catch the two silent-degradation
shapes, honour the `# fail-open:` escape hatch, and skip rule-test fixtures — and
the real scanner tree must currently pass it. If someone re-plants an
`except: pass` or a constant-returning measurement, this test (and CI) goes red.
"""
from __future__ import annotations

import importlib.util
import textwrap
from pathlib import Path

_SCANNER = Path(__file__).resolve().parents[1]
_CHECKER = _SCANNER / "tools" / "check_no_silent_degradation.py"

_spec = importlib.util.spec_from_file_location("silent_degradation_guard", _CHECKER)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


def _kinds(path: Path):
    return {v.kind for v in guard.check_file(path)}


def test_flags_swallowed_exception(tmp_path):
    f = tmp_path / "a.py"
    f.write_text(
        textwrap.dedent(
            """
            def load():
                try:
                    risky()
                except Exception:
                    pass
            """
        )
    )
    assert "swallowed-exception" in _kinds(f)


def test_flags_bare_except_pass(tmp_path):
    f = tmp_path / "b.py"
    f.write_text("def f():\n    try:\n        g()\n    except:\n        pass\n")
    assert "swallowed-exception" in _kinds(f)


def test_flags_fabricated_measurement(tmp_path):
    f = tmp_path / "c.py"
    f.write_text(
        textwrap.dedent(
            """
            def coverage_score(path):
                '''Measure test coverage percent.'''
                try:
                    return compute(path)
                except Exception:
                    return 100
            """
        )
    )
    assert "fabricated-measurement" in _kinds(f)


def test_fail_open_marker_exempts(tmp_path):
    f = tmp_path / "d.py"
    f.write_text(
        textwrap.dedent(
            """
            def cleanup():
                try:
                    close()
                except Exception:
                    # fail-open: best-effort cleanup, nothing measured here
                    pass
            """
        )
    )
    assert _kinds(f) == set()


def test_rule_fixture_is_skipped(tmp_path):
    f = tmp_path / "e.py"
    f.write_text(
        "def broad(data):\n"
        "    # ruleid: ai-code-broad-except-pass\n"
        "    try:\n        return data['k']\n    except Exception:\n        pass\n"
    )
    assert guard.check_file(f) == []


def test_named_exception_not_flagged(tmp_path):
    # Narrow, intentional catch of a specific error is fine.
    f = tmp_path / "g.py"
    f.write_text("def f():\n    try:\n        g()\n    except KeyError:\n        pass\n")
    assert _kinds(f) == set()


def test_real_scanner_tree_is_clean():
    """The live tree must pass the guard — this is the gate that would go red if a
    silent-degradation site were introduced without a documented `# fail-open:`."""
    rc = guard.main(["check", str(_SCANNER)])
    assert rc == 0
