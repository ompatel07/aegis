"""Tests for the extra quality checks: nesting depth and magic numbers."""
from __future__ import annotations

from engines import quality_engine as q


def test_brace_nesting_excludes_function_block():
    body = [
        "function f() {",       # function's own block -> not counted
        "  if (a) {",           # nesting 1
        "    for (;;) {",       # nesting 2
        "      while (x) {",    # nesting 3
        "        if (y) {",     # nesting 4
        "          g();",
        "        }",
        "      }",
        "    }",
        "  }",
        "}",
    ]
    assert q._brace_nesting(body) == 4


def test_indent_nesting_python():
    body = [
        "def f():",
        "    if a:",
        "        for x in y:",
        "            while z:",
        "                do()",
    ]
    assert q._indent_nesting(body) == 4


def test_magic_number_finding_flags_number_heavy_file():
    lines = ["x = 42", "y = 137", "z = 256", "w = 999", "a = 7", "b = 88", "c = 13"]
    finding = q._magic_number_finding(lines, "src/calc.js", "javascript")
    assert finding is not None
    assert finding.metadata["magic_number_count"] >= q._MAGIC_MIN


def test_magic_number_finding_ignores_constants_and_trivial():
    lines = ["const MAX_SIZE = 100", "i = 0", "j = 1", "k = 2", "flag = -1", "PORT = 8080"]
    # Only the two constant defs contain non-trivial numbers, and both are excluded.
    assert q._magic_number_finding(lines, "src/config.js", "javascript") is None


def test_magic_number_finding_skips_test_files():
    lines = [f"expect(x).toBe({n})" for n in range(10, 30)]
    assert q._magic_number_finding(lines, "src/calc.test.js", "javascript") is None


def test_tech_debt_marker_detected():
    lines = ["// TODO: fix this", "const x = 1", "# FIXME later", "code()"]
    f = q._tech_debt_finding(lines, "src/a.js", "javascript")
    assert f is not None and f.metadata["marker_count"] == 2


def test_tech_debt_ignores_word_in_string_literal():
    lines = ['const msg = "the TODO list";', "run()"]  # not in a comment
    assert q._tech_debt_finding(lines, "src/a.js", "javascript") is None


def test_debug_statement_flags_console_and_debugger():
    lines = ["function f() {", "  console.log('x');", "  debugger", "}"]
    f = q._debug_statement_finding(lines, "app/routes/x.js", "javascript")
    assert f is not None and f.metadata["debug_count"] == 2


def test_debug_statement_skips_test_files():
    assert q._debug_statement_finding(["console.log('x')"], "test/x.spec.js", "javascript") is None
