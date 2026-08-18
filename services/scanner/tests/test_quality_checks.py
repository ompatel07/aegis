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


def test_magic_number_finding_ignores_svg_icon_coordinates():
    # An SVG icon component's numbers are path/coordinate/filter geometry, not
    # extractable constants — flagging them is noise.
    lines = [
        "const Arrow = (props) => (",
        "  <svg width={props.width || 50} height={props.height || 50}",
        '    viewBox="0 0 52 2047" {...props}>',
        '    <path d="M8 24a1 1 0 1 0 0 2v-2Zm34.707 1.707-6.364-6.364L40.586 25l-5.657 5.657z" />',
        '    <filter x={3} y={17.636} width={44} height={22.728}>',
        "      <feOffset dy={4} /><feGaussianBlur stdDeviation={2} />",
        '      <feColorMatrix values="0 0 0 0 0 0 0 0 0 127 0" />',
        "    </filter>",
        "  </svg>",
        ")",
    ]
    assert q._magic_number_finding(lines, "src/Icons/Arrow.js", "javascript") is None


def test_magic_number_finding_still_flags_logic_beside_inline_svg():
    # Real magic numbers in the surrounding logic must still be caught even when the
    # file also renders an inline SVG.
    lines = [
        "function Chart() {",
        "  doLayout(1440, 733, 91, 42, 8675, 512, 4096);",
        "  return <svg viewBox='0 0 52 2047'><path d='M26 0V314C12 314 51 353z'/></svg>;",
        "}",
    ]
    finding = q._magic_number_finding(lines, "src/Chart.jsx", "javascript")
    assert finding is not None
    assert finding.metadata["magic_number_count"] >= q._MAGIC_MIN


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
