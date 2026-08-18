"""Tests for token-normalized clone detection.

The point of token normalization is to catch clones that survive variable
renaming and reformatting — the cases naive line-hashing misses. These tests
assert exactly that, and that genuinely distinct code is not flagged.
"""
from __future__ import annotations

from utils import duplication

# Same algorithm, DIFFERENT identifier names and DIFFERENT formatting/indent.
_ORIGINAL = '''\
def compute_totals(items, rate):
    total = 0
    count = 0
    for item in items:
        value = item * rate
        total = total + value
        count = count + 1
        if value > 100:
            total = total - 1
    average = total / count
    return average
'''

_RENAMED_REFORMATTED = '''\
def compute_totals(elements, factor):
        sum_value = 0
        n = 0
        for element in elements:
            v = element * factor
            sum_value = sum_value + v
            n = n + 1
            if v > 100:
                sum_value = sum_value - 1
        mean = sum_value / n
        return mean
'''


def _write(root, rel, content):
    p = root / rel
    p.write_text(content, encoding="utf-8")
    return str(p)


def test_detects_renamed_and_reformatted_clone(tmp_path):
    a = _write(tmp_path, "a.py", _ORIGINAL)
    b = _write(tmp_path, "b.py", _RENAMED_REFORMATTED)
    dup_count, clones = duplication.find_clones([(a, "python"), (b, "python")], str(tmp_path))

    assert clones, "renamed + reformatted duplicate was not detected"
    assert dup_count > 0
    files = {c["file"] for c in clones}
    peers = {p.split(":")[0] for c in clones for p in c["peers"]}
    assert "a.py" in files and "b.py" in (files | peers)


def test_no_false_clone_on_distinct_code(tmp_path):
    a = _write(tmp_path, "a.py", _ORIGINAL)
    other = '''\
def render_report(rows, template):
    output = []
    for row in rows:
        line = template.format(name=row.name, score=row.score)
        output.append(line.upper())
    header = "REPORT"
    footer = "END"
    return header + "\\n" + "\\n".join(output) + "\\n" + footer
'''
    b = _write(tmp_path, "b.py", other)
    _dup, clones = duplication.find_clones([(a, "python"), (b, "python")], str(tmp_path))
    assert clones == [], f"distinct code wrongly flagged as duplicate: {clones}"


# Two SVG icon components share the boilerplate `<svg id=… viewBox>` scaffold but
# are distinct presentational assets (a plus icon vs a minus icon) — clone detection
# should NOT flag them: there is no reusable logic to extract.
_ICON_MINUS = '''\
export function Minus(props) {
    return (
      <svg
        id="Layer_1"
        data-name="Layer 1"
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 16 16"
        {...props}
      >
        <defs>
          <style>{'.cls-1{fill-rule:evenodd}'}</style>
        </defs>
        <path className="cls-1" d="M.5 8.5v-1h15v1z" />
      </svg>
    );
  }
'''
_ICON_PLUS = '''\
export function Plus(props) {
    return (
      <svg
        id="Layer_1"
        data-name="Layer 1"
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 16 16"
        {...props}
      >
        <defs>
          <style>{'.cls-1{fill-rule:evenodd}'}</style>
        </defs>
        <path className="cls-1" d="M.5 8.5v-1h15v1z" />
        <path className="cls-1" d="M8.5 15.5h-1V.5h1z" />
      </svg>
    );
  }
'''


def test_svg_icon_components_not_flagged_as_clones(tmp_path):
    a = _write(tmp_path, "Minus.js", _ICON_MINUS)
    b = _write(tmp_path, "Plus.js", _ICON_PLUS)
    _dup, clones = duplication.find_clones([(a, "javascript"), (b, "javascript")], str(tmp_path))
    assert clones == [], f"SVG icon scaffold wrongly flagged as duplicate: {clones}"


def test_svg_dominated_detection_is_precise():
    assert duplication._is_svg_dominated(_ICON_MINUS) is True
    # A real logic file that merely mentions '<svg' in a string is NOT SVG-dominated.
    logic = (
        "function build() {\n"
        "  for (let i = 0; i < 10; i++) { emit(i); }\n"
        "  const tag = '<svg/>';\n"
        "  return render(tag) + compute(a, b, c);\n"
        "}\n"
    )
    assert duplication._is_svg_dominated(logic) is False


def test_normalize_tokens_collapses_identifiers_keeps_literals():
    toks = [t for t, _ln in duplication.normalize_tokens("x = foo(42, 'hi')\n", "python")]
    assert toks.count("ID") == 2  # x, foo -> ID (rename-insensitive)
    assert "42" in toks  # numeric literal kept verbatim (distinguishes distinct code)
    assert any("hi" in t for t in toks)  # string literal kept, not collapsed
    assert "STR" not in toks and "NUM" not in toks
    assert "=" in toks and "(" in toks  # operators/punctuation preserved
