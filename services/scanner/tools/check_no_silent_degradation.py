#!/usr/bin/env python3
"""B1 structural guard (Pass D1): fail the build on silent-degradation patterns.

Silent degradation is the reflex this whole pass exists to kill: when Aegis does
not know something, it substitutes a plausible number instead of saying "not
measured". This checker makes the greppable shapes of that reflex a build error.

Two classes, both AST-detected over the scanner's Python:

  1. SWALLOWED EXCEPTION -- `except:` or `except Exception:` (or `BaseException`)
     whose body is only `pass`/`...`. Swallowing an error silently is how a failed
     measurement becomes an invisible one.

  2. FABRICATED MEASUREMENT -- a function whose NAME or DOCSTRING says it measures
     something (score/rating/density/coverage/count/...), returning a hardcoded
     numeric constant from INSIDE an `except` handler. That is substituting a
     number for a failure -- exactly the bug.

Either is allowed ONLY at a site that carries a `# fail-open:` comment naming why
failing open is correct there. The marker is deliberate, greppable, and forces the
author to write down the justification the reviewer can then check.

Usage:  python3 scripts/ci/check_no_silent_degradation.py [PATHS...]
Exit 0 if clean; exit 1 with a report listing every violation.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

# Words that mark a function as producing a MEASUREMENT (a number that means
# something about the code under scan). Matched against function name and the
# first line of its docstring.
_MEASURE_WORDS = re.compile(
    r"score|rating|measure|density|coverag|count|ratio|percent|complexit|"
    r"duplicat|maintainab|reliab|churn|smell|lines_of_code|\bloc\b|\bkloc\b",
    re.IGNORECASE,
)

# The one sanctioned escape hatch. A handler/return is exempt iff a line within
# its source span carries this marker followed by a reason.
_ALLOW_MARKER = re.compile(r"#\s*fail-open:\s*\S")

# Default to the scanner package (this file lives in services/scanner/tools/), so
# the guard lints the same tree no matter what directory it is invoked from.
_DEFAULT_ROOTS = [str(Path(__file__).resolve().parents[1])]
# Directories we never lint (third-party, generated, this checker's own tests).
_SKIP_PARTS = {".venv", "venv", "node_modules", "__pycache__", ".git", "site-packages"}


class Violation:
    __slots__ = ("path", "line", "kind", "detail")

    def __init__(self, path: str, line: int, kind: str, detail: str) -> None:
        self.path = path
        self.line = line
        self.kind = kind
        self.detail = detail

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: [{self.kind}] {self.detail}"


def _span_documented(src_lines: list[str], node: ast.AST) -> bool:
    """True if the node's source span carries a `# fail-open:` reason."""
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", start)
    if start is None:
        return False
    for ln in src_lines[start - 1 : end]:
        if _ALLOW_MARKER.search(ln):
            return True
    return False


def _body_is_only_pass(handler: ast.ExceptHandler) -> bool:
    body = [n for n in handler.body if not isinstance(n, ast.Pass)]
    # allow a bare `...` and a lone docstring/constant expression
    body = [
        n
        for n in body
        if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))
    ]
    return len(body) == 0


def _handler_catches_broadly(handler: ast.ExceptHandler) -> bool:
    t = handler.type
    if t is None:  # bare `except:`
        return True
    names = []
    if isinstance(t, ast.Name):
        names = [t.id]
    elif isinstance(t, ast.Tuple):
        names = [e.id for e in t.elts if isinstance(e, ast.Name)]
    return any(n in ("Exception", "BaseException") for n in names)


def _is_measurement_func(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if _MEASURE_WORDS.search(fn.name):
        return True
    doc = ast.get_docstring(fn) or ""
    first = doc.strip().splitlines()[0] if doc.strip() else ""
    return bool(_MEASURE_WORDS.search(first))


def _numeric_returns_in_excepts(fn: ast.FunctionDef | ast.AsyncFunctionDef):
    """Yield Return nodes returning a numeric constant lexically inside an
    except handler of `fn` (not nested inside a deeper function)."""
    for handler in ast.walk(fn):
        if not isinstance(handler, ast.ExceptHandler):
            continue
        for node in ast.walk(handler):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not fn:
                # returns inside a nested def belong to that def; walk still
                # descends, but we only care about numeric-literal returns and
                # a nested measurement def is checked on its own iteration.
                continue
            if (
                isinstance(node, ast.Return)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, (int, float))
                and not isinstance(node.value.value, bool)
            ):
                yield handler, node


# Semgrep rule-test fixtures carry these annotations. They are deliberately-bad
# sample code that Aegis's OWN rules are meant to flag — not Aegis's logic — so the
# guard must not lint them.
_RULE_FIXTURE_MARKER = re.compile(r"^\s*#\s*(ruleid|ok):", re.MULTILINE)


def check_file(path: Path) -> list[Violation]:
    src = path.read_text(encoding="utf-8", errors="replace")
    if _RULE_FIXTURE_MARKER.search(src):
        return []
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        return [Violation(str(path), e.lineno or 0, "syntax-error", str(e))]
    lines = src.splitlines()
    out: list[Violation] = []

    # Class 1: swallowed broad exceptions.
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if _handler_catches_broadly(node) and _body_is_only_pass(node):
            if not _span_documented(lines, node):
                caught = "except:" if node.type is None else "except Exception:"
                out.append(
                    Violation(
                        str(path),
                        node.lineno,
                        "swallowed-exception",
                        f"`{caught} pass` silently drops the error. Handle it, or "
                        f"add `# fail-open: <why failing open is correct here>`.",
                    )
                )

    # Class 2: measurement functions that fabricate a number on an except path.
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_measurement_func(node):
            continue
        for handler, ret in _numeric_returns_in_excepts(node):
            if _span_documented(lines, handler):
                continue
            out.append(
                Violation(
                    str(path),
                    ret.lineno,
                    "fabricated-measurement",
                    f"`{node.name}` measures, but returns constant "
                    f"{ret.value.value!r} from an except handler. Return None "
                    f"(not measured), or add `# fail-open: <why>`.",
                )
            )
    return out


def iter_py_files(roots: list[str]):
    for root in roots:
        p = Path(root)
        if p.is_file() and p.suffix == ".py":
            yield p
            continue
        for f in p.rglob("*.py"):
            if _SKIP_PARTS & set(f.parts):
                continue
            yield f


def main(argv: list[str]) -> int:
    roots = argv[1:] or _DEFAULT_ROOTS
    violations: list[Violation] = []
    for f in iter_py_files(roots):
        violations.extend(check_file(f))

    if not violations:
        print("check_no_silent_degradation: clean (no undocumented fail-open sites)")
        return 0

    violations.sort(key=lambda v: (v.path, v.line))
    print("SILENT DEGRADATION GUARD FAILED\n")
    for v in violations:
        print(v)
    print(
        f"\n{len(violations)} violation(s). Each is a place Aegis could hide a "
        f"failure behind a plausible value. Fix it, or justify it with a "
        f"`# fail-open:` comment."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
