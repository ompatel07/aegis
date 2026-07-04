"""Turn a real human file into an AI-style positive sample by applying the
documented LLM refactoring tells — *without* changing its size, vocabulary, or
structure. Only the signals move.

This is the honest way to build the positive class: human and AI samples are
drawn from the *same* real code, differing only in the tells (generic naming,
boilerplate docstrings, uniform quoting, cargo-cult exception handling, no
TODOs). The classifier therefore learns to detect those tells rather than a
trivial "this text is synthetic" artifact — keeping cross-validation honest.

The transformed text is used for feature extraction only; it never needs to be
runnable, so renaming can be aggressive.
"""
from __future__ import annotations

import random
import re

_GENERIC = ["result", "data", "output", "response", "item", "value", "temp",
            "res", "obj", "payload", "content", "info", "user_data", "temp_result"]
_KEEP = {"self", "cls", "this", "true", "false", "none", "null", "return", "if",
         "for", "in", "len", "int", "str", "def", "function", "const", "let",
         "var", "class", "import", "from", "print", "log", "error"}
_IDENT_DEF = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


def _rename_generic(text: str, rng: random.Random) -> str:
    idents = {m.group(0) for m in _IDENT_DEF.finditer(text)
              if m.group(0).lower() not in _KEEP and m.group(0).islower()}
    idents = list(idents)
    rng.shuffle(idents)
    take = idents[: max(1, int(len(idents) * rng.uniform(0.35, 0.65)))]
    for name in take:
        repl = rng.choice(_GENERIC)
        text = re.sub(rf"\b{re.escape(name)}\b", repl, text)
    return text


def _add_docstrings(text: str, rng: random.Random, lang: str) -> str:
    out = []
    for line in text.split("\n"):
        out.append(line)
        if lang == "python" and re.match(r"^(\s*)def\s+\w+\(.*\):\s*$", line):
            indent = re.match(r"^(\s*)", line).group(1) + "    "
            out.append(f'{indent}"""This function processes the given input and returns the result.\n\n'
                       f"{indent}Args:\n{indent}    input: The value to process.\n\n"
                       f"{indent}Returns:\n{indent}    The processed result.\n{indent}\"\"\"")
        elif lang != "python" and re.match(r"^\s*(?:async\s+)?function\s+\w+", line):
            out.insert(len(out) - 1, "/**\n * This function processes the input and returns the result.\n"
                                     " * @param input The value to process.\n * @returns The result.\n */")
    return "\n".join(out)


def _add_sentence_comments(text: str, rng: random.Random, lang: str) -> str:
    marker = "#" if lang == "python" else "//"
    lines = text.split("\n")
    out = []
    for line in lines:
        if re.match(r"^\s*(?:def |function |const |let |var )", line) and rng.random() < 0.5:
            indent = re.match(r"^(\s*)", line).group(1)
            out.append(f"{indent}{marker} Initialize the value to store the processed output.")
        out.append(line)
    return "\n".join(out)


def _normalize_quotes(text: str) -> str:
    return text.replace("'", '"')


def _strip_todos(text: str) -> str:
    return re.sub(r"(?im)^.*\b(todo|fixme|xxx|hack)\b.*$\n?", "", text)


def _add_broad_except(text: str, lang: str) -> str:
    if lang == "python":
        return re.sub(r"except\s+\w+(\s+as\s+\w+)?\s*:", "except Exception as e:", text, count=2)
    return re.sub(r"catch\s*\(\s*\w+\s*\)", "catch (error)", text, count=2)


def to_ai_style(text: str, lang: str, rng: random.Random) -> str:
    """Apply a random subset of AI tells to real code text (probabilistic overlap)."""
    if rng.random() < 0.6:
        text = _rename_generic(text, rng)
    if rng.random() < 0.6:
        text = _add_docstrings(text, rng, lang)
    if rng.random() < 0.55:
        text = _add_sentence_comments(text, rng, lang)
    if rng.random() < 0.7:
        text = _normalize_quotes(text)
    if rng.random() < 0.8:
        text = _strip_todos(text)
    if rng.random() < 0.4:
        text = _add_broad_except(text, lang)
    return text
