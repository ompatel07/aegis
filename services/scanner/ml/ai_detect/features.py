"""Metadata feature extraction for AI-generated-code detection.

Signals are derived **locally** from file text — nothing is sent externally. The
features encode the documented tells of LLM-written code (Phase 2C TASK 3a):
verbose/boilerplate docstrings, generic variable naming, cargo-cult exception
handling, and *too-consistent* style. All features are language-agnostic
(regex/state-machine based) so the same vector works for Python, JS/TS, Go, Java.

FEATURE_NAMES is the stable, ordered contract shared by dataset build, training,
and inference — never reorder; append only.
"""
from __future__ import annotations

import re

FEATURE_NAMES: list[str] = [
    "loc",                       # non-blank lines of code (log-damped)
    "blank_ratio",               # blank / total lines
    "comment_ratio",             # comment lines / non-blank lines
    "doc_boilerplate_ratio",     # AI-style doc markers (Args:/Returns:/@param/"This function")
    "generic_name_ratio",        # identifiers that are generic (result/data/output/…)
    "template_name_ratio",       # names matching AI templates (user_data/temp_result/…)
    "bare_except_ratio",         # broad/empty exception handlers / total handlers
    "trycatch_density",          # try/catch|except per 100 loc
    "avg_line_len",              # mean length of non-blank lines
    "quote_consistency",         # |#" - #'| / (#" + #')  → AI trends to 1.0
    "indent_consistency",        # fraction of indented lines on the dominant unit
    "sentence_comment_ratio",    # comments that are full sentences (Cap … .)
    "todo_density",              # TODO/FIXME/XXX per 100 loc → human tell (inverse)
    "func_density",              # function/def declarations per 100 loc
]

# Comment syntax per language family: (line-comment regex, block open, block close).
_COMMENT = {
    "python": (r"#", '"""', '"""'),
    "javascript": (r"//", "/*", "*/"),
    "typescript": (r"//", "/*", "*/"),
    "go": (r"//", "/*", "*/"),
    "java": (r"//", "/*", "*/"),
    "ruby": (r"#", "=begin", "=end"),
    "php": (r"//|#", "/*", "*/"),
}
_DEFAULT_COMMENT = (r"//|#", "/*", "*/")

# Identifiers AI reaches for by default.
_GENERIC_NAMES = {
    "result", "results", "data", "output", "input", "response", "resp", "req",
    "request", "item", "items", "value", "values", "val", "temp", "tmp", "res",
    "ret", "obj", "arr", "list", "dict", "map", "element", "el", "elem", "node",
    "content", "payload", "params", "args", "kwargs", "info", "msg", "message",
    "status", "count", "index", "idx", "key", "flag", "buffer", "handler",
}
_TEMPLATE_NAME = re.compile(
    r"^(?:user_data|temp_result|temp_\w+|\w+_result|\w+_data|\w+_list|"
    r"my_\w+|new_\w+|the_\w+|current_\w+|final_\w+)$"
)
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")
_KEYWORDS = {
    "if", "else", "elif", "for", "while", "return", "def", "class", "function",
    "func", "var", "let", "const", "import", "from", "as", "in", "is", "and",
    "or", "not", "true", "false", "none", "null", "nil", "self", "this", "new",
    "try", "except", "catch", "finally", "throw", "raise", "with", "async",
    "await", "public", "private", "static", "void", "int", "string", "bool",
    "type", "interface", "struct", "package", "end", "do", "then", "switch",
    "case", "break", "continue", "default", "extends", "implements", "super",
}

_DOC_BOILERPLATE = re.compile(
    r"(?i)\b(args|arguments|returns?|raises?|parameters?|yields?|examples?)\s*:"
    r"|@(param|returns?|throws?|description|example)\b"
    r"|:param\b|:returns?\b|:rtype\b"
    r"|\bthis (function|method|class|module) \w+"
)
_SENTENCE = re.compile(r"^[A-Z][^\n]{6,}[.!?]$")
_TODO = re.compile(r"(?i)\b(todo|fixme|xxx|hack|wip|nocommit)\b")
_FUNC = re.compile(
    r"(?m)^\s*(?:async\s+)?(?:def|function|func|fn)\b"
    r"|=>\s*\{?\s*$"
    r"|\bpublic\b.*\)\s*\{"
)
_BARE_EXCEPT = re.compile(r"except\s*:|except\s+Exception\b|catch\s*\(\s*\w*\s*\)")
_HANDLER = re.compile(r"\bexcept\b|\bcatch\b")
_TRY = re.compile(r"\btry\b|\bcatch\b|\bexcept\b")


def _lang_key(language: str | None) -> str:
    return (language or "").lower().strip()


def extract(text: str, language: str | None = None) -> dict[str, float]:
    """Return the metadata feature vector for one file's source text."""
    lines = text.split("\n")
    total = len(lines) or 1
    line_re_src, blk_open, blk_close = _COMMENT.get(_lang_key(language), _DEFAULT_COMMENT)
    line_com_re = re.compile(rf"^\s*(?:{line_re_src})")

    blank = 0
    comment_lines = 0
    sentence_comments = 0
    todo_hits = 0
    indented = 0
    indent_ok = 0
    line_len_sum = 0
    nonblank = 0
    dquote = squote = 0
    in_block = False

    for raw in lines:
        s = raw.strip()
        if not s:
            blank += 1
            continue
        nonblank += 1
        line_len_sum += min(len(raw), 200)
        dquote += raw.count('"')
        squote += raw.count("'")

        # Indentation consistency (spaces multiple of the dominant unit / tabs).
        lead = len(raw) - len(raw.lstrip(" \t"))
        if lead > 0:
            indented += 1
            if "\t" in raw[:lead] or lead % 2 == 0:
                indent_ok += 1

        # Comment detection (block state machine + line comments).
        is_comment = False
        if in_block:
            is_comment = True
            if blk_close in s:
                in_block = False
        elif blk_open and blk_open in s and (blk_close not in s.split(blk_open, 1)[1]):
            is_comment = True
            in_block = True
        elif line_com_re.search(s) or (blk_open and blk_open in s):
            is_comment = True

        if is_comment:
            comment_lines += 1
            body = re.sub(r'^[\s#/*"\']+|[\s*"\']+$', "", s)
            if _SENTENCE.match(body):
                sentence_comments += 1
        if _TODO.search(s):
            todo_hits += 1

    nonblank = nonblank or 1

    # Identifier statistics.
    idents = [m.group(0) for m in _IDENT.finditer(text)]
    idents = [i for i in idents if i.lower() not in _KEYWORDS]
    nid = len(idents) or 1
    generic = sum(1 for i in idents if i.lower() in _GENERIC_NAMES)
    template = sum(1 for i in idents if _TEMPLATE_NAME.match(i.lower()))

    handlers = len(_HANDLER.findall(text))
    bare = len(_BARE_EXCEPT.findall(text))
    trycatch = len(_TRY.findall(text))
    doc_boiler = len(_DOC_BOILERPLATE.findall(text))
    funcs = len(_FUNC.findall(text))

    qtotal = dquote + squote
    quote_consistency = abs(dquote - squote) / qtotal if qtotal else 0.5

    import math

    return {
        "loc": math.log1p(nonblank),
        "blank_ratio": blank / total,
        "comment_ratio": comment_lines / nonblank,
        "doc_boilerplate_ratio": doc_boiler / nonblank * 100,
        "generic_name_ratio": generic / nid,
        "template_name_ratio": template / nid * 100,
        "bare_except_ratio": (bare / handlers) if handlers else 0.0,
        "trycatch_density": trycatch / nonblank * 100,
        "avg_line_len": line_len_sum / nonblank,
        "quote_consistency": quote_consistency,
        "indent_consistency": (indent_ok / indented) if indented else 1.0,
        "sentence_comment_ratio": (sentence_comments / comment_lines) if comment_lines else 0.0,
        "todo_density": todo_hits / nonblank * 100,
        "func_density": funcs / nonblank * 100,
    }


def vector(feats: dict[str, float]) -> list[float]:
    """Order a feature dict into the stable model input vector."""
    return [float(feats.get(name, 0.0)) for name in FEATURE_NAMES]
