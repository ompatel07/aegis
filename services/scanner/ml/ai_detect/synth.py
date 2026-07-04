"""Synthetic AI-style code generation for the detector's cold-start dataset.

Human samples in the training set are **real** (cloned pre-2021 OSS, see
dataset.py). The positive (AI) class is synthesised here to exhibit the
documented LLM tells — verbose docstrings, generic naming, cargo-cult
try/except, uniform style.

Crucially each tell is applied *probabilistically per file*, not to every file.
Real AI code doesn't carry every tell at once, and real human code (e.g. Django)
carries some of them — so the two classes overlap and the classifier must learn
a genuine boundary rather than a trivial giveaway. This keeps the reported
cross-validation metrics honest. The synthetic nature of the AI class is
documented in PHASE2C_VERIFICATION_SUMMARY.md; it is a cold-start prior refined
by real user feedback over time.
"""
from __future__ import annotations

import random

_VERBS = ["process", "compute", "calculate", "fetch", "retrieve", "build",
          "generate", "parse", "validate", "transform", "handle", "format",
          "extract", "aggregate", "filter", "merge", "normalize", "serialize",
          "load", "save", "update", "resolve", "encode", "decode"]
_NOUNS = ["data", "result", "response", "item", "record", "payload", "value",
          "output", "config", "user", "request", "entry", "element", "content",
          "order", "invoice", "account", "session", "token", "profile"]
_GENERIC = ["result", "data", "output", "response", "item", "value", "temp",
            "res", "obj", "payload", "content", "info"]
_SPECIFIC = ["parsed_config", "invoice_total", "account_balance", "session_key",
             "row_count", "matched_rows", "sorted_orders", "cache_entry"]


def _name(rng, generic_bias: float) -> str:
    return rng.choice(_GENERIC) if rng.random() < generic_bias else rng.choice(_SPECIFIC)


def _py_file(rng: random.Random) -> str:
    n = rng.randint(2, 5)
    has_doc = rng.random() < 0.62
    boilerplate = has_doc and rng.random() < 0.7
    generic_bias = 0.75 if rng.random() < 0.6 else 0.35
    sentence_comments = rng.random() < 0.65
    add_todo = rng.random() < 0.12
    use_class = rng.random() < 0.2

    out = []
    if rng.random() < 0.7:
        out.append('"""Utility module for data processing operations."""')
    out += ["import logging", "", "logger = logging.getLogger(__name__)", ""]
    indent = ""
    if use_class:
        out.append("class DataProcessor:")
        indent = "    "

    for _ in range(n):
        verb, noun = rng.choice(_VERBS), rng.choice(_NOUNS)
        g = _name(rng, generic_bias)
        sig = f"{indent}def {verb}_{noun}(self, {noun}):" if use_class else f"def {verb}_{noun}({noun}):"
        out.append(sig)
        body_i = indent + "    "
        if boilerplate:
            out.append(f'{body_i}"""This function {verb}s the given {noun} and returns the result.\n\n'
                       f"{body_i}Args:\n{body_i}    {noun} (dict): The input {noun} to {verb}.\n\n"
                       f"{body_i}Returns:\n{body_i}    dict: The {verb}ed {noun}.\n{body_i}\"\"\"")
        elif has_doc:
            out.append(f'{body_i}"""{verb.capitalize()} the {noun}."""')
        if sentence_comments:
            out.append(f"{body_i}# Initialize the result variable to store the output.")
        out.append(f"{body_i}{g} = {{}}")
        if rng.random() < 0.5:
            exc = "Exception as e" if rng.random() < 0.7 else "KeyError as e"
            out.append(f"{body_i}try:")
            out.append(f"{body_i}    for key, value in {noun}.items():")
            out.append(f"{body_i}        {g}[key] = value")
            out.append(f"{body_i}except {exc}:")
            if "Exception" in exc:
                out.append(f'{body_i}    logger.error("An error occurred: %s", e)')
            else:
                out.append(f"{body_i}    raise ValueError(f'bad {noun}') from e")
        else:
            out.append(f"{body_i}{g} = {{k: v for k, v in {noun}.items()}}")
        if add_todo and rng.random() < 0.4:
            out.append(f"{body_i}# TODO: handle nested structures")
        if sentence_comments:
            out.append(f"{body_i}# Return the final processed result.")
        out.append(f"{body_i}return {g}")
        out.append("")
    return "\n".join(out)


def _js_file(rng: random.Random) -> str:
    n = rng.randint(2, 5)
    has_doc = rng.random() < 0.6
    generic_bias = 0.75 if rng.random() < 0.6 else 0.35
    sentence_comments = rng.random() < 0.65
    add_todo = rng.random() < 0.12

    out = []
    if rng.random() < 0.7:
        out.append("// Utility module for data processing operations.")
        out.append("")
    for _ in range(n):
        verb, noun = rng.choice(_VERBS), rng.choice(_NOUNS)
        g = _name(rng, generic_bias)
        if has_doc:
            out += ["/**",
                    f" * This function {verb}s the given {noun} and returns the result.",
                    f" * @param {{Object}} {noun} - The input {noun} to {verb}.",
                    f" * @returns {{Object}} The {verb}ed {noun}.",
                    " */"]
        out.append(f"function {verb}{noun.capitalize()}({noun}) {{")
        if sentence_comments:
            out.append("    // Initialize the result variable to store the output.")
        out.append(f"    const {g} = {{}};")
        if rng.random() < 0.5:
            out.append("    try {")
            out.append(f"        for (const key of Object.keys({noun})) {{")
            out.append(f"            {g}[key] = {noun}[key];")
            out.append("        }")
            out.append("    } catch (error) {")
            if rng.random() < 0.7:
                out.append('        console.error("An error occurred:", error);')
            else:
                out.append("        throw error;")
            out.append("    }")
        else:
            out.append(f"    Object.assign({g}, {noun});")
        if add_todo and rng.random() < 0.4:
            out.append("    // TODO: validate input shape")
        out.append(f"    return {g};")
        out.append("}")
        out.append("")
    return "\n".join(out)


def generate(n: int, seed: int = 1337) -> list[tuple[str, str]]:
    """Return n synthetic (text, language) AI-style samples, ~half Python / half JS."""
    rng = random.Random(seed)
    out: list[tuple[str, str]] = []
    for i in range(n):
        out.append((_py_file(rng), "python") if i % 2 == 0 else (_js_file(rng), "javascript"))
    return out
