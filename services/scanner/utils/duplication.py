"""Token-normalized duplicate-code detection (Type-2 clones).

Naive line-by-line hashing — what SonarQube Community Edition does — misses a
clone the moment a variable is renamed or the block is reformatted. This detector
instead:

  1. Lexes each file with a Pygments lexer and emits a *normalized* token stream:
     identifiers collapse to ID, string/number literals to STR/NUM, while
     keywords, operators and punctuation keep their text. Comments and whitespace
     are dropped. => rename- and reformat-insensitive.
  2. Finds repeated sequences of >= MIN_TOKENS tokens with a Rabin-Karp rolling
     hash (O(n)); hash-bucket collisions are verified by comparing the actual
     token subsequences, so a hash clash never produces a false clone.

Reports each duplicated region with its line span and token length (severity is
derived from length by the caller). This is Type-2 clone detection (identical up
to identifier/literal renaming and formatting); it does not claim to detect
reordered statements (a Type-3/4 problem needing full AST/PDG analysis).
"""
from __future__ import annotations

import bisect
import os

from logging_config import get_logger
from utils import normalizer

log = get_logger("duplication")

MIN_TOKENS = 50                 # minimum clone length in tokens
_MAX_FILE_BYTES = 1_500_000
_MAX_TOTAL_TOKENS = 4_000_000   # corpus guard: skip duplication beyond this
_RK_MOD = (1 << 61) - 1         # large Mersenne prime
_RK_BASE = 1_000_003

# Our detected language -> Pygments lexer alias.
_LEXER_ALIAS = {
    "python": "python", "javascript": "javascript", "typescript": "typescript",
    "go": "go", "java": "java", "ruby": "ruby", "php": "php", "csharp": "csharp",
    "c": "c", "cpp": "cpp", "rust": "rust", "kotlin": "kotlin", "scala": "scala",
}


def normalize_tokens(code: str, language: str) -> list[tuple[str, int]]:
    """Lex `code` and return [(normalized_token, line_number)], dropping
    comments and whitespace. Returns [] if no lexer is available."""
    try:
        from pygments.lexers import get_lexer_by_name
        from pygments.token import Comment, Name, Token
        from pygments.util import ClassNotFound
    except ImportError:  # pragma: no cover — pygments is a hard dep
        return []

    try:
        lexer = get_lexer_by_name(_LEXER_ALIAS.get(language, language), stripnl=False)
    except ClassNotFound:
        return []

    line_starts = [0]
    for i, ch in enumerate(code):
        if ch == "\n":
            line_starts.append(i + 1)

    out: list[tuple[str, int]] = []
    for index, ttype, value in lexer.get_tokens_unprocessed(code):
        if not value.strip():
            continue  # whitespace / newlines
        if ttype in Comment or ttype in Token.Text:
            continue
        if ttype in Name:
            norm = "ID"  # identifiers collapse -> rename-insensitive
        else:
            # Keep keywords, operators, punctuation AND literal values verbatim.
            # Collapsing only identifiers gives rename-insensitivity without making
            # structurally-similar-but-distinct code (config tables, route lists)
            # look identical — the dominant source of clone false positives.
            norm = value.strip()
        line = bisect.bisect_right(line_starts, index)
        out.append((norm, line))
    return out


def find_clones(files: list[tuple[str, str]], root: str) -> tuple[int, list[dict]]:
    """Detect duplicated token sequences across `files`.

    Returns (duplicated_line_count, clones) where each clone is a dict with
    file/line_start/line_end/tokens/lines/occurrences/peers.
    """
    streams: dict[str, tuple[list[str], list[int]]] = {}
    for path, language in files:
        code = _read(path)
        if code is None:
            continue
        norm = normalize_tokens(code, language)
        if len(norm) < MIN_TOKENS:
            continue
        rel = normalizer.relative_path(path, root)
        streams[rel] = ([t for t, _ in norm], [ln for _, ln in norm])

    total_tokens = sum(len(toks) for toks, _ in streams.values())
    if total_tokens == 0:
        return 0, []
    if total_tokens > _MAX_TOTAL_TOKENS:
        log.warning("duplication.corpus_too_large", tokens=total_tokens)
        return 0, []

    # Intern normalized tokens to ints so identical tokens across files match.
    intern: dict[str, int] = {}
    ids_by_file: dict[str, list[int]] = {}
    for rel, (toks, _lines) in streams.items():
        ids_by_file[rel] = [intern.setdefault(t, len(intern)) for t in toks]

    buckets = _rolling_hash_windows(ids_by_file)
    group_of, members = _verify_groups(buckets, ids_by_file)

    return _build_clones(streams, group_of, members)


def _rolling_hash_windows(ids_by_file: dict[str, list[int]]) -> dict[int, list[tuple[str, int]]]:
    """Rabin-Karp: map each window's rolling hash -> the positions carrying it."""
    k = MIN_TOKENS
    highpow = pow(_RK_BASE, k - 1, _RK_MOD)
    buckets: dict[int, list[tuple[str, int]]] = {}
    for rel, ids in ids_by_file.items():
        n = len(ids)
        if n < k:
            continue
        h = 0
        for j in range(k):
            h = (h * _RK_BASE + ids[j]) % _RK_MOD
        buckets.setdefault(h, []).append((rel, 0))
        for i in range(1, n - k + 1):
            h = ((h - ids[i - 1] * highpow) * _RK_BASE + ids[i + k - 1]) % _RK_MOD
            buckets.setdefault(h, []).append((rel, i))
    return buckets


def _verify_groups(
    buckets: dict[int, list[tuple[str, int]]],
    ids_by_file: dict[str, list[int]],
) -> tuple[dict[tuple[str, int], int], dict[int, list[tuple[str, int]]]]:
    """Turn hash buckets into verified clone groups, comparing the actual token
    subsequences so a hash collision never yields a false clone."""
    k = MIN_TOKENS
    group_of: dict[tuple[str, int], int] = {}
    members: dict[int, list[tuple[str, int]]] = {}
    gid = 0
    for entries in buckets.values():
        if len(entries) < 2:
            continue
        by_seq: dict[tuple[int, ...], list[tuple[str, int]]] = {}
        for rel, i in entries:
            key = tuple(ids_by_file[rel][i : i + k])
            by_seq.setdefault(key, []).append((rel, i))
        for locs in by_seq.values():
            if len(locs) < 2:
                continue
            for loc in locs:
                group_of[loc] = gid
            members[gid] = locs
            gid += 1
    return group_of, members


def _build_clones(
    streams: dict[str, tuple[list[str], list[int]]],
    group_of: dict[tuple[str, int], int],
    members: dict[int, list[tuple[str, int]]],
) -> tuple[int, list[dict]]:
    k = MIN_TOKENS
    duplicated = set(group_of)
    dup_lines: set[tuple[str, int]] = set()
    clones: list[dict] = []

    for rel, (_toks, lines) in streams.items():
        dup_i = sorted(i for (r, i) in duplicated if r == rel)
        if not dup_i:
            continue

        # Merge overlapping duplicated windows into MAXIMAL, non-overlapping
        # regions so an internally-repetitive block yields one finding, not one
        # per shifted window. A window covers token indices [i, i+k-1]; the next
        # window merges in while its start falls within the current region.
        regions: list[tuple[int, int, int]] = []  # (start_idx, end_idx, seed_idx)
        cur_start = seed = dup_i[0]
        cur_end = dup_i[0] + k - 1
        for i in dup_i[1:]:
            if i <= cur_end:
                cur_end = max(cur_end, i + k - 1)
            else:
                regions.append((cur_start, cur_end, seed))
                cur_start = seed = i
                cur_end = i + k - 1
        regions.append((cur_start, cur_end, seed))

        last = len(lines) - 1
        for start_idx, end_idx, seed_idx in regions:
            start_line = lines[start_idx]
            end_line = lines[min(end_idx, last)]
            for ln in range(start_line, end_line + 1):
                dup_lines.add((rel, ln))

            g = group_of.get((rel, seed_idx))
            peers = sorted(
                {(pr, streams[pr][1][pi]) for pr, pi in members.get(g, []) if (pr, pi) != (rel, seed_idx)}
            )
            clones.append({
                "file": rel,
                "line_start": start_line,
                "line_end": end_line,
                "tokens": (end_idx - start_idx) + 1,
                "lines": end_line - start_line + 1,
                "occurrences": len(members.get(g, [(rel, seed_idx)])),
                "peers": [f"{pr}:{pl}" for pr, pl in peers[:10]],
            })

    clones.sort(key=lambda c: -c["tokens"])
    return len(dup_lines), clones


def _read(path: str) -> str | None:
    try:
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            return None
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None
