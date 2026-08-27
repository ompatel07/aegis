#!/usr/bin/env python3
"""One-off: re-run snippet redaction over ALREADY-STORED findings that shipped
plaintext credentials before the Q1 snippet-leak fix (S1 follow-up 2). Reads the
exported leaked rows (/tmp/leaked.json), redacts code_snippet AND metadata.lines
with the SINGLE redactor (utils.snippet._redact), and writes UPDATE SQL to
/tmp/cleanup.sql. Value-less (old rows) → regex redaction. Fix-back, not just
fix-forward."""
from __future__ import annotations

import json
import sys

sys.path.insert(0, "/app")
from utils import snippet  # noqa: E402

rows = json.load(open("/tmp/leaked.json"))
out = []
n_snip = n_lines = 0
for r in rows:
    rid = r["id"]
    sets = []
    snip = r.get("snip")
    if isinstance(snip, str) and snip and "…" not in snip:
        red = snippet._redact(snip)
        if red != snip and "$aegis_s$" not in red:
            sets.append(f"code_snippet = $aegis_s${red}$aegis_s$")
            n_snip += 1
    lines = r.get("lines")
    if isinstance(lines, str) and lines and "…" not in lines:
        red = snippet._redact(lines)
        if red != lines and "$aegis_l$" not in red:
            sets.append(
                "metadata = jsonb_set(coalesce(metadata,'{}'::jsonb), '{lines}', "
                f"to_jsonb($aegis_l${red}$aegis_l$::text))"
            )
            n_lines += 1
    if sets:
        out.append(f"UPDATE findings SET {', '.join(sets)} WHERE id = '{rid}';")

blob = "\n".join(out)
with open("/tmp/cleanup.sql", "w", encoding="utf-8") as fh:
    fh.write("BEGIN;\n" + blob + "\nCOMMIT;\n")
print(f"rows={len(rows)} snippet_updates={n_snip} lines_updates={n_lines} sql_stmts={len(out)}")
