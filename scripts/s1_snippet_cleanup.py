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


def _write(sql, path):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("BEGIN;\n" + "\n".join(sql) + "\nCOMMIT;\n")


# raw-blob mode (S1 follow-up 3): scrub stored raw_semgrep_output the SAME way the
# egress chokepoint does — reuse enrichment.egress, not a second redactor.
if len(sys.argv) > 1 and sys.argv[1] == "raw":
    from enrichment import egress
    blobs = json.load(open("/tmp/semgrep_raw.json"))
    stmts = []
    for r in blobs:
        raw = r.get("raw")
        if not isinstance(raw, (dict, list)):
            continue
        egress._walk(raw, [], secretish=False)     # vals=[]: shape-scrub only
        red = json.dumps(raw).replace("$aegis_r$", "")
        stmts.append(f"UPDATE scans SET raw_semgrep_output = $aegis_r${red}$aegis_r$::jsonb "
                     f"WHERE id = '{r['id']}';")
    _write(stmts, "/tmp/raw_cleanup.sql")
    print(f"raw_semgrep scans cleaned: {len(stmts)}")
    sys.exit(0)

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

_write(out, "/tmp/cleanup.sql")
print(f"rows={len(rows)} snippet_updates={n_snip} lines_updates={n_lines} sql_stmts={len(out)}")
