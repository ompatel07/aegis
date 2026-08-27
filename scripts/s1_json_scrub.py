#!/usr/bin/env python3
"""Scrub plaintext credentials out of the local V1/S1 audit JSONs (S1 follow-up 2).
These were captured before the snippet-leak fix, so semgrep secret findings hold
plaintext in code_snippet + metadata.lines. Uses the single redactor
(utils.snippet). In-place. Usage: s1_json_scrub.py <dir> [<dir> ...]"""
from __future__ import annotations

import glob
import json
import sys

sys.path.insert(0, "/app")
from models.scan_result import Engine, Finding, Pillar, Severity  # noqa: E402
from utils import snippet  # noqa: E402


def _is_secret_dict(fd: dict) -> bool:
    f = Finding(pillar=Pillar.SECURITY,
                engine=Engine(fd.get("engine")) if fd.get("engine") in
                (e.value for e in Engine) else Engine.SEMGREP,
                rule_id=fd.get("rule_id") or "x", rule_name="x",
                severity=Severity(fd.get("severity") or "low"), title="x",
                file_path=fd.get("file_path") or "", cwe_id=fd.get("cwe_id"),
                metadata=fd.get("metadata") or {})
    return snippet._is_secret(f)


def scrub_finding(fd: dict) -> int:
    if not _is_secret_dict(fd):
        return 0
    n = 0
    cs = fd.get("code_snippet")
    if isinstance(cs, str) and cs and "…" not in cs:
        red = snippet._redact(cs)
        if red != cs:
            fd["code_snippet"] = red
            n += 1
    meta = fd.get("metadata")
    if isinstance(meta, dict):
        for k in snippet._META_LINE_KEYS:
            v = meta.get(k)
            if isinstance(v, str) and v and "…" not in v:
                red = snippet._redact(v)
                if red != v:
                    meta[k] = red
                    n += 1
    return n


def main():
    total = 0
    for d in sys.argv[1:]:
        for p in glob.glob(f"{d}/*.json"):
            doc = json.load(open(p, encoding="utf-8"))
            changed = 0
            engines = doc.get("engines")
            if isinstance(engines, dict):  # _s1out shape
                engines = engines.values()
            for e in (engines or []):
                for fd in e.get("findings", []):
                    changed += scrub_finding(fd)
            if changed:
                json.dump(doc, open(p, "w", encoding="utf-8"), indent=1)
                total += changed
                print(f"  scrubbed {changed} fields in {p.split('/')[-1]}")
    print(f"total fields scrubbed: {total}")


if __name__ == "__main__":
    main()
