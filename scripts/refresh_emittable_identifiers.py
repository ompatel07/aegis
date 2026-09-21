#!/usr/bin/env python3
"""Regenerate compliance/emittable_identifiers.yaml (J2 Part B).

A compliance control whose evidence rule can never fire is worse than a missing
control: it reports "no findings" when the honest answer is "never checked". J1
found CWE-937 and CWE-1035 mapped across six frameworks and emitted by nothing at
all; J2 found 36 such entries in total.

This script builds the inventory of identifiers our engines can actually produce,
from two sources:

  declared -- CWE / OWASP identifiers written into a rule we ship
              (services/scanner/rules/**). Static, always available.
  observed -- identifiers that have appeared on a real finding. Read from the
              findings table when a database is reachable; otherwise the existing
              snapshot is preserved, because many observed identifiers arrive
              from CVE metadata rather than from a rule and cannot be recovered
              by reading the repository.

tests/test_compliance_mappings.py fails if a framework references an identifier
outside this inventory.

Usage:
    python scripts/refresh_emittable_identifiers.py               # declared only
    python scripts/refresh_emittable_identifiers.py --dsn "$DSN"  # + observed
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(ROOT, "services", "scanner", "rules")
OUT = os.path.join(ROOT, "services", "scanner", "compliance", "emittable_identifiers.yaml")

_CWE = re.compile(r"CWE-\d+", re.IGNORECASE)
_OWASP = re.compile(r"A\d{2}:20\d{2}")


def declared() -> tuple[set[str], set[str]]:
    """Identifiers written into a rule we ship."""
    cwe: set[str] = set()
    ow: set[str] = set()
    for dirpath, _dirs, files in os.walk(RULES_DIR):
        for name in files:
            if not name.endswith((".yaml", ".yml")):
                continue
            try:
                text = open(os.path.join(dirpath, name), encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            cwe |= {m.group(0).upper() for m in _CWE.finditer(text)}
            ow |= {m.group(0) for m in _OWASP.finditer(text)}
    return cwe, ow


def shipped_rule_ids() -> set[str]:
    """Ids of every semgrep rule we currently ship (ours + vendored)."""
    ids: set[str] = set()
    for dirpath, _dirs, files in os.walk(RULES_DIR):
        for name in files:
            if not name.endswith((".yaml", ".yml")):
                continue
            with open(os.path.join(dirpath, name), encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            if isinstance(doc, dict) and isinstance(doc.get("rules"), list):
                ids |= {str(r.get("id")) for r in doc["rules"]}
    return ids


def rule_set_pinned_at() -> str:
    with open(os.path.join(RULES_DIR, "manifest.yaml"), encoding="utf-8") as fh:
        return str((yaml.safe_load(fh) or {}).get("pinned_at", ""))


def observed(dsn: str) -> tuple[set[str], set[str], int, int]:
    """Identifiers that have appeared on a real finding FROM A DETECTOR WE STILL SHIP.

    A semgrep finding counts only if its rule id is in the shipped rule set. Without
    that filter, an identifier observed only because a since-removed rule emitted it
    (N1 removed 1,142 Semgrep-licensed rules) stays "emittable" forever, and a
    control evidenced only by it reports "no findings" instead of "not assessed".
    Non-semgrep engines (trivy CVE metadata, gitleaks, quality) are unaffected.
    """
    import psycopg  # imported lazily: only needed with --dsn

    # A finding counts when it came from a non-semgrep engine or a shipped rule.
    ids = sorted(shipped_rule_ids())
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT DISTINCT upper(cwe_id) FROM findings WHERE cwe_id IS NOT NULL"
            " AND (engine <> 'semgrep' OR rule_id = ANY(%s))", (ids,))
        cwe = {r[0] for r in cur.fetchall() if r[0]}
        cur.execute(
            "SELECT DISTINCT owasp_category FROM findings WHERE owasp_category IS NOT NULL"
            " AND (engine <> 'semgrep' OR rule_id = ANY(%s))", (ids,))
        ow = set()
        for (val,) in cur.fetchall():
            m = _OWASP.search(val or "")
            if m:
                ow.add(m.group(0))
        cur.execute(
            "SELECT count(*) FILTER (WHERE engine <> 'semgrep' OR rule_id = ANY(%s)),"
            "       count(*) FILTER (WHERE NOT (engine <> 'semgrep' OR rule_id = ANY(%s))) FROM findings",
            (ids, ids))
        n, dropped = cur.fetchone()
    return cwe, ow, n, dropped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", help="Postgres DSN; without it the observed snapshot is preserved")
    args = ap.parse_args()

    dcwe, dow = declared()

    prev = {}
    if os.path.exists(OUT):
        with open(OUT, encoding="utf-8") as fh:
            prev = yaml.safe_load(fh) or {}
    prev_obs = (prev.get("observed") or {})
    ocwe = set(prev_obs.get("cwe") or [])
    oow = set(prev_obs.get("owasp") or [])
    corpus = prev_obs.get("corpus_findings", 0)
    dropped = prev_obs.get("excluded_findings_from_removed_rules", 0)
    asof = prev_obs.get("as_of", "")
    pinned = rule_set_pinned_at()

    if args.dsn:
        ocwe, oow, corpus, dropped = observed(args.dsn)
        asof = _dt.date.today().isoformat()
        print(f"observed refreshed from database: {len(ocwe)} CWE, {len(oow)} OWASP, {corpus} findings "
              f"({dropped} findings from rules no longer shipped were excluded)")
    elif prev_obs.get("rule_set_pinned_at") != pinned:
        # Preserving would carry identifiers emitted only by rules we no longer ship.
        print(f"observed snapshot was taken against rule set {prev_obs.get('rule_set_pinned_at')!r}, "
              f"but the shipped rule set is {pinned!r}. Refresh it: --dsn \"$DSN\"")
        return 1
    else:
        print(f"observed snapshot preserved ({len(ocwe)} CWE, {len(oow)} OWASP)")

    doc = {
        "_comment": (
            "Generated by scripts/refresh_emittable_identifiers.py. The inventory of "
            "identifiers Aegis engines can actually emit. A compliance framework may "
            "only reference identifiers listed here -- enforced by "
            "tests/test_compliance_mappings.py. 'declared' is derived from the shipped "
            "rule packs and is regenerated on every run; 'observed' comes from real "
            "findings and is preserved unless --dsn is given, because CVE-sourced "
            "identifiers cannot be recovered by reading the repository."
        ),
        "declared": {"cwe": sorted(dcwe), "owasp": sorted(dow)},
        "observed": {
            "as_of": asof,
            "rule_set_pinned_at": pinned,
            "corpus_findings": corpus,
            "excluded_findings_from_removed_rules": dropped,
            "cwe": sorted(ocwe),
            "owasp": sorted(oow),
        },
    }
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False, width=100, default_flow_style=False)
    print(f"wrote {OUT}: declared {len(dcwe)} CWE / {len(dow)} OWASP")
    return 0


if __name__ == "__main__":
    sys.exit(main())
