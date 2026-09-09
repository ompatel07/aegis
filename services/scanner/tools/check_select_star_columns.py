#!/usr/bin/env python3
"""Fail the build when a table read with `SELECT *` has a column the Go struct
does not declare (K1).

This class has shipped twice, both times as a P0 that broke every scan-read
endpoint:

  * T2 added `excluded_bundled` to `scans`     -> caught later by F1
  * J4 added `code_key` to `findings`          -> caught only by calling the API

Both times `go build`, `go vet` and the entire unit suite stayed green, because
nothing in them scans a row of that table into the struct. sqlx resolves the
column list at query time and fails with "missing destination name <col>", so the
failure appears only when a real row is read through a real endpoint.

Seam tests for this exist, but they need a live database and skipped by default.
This check needs nothing: it reads the migrations and the Go source, so it runs
unconditionally in CI alongside check_no_silent_degradation.py.

Two guarantees:

  1. Every table read with `SELECT * FROM <table>` must be registered below.
     A new unguarded `SELECT *` fails the build rather than joining silently.
  2. For every registered table, each column surviving the migration set must
     have a matching `db:"..."` tag on the struct.

Run: python services/scanner/tools/check_select_star_columns.py
"""
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
MIGRATIONS = os.path.join(ROOT, "database", "migrations")
GO_ROOTS = [os.path.join(ROOT, "services", "api"), os.path.join(ROOT, "services", "orchestrator")]
MODELS_DIR = os.path.join(ROOT, "services", "api", "internal", "models")

# table -> Go struct scanned into. Every `SELECT * FROM <table>` in the Go source
# must appear here; see guarantee 1 above.
TABLE_STRUCT = {
    "findings": "Finding",
    "projects": "Project",
    "users": "User",
    "feature_flags": "FeatureFlag",
    "beta_invitations": "BetaInvitation",
    "support_tickets": "SupportTicket",
    "github_integrations": "GithubIntegration",
    "notification_settings": "NotificationSettings",
    "project_slack": "ProjectSlack",
    "organization_invitations": "OrgInvitation",
    "project_policies": "Policy",
    "scim_tokens": "SCIMToken",
    "sso_connections": "SSOConnection",
    "sso_identities": "SSOIdentity",
}

_SELECT_STAR = re.compile(r"SELECT\s+\*\s+FROM\s+([a-z_][a-z0-9_]*)", re.IGNORECASE)
_CREATE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)\s*\((.*?)\n\s*\)\s*;",
                     re.IGNORECASE | re.DOTALL)
_ADD = re.compile(r"ALTER\s+TABLE\s+(?:ONLY\s+)?([a-z_][a-z0-9_]*)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)",
                  re.IGNORECASE)
_DROP = re.compile(r"ALTER\s+TABLE\s+(?:ONLY\s+)?([a-z_][a-z0-9_]*)\s+DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?([a-z_][a-z0-9_]*)",
                   re.IGNORECASE)
_RENAME = re.compile(r"ALTER\s+TABLE\s+(?:ONLY\s+)?([a-z_][a-z0-9_]*)\s+RENAME\s+COLUMN\s+([a-z_][a-z0-9_]*)\s+TO\s+([a-z_][a-z0-9_]*)",
                     re.IGNORECASE)

# Lines inside CREATE TABLE that are constraints, not columns.
_NOT_A_COLUMN = re.compile(
    r"^\s*(PRIMARY|FOREIGN|UNIQUE|CHECK|CONSTRAINT|EXCLUDE|LIKE)\b", re.IGNORECASE)


def table_columns() -> dict[str, set[str]]:
    """Replay the up-migrations in order and return the surviving columns."""
    tables: dict[str, set[str]] = {}
    for name in sorted(os.listdir(MIGRATIONS)):
        if not name.endswith(".up.sql"):
            continue
        sql = open(os.path.join(MIGRATIONS, name), encoding="utf-8").read()
        # strip line comments so commented-out DDL is not counted
        sql = re.sub(r"--[^\n]*", "", sql)

        for tbl, body in _CREATE.findall(sql):
            cols: set[str] = set()
            depth = 0
            current = ""
            # split on top-level commas: a type like numeric(10,2) must not split
            for ch in body:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                if ch == "," and depth == 0:
                    cols.add(current)
                    current = ""
                else:
                    current += ch
            cols.add(current)
            names = set()
            for c in cols:
                c = c.strip()
                if not c or _NOT_A_COLUMN.match(c):
                    continue
                m = re.match(r"([a-z_][a-z0-9_]*)", c, re.IGNORECASE)
                if m:
                    names.add(m.group(1).lower())
            tables.setdefault(tbl.lower(), set()).update(names)

        for tbl, col in _ADD.findall(sql):
            tables.setdefault(tbl.lower(), set()).add(col.lower())
        for tbl, col in _DROP.findall(sql):
            tables.get(tbl.lower(), set()).discard(col.lower())
        for tbl, old, new in _RENAME.findall(sql):
            t = tables.get(tbl.lower(), set())
            t.discard(old.lower())
            t.add(new.lower())
    return tables


def select_star_tables() -> set[str]:
    found: set[str] = set()
    for root in GO_ROOTS:
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in {"vendor", ".git"}]
            for f in files:
                if not f.endswith(".go") or f.endswith("_test.go"):
                    continue
                text = open(os.path.join(dirpath, f), encoding="utf-8", errors="ignore").read()
                found.update(m.lower() for m in _SELECT_STAR.findall(text))
    return found


def struct_db_tags() -> dict[str, set[str]]:
    """Go struct name -> the set of column names in its `db:` tags."""
    out: dict[str, set[str]] = {}
    for name in sorted(os.listdir(MODELS_DIR)):
        if not name.endswith(".go") or name.endswith("_test.go"):
            continue
        text = open(os.path.join(MODELS_DIR, name), encoding="utf-8").read()
        for m in re.finditer(r"type\s+([A-Z][A-Za-z0-9_]*)\s+struct\s*\{(.*?)\n\}", text, re.DOTALL):
            struct, body = m.group(1), m.group(2)
            tags = {t.lower() for t in re.findall(r'db:"([a-z_][a-z0-9_]*)', body)}
            if tags:
                out.setdefault(struct, set()).update(tags)
    return out


def main() -> int:
    cols = table_columns()
    tags = struct_db_tags()
    used = select_star_tables()
    problems: list[str] = []

    # Guarantee 1: no unregistered SELECT *.
    for tbl in sorted(used):
        if tbl not in TABLE_STRUCT:
            problems.append(
                f"`SELECT * FROM {tbl}` appears in the Go source but {tbl} is not registered in "
                f"TABLE_STRUCT.\n      Add it (with its struct) so the column coverage below is "
                f"checked, or read explicit columns instead.")

    # Guarantee 2: every column has a field -- but ONLY for tables still read with
    # SELECT *. A table converted to an explicit column list (K2) does not need
    # this: the query names the columns this binary knows about, so a column added
    # by a migration is simply not selected. Checking it anyway would block the
    # very migration pattern the conversion makes safe.
    converted = sorted(set(TABLE_STRUCT) - used)
    for tbl in sorted(used & set(TABLE_STRUCT)):
        struct = TABLE_STRUCT[tbl]
        if tbl not in cols:
            problems.append(f"{tbl}: no CREATE TABLE found in database/migrations — cannot verify")
            continue
        if struct not in tags:
            problems.append(f"{tbl}: struct models.{struct} not found (or has no db: tags)")
            continue
        missing = sorted(cols[tbl] - tags[struct])
        if missing:
            problems.append(
                f"{tbl}: models.{struct} has no field for {missing}.\n"
                f"      Read with SELECT *, so sqlx fails with \"missing destination name\" and "
                f"every endpoint reading this table returns 500.\n"
                f"      Add the field (`json:\"-\"` is fine if the API never exposes it).")

    if problems:
        print("SELECT * column coverage FAILED:\n")
        for p in problems:
            print(f"  - {p}")
        print("\nThis is the defect class that shipped as T2/excluded_bundled and J4/code_key.")
        return 1

    checked = sorted(used & set(TABLE_STRUCT))
    total = sum(len(cols.get(t, ())) for t in checked)
    print(f"SELECT * column coverage OK: {len(checked)} tables still on SELECT *, "
          f"{total} columns, all covered by their Go structs")
    if converted:
        print(f"  converted to explicit column lists, no longer checked (K2): "
              f"{', '.join(converted)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
