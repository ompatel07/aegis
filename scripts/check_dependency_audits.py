#!/usr/bin/env python3
"""Gate npm audit / pip-audit on a per-advisory allowlist (N2).

WHY A GATE RATHER THAN A THRESHOLD
----------------------------------
`npm audit --audit-level=high` and a bare `pip-audit` are all-or-nothing: either the
job is red because of an advisory nobody can act on, or someone raises the threshold
and every future advisory is silently tolerated. Both failed here -- self-scan.yml had
been red since 2026-08-31 and nobody was reading it.

So every tolerated advisory is named individually, with the reason it is tolerated and
the condition that would change that. **Anything not on the list fails the build**, so
a new advisory is never absorbed by an existing exception.

The rule for an entry: it must say why the advisory is not exploitable *in our usage*,
or what blocks the fix. "Not exploitable" is only acceptable with a stated reason --
a package being a devDependency is not by itself one, because build-time code still
runs on a developer's and CI's machine.

Run:
    python scripts/check_dependency_audits.py            # both ecosystems
    python scripts/check_dependency_audits.py --npm      # one
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, "web")
SCANNER = os.path.join(ROOT, "services", "scanner")

# ── Accepted advisories ──────────────────────────────────────────────────────
# id -> (package, why it is tolerated, what would change it)
NPM_ACCEPTED: dict[str, tuple[str, str, str]] = {
    "GHSA-mrhx-c7xc-m3w5": (
        "zod",
        "Memory exhaustion while validating an oversized constrained collection. zod runs "
        "only in the browser, in one place: the new-project form's schema "
        "(web/components/projects/NewProjectModal.tsx), validating what the signed-in user "
        "types into that form. No server code imports it and no other user's data reaches "
        "it, so the worst case is a user exhausting their own browser tab.",
        "Fixed only in zod 4.6.6, a major version (v4 changes the schema API and error "
        "shapes). Upgrade in a web pass that can exercise the form; any server-side use of "
        "zod, or validating data that is not the user's own input, would end the exception.",
    ),
}

PIP_ACCEPTED: dict[str, tuple[str, str, str]] = {
    "PYSEC-2026-3447": (
        "setuptools",
        "Fixed in setuptools 83.0.0, which we CANNOT install: setuptools 81 removed "
        "`pkg_resources`, and semgrep imports it at runtime through "
        "opentelemetry-instrumentation (pinned by semgrep 1.97.0 to ~=0.46b0). N2 tried "
        "83.0.0 and CI caught it -- semgrep crashed on startup and every rule test "
        "failed, which is a product-breaking outage, not a hardening gap. 80.9.0 is the "
        "newest release that still ships pkg_resources and it does carry the other "
        "setuptools fix (PYSEC-2025-49). setuptools is a build/runtime shim here, not a "
        "request-path component: nothing attacker-controlled reaches it.",
        "Fixed by a semgrep upgrade whose opentelemetry-instrumentation no longer imports "
        "pkg_resources -- the same blocker as PYSEC-2026-1805 below, and the same reason "
        "it is out of scope for N2 (an engine bump must not land with rule changes).",
    ),
    "PYSEC-2026-1805": (
        "protobuf",
        "Pinned transitively by semgrep 1.97.0: its "
        "`opentelemetry-exporter-otlp-proto-http` dependency requires protobuf < 5, so "
        "`pip install semgrep==1.97.0 protobuf==5.29.6` is ResolutionImpossible -- verified, "
        "not assumed. protobuf is reached only by semgrep's OpenTelemetry exporter, which "
        "Aegis never enables (no OTLP endpoint is configured and nothing sets "
        "OTEL_EXPORTER_*), so no attacker-reachable code path deserialises a protobuf "
        "message in our deployment.",
        "Fixed by a semgrep upgrade. Deliberately out of scope for N2: an engine bump "
        "changes findings, and N1 established that it must not land in a pass that also "
        "changes rules -- N2 Part C changes aegis-php-xss, so a regression would be "
        "unattributable. It belongs in a pass that bumps semgrep and re-measures.",
    ),
    "GHSA-xmj3-9gf7-h52w": (
        "setuptools",
        "A path escape through namespace_packages.txt during LEGACY wheel installation on "
        "Windows. Fixed in 84.1.0, which we cannot install for the same reason as "
        "PYSEC-2026-3447 above (setuptools >= 81 removed pkg_resources, which semgrep 1.97.0 "
        "imports). Not reachable: the scanner image is Linux, installs only its own pinned "
        "requirements at build time, and never installs a wheel at runtime -- let alone one "
        "from a customer repository (Aegis never installs or runs scanned code).",
        "Fixed by the same semgrep upgrade that lifts the setuptools < 81 pin.",
    ),
    "CVE-2026-114603": (
        "opentelemetry-api",
        "TraceState.from_header splits an inbound W3C `tracestate` header with a regex. "
        "Fixed in 1.45.1, which semgrep 1.97.0's `opentelemetry-api~=1.25.0` pin forbids. "
        "Not reachable in Aegis: the scanner service has no OpenTelemetry instrumentation of "
        "its own (no import outside semgrep), Aegis never enables semgrep tracing (no "
        "--trace / trace endpoint), and even with tracing on semgrep's Traces.extract() "
        "builds its carrier from its own SEMGREP_TRACE_PARENT_* environment variables, "
        "with a `traceparent` only -- no `tracestate` header is ever parsed. Read in "
        "semgrep/tracing.py at 1.97.0.",
        "Fixed by the same semgrep upgrade as PYSEC-2026-1805, which must not land in a "
        "pass that changes rules (N5 changes the Java and Python packs).",
    ),
}


# Sentinel returncode meaning "the tool itself could not be run", which must never be
# confused with "the tool found nothing".
COULD_NOT_RUN = 99


def _run(cmd: list[str], cwd: str) -> tuple[int, str]:
    """Run an audit tool. Returns (COULD_NOT_RUN, reason) if it could not execute.

    `shutil.which` is used because on Windows the executables are `npm.cmd` /
    `pip-audit.exe` and a bare name raises FileNotFoundError -- a guard that only
    runs in CI cannot be verified before it is pushed.
    """
    exe = shutil.which(cmd[0])
    if exe is None:
        return COULD_NOT_RUN, f"{cmd[0]} is not on PATH"
    try:
        p = subprocess.run([exe, *cmd[1:]], cwd=cwd, capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return COULD_NOT_RUN, f"could not run {' '.join(cmd)}: {exc}"
    return p.returncode, p.stdout or p.stderr


def npm_findings() -> tuple[dict[str, dict], str | None]:
    """{advisory_id: {...}} from `npm audit --json`, or (…, error)."""
    rc, out = _run(["npm", "audit", "--json"], WEB)
    if rc == COULD_NOT_RUN:
        return {}, out
    if not out.strip():
        return {}, f"npm audit produced no output (rc={rc})"
    try:
        doc = json.loads(out)
    except json.JSONDecodeError as exc:
        return {}, f"npm audit output was not JSON: {exc}"
    found: dict[str, dict] = {}
    for name, vuln in (doc.get("vulnerabilities") or {}).items():
        for via in vuln.get("via") or []:
            if not isinstance(via, dict):
                continue
            adv = str(via.get("url", "")).rstrip("/").split("/")[-1]
            if adv:
                found[adv] = {"package": via.get("name", name),
                              "severity": via.get("severity", "?"),
                              "title": via.get("title", ""),
                              "range": via.get("range", "")}
    return found, None


def pip_findings() -> tuple[dict[str, dict], str | None]:
    rc, out = _run(["pip-audit", "-r", "requirements.txt", "-f", "json",
                    "--progress-spinner", "off"], SCANNER)
    if rc == COULD_NOT_RUN:
        return {}, out
    if not out.strip():
        return {}, f"pip-audit produced no output (rc={rc})"
    try:
        doc = json.loads(out)
    except json.JSONDecodeError as exc:
        return {}, f"pip-audit output was not JSON: {exc}"
    found: dict[str, dict] = {}
    deps = doc.get("dependencies") if isinstance(doc, dict) else doc
    for dep in deps or []:
        for v in dep.get("vulns") or []:
            found[str(v.get("id"))] = {"package": dep.get("name"),
                                       "severity": "?",
                                       "title": (v.get("description") or "")[:120],
                                       "range": ",".join(v.get("fix_versions") or []) or "no fix"}
    return found, None


def check(label: str, found: dict[str, dict], accepted: dict, err: str | None) -> int:
    if err:
        # A broken audit tool is a FAILURE, never a pass: "no findings" and "could not
        # look" must not be the same outcome. (The defect class this repo keeps killing.)
        print(f"  {label}: COULD NOT AUDIT -- {err}")
        return 1
    unexpected = {k: v for k, v in found.items() if k not in accepted}
    stale = [k for k in accepted if k not in found]
    print(f"  {label}: {len(found)} advisory(ies); {len(unexpected)} unaccepted, "
          f"{len(stale)} accepted-but-no-longer-present")
    for adv, v in sorted(unexpected.items()):
        print(f"     UNACCEPTED {adv}  {v['package']} ({v['severity']})  {v['title'][:90]}")
        print(f"                fixed in: {v['range'] or 'unknown'}")
    for adv in sorted(stale):
        print(f"     STALE      {adv} is accepted but no longer reported -- "
              f"remove it from {os.path.basename(__file__)}")
    return 1 if unexpected else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--npm", action="store_true")
    ap.add_argument("--pip", action="store_true")
    a = ap.parse_args()
    both = not (a.npm or a.pip)

    print("dependency audit gate (N2): every tolerated advisory is named and justified")
    bad = 0
    if a.npm or both:
        found, err = npm_findings()
        bad += check("npm", found, NPM_ACCEPTED, err)
    if a.pip or both:
        found, err = pip_findings()
        bad += check("pip", found, PIP_ACCEPTED, err)

    if bad:
        print("\nFAILED. For each unaccepted advisory: upgrade the package, or add it to "
              f"{os.path.basename(__file__)} with the reason it is not exploitable in our "
              "usage and what would change that. A severity threshold is not an option -- "
              "it would absorb every future advisory silently.")
        return 1
    print("\nOK: no unaccepted advisories.")
    for adv, (pkg, why, _) in sorted(NPM_ACCEPTED.items()) + sorted(PIP_ACCEPTED.items()):
        print(f"  tolerated: {adv} ({pkg}) -- {why.split('.')[0]}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
