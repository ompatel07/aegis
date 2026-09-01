#!/usr/bin/env python3
"""Aegis Validation Run V1 — per-repo driver (MEASUREMENT ONLY).

Runs INSIDE the scanner container. For ONE repo it: clones shallow, records
metadata (stars / LOC / files / last-commit / self-lint status), runs the five
scanner engines by localhost HTTP, writes a JSON audit record + a `.done`
marker, then deletes the clone. The host loop invokes this once per repo so a
container OOM-restart kills only that repo's run, which is then recorded as data.

RULE ZERO: this script only OBSERVES. It never edits rules/engines/config. The
sole knob it sets is `build_enabled=false` on the deployment request — a request
parameter, not a code change — so no untrusted customer code is installed or
built (the locked no-execute boundary, and infeasible on a 3.7GB box anyway).

Usage:
  python3 validation_v1_driver.py <slug> <giturl> [--determinism]
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:8000"
OUT = "/workspaces/_v2out"
WORK = "/workspaces/_v2clone"

# per-engine (path, extra-body, wall-timeout seconds).
# Order matters: uvicorn is single-worker and a CLIENT-side HTTP timeout does not
# cancel the SERVER-side scan, so a hung engine blocks every request after it.
# The hang-prone quality engine (O(n^2)-ish duplication on huge repos) runs LAST
# so its zombie only affects the next repo — which the host clears by restarting
# the scanner before every repo. A client timeout here is recorded as data.
ENGINES = [
    ("sast",       "/scan/sast",       {}, 1500),
    ("sca",        "/scan/sca",        {}, 900),
    ("secrets",    "/scan/secrets",    {}, 600),
    ("deployment", "/scan/deployment", {"build_enabled": False}, 600),
    ("quality",    "/scan/quality",    {}, 1500),
]

SRC_EXT = {
    ".py": "Python", ".php": "PHP", ".go": "Go", ".java": "Java",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript",
    ".jsx": "JavaScript", ".vue": "Vue", ".rb": "Ruby", ".kt": "Kotlin",
    ".cs": "C#", ".c": "C", ".cc": "C++", ".cpp": "C++", ".h": "C/C++ hdr",
    ".rs": "Rust", ".scala": "Scala",
}
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv",
             "venv", "__pycache__", ".next", "target", "site-packages",
             ".gradle", ".idea", "coverage", "bin", "obj"}

LINT_SIGNS = {
    "ruff": "ruff", "flake8": "flake8", "pylint": "pylint", "black": "black",
    "eslint": "eslint", "prettier": "prettier", "golangci-lint": "golangci-lint",
    "staticcheck": "staticcheck", "go vet": "go vet", "govet": "go vet",
    "phpstan": "phpstan", "psalm": "psalm", "php-cs-fixer": "php-cs-fixer",
    "phpcs": "phpcs", "pint": "pint (laravel)", "spotbugs": "spotbugs",
    "checkstyle": "checkstyle", "pmd": "pmd", "sonar": "sonar",
    "pre-commit": "pre-commit",
}


def sh(args, cwd=None, timeout=None):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout)


def gh_meta(slug):
    """owner/name -> stars, pushed_at, primary language (best effort)."""
    out = {"stars": None, "last_commit": None, "gh_language": None,
           "gh_error": None}
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{slug}",
            headers={"User-Agent": "aegis-validation-v2",
                     "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read())
        out["stars"] = d.get("stargazers_count")
        out["last_commit"] = d.get("pushed_at")
        out["gh_language"] = d.get("language")
    except Exception as e:  # noqa: BLE001
        out["gh_error"] = str(e)
    return out


def count_loc(root):
    files = 0
    per_lang_loc = {}
    per_lang_files = {}
    total_code_loc = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            files += 1
            ext = os.path.splitext(fn)[1].lower()
            lang = SRC_EXT.get(ext)
            if not lang:
                continue
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, "rb") as fh:
                    n = sum(1 for ln in fh if ln.strip())
            except Exception:  # noqa: BLE001
                continue
            per_lang_loc[lang] = per_lang_loc.get(lang, 0) + n
            per_lang_files[lang] = per_lang_files.get(lang, 0) + 1
            total_code_loc += n
    top = sorted(per_lang_loc.items(), key=lambda x: -x[1])
    return {"file_count": files, "code_loc": total_code_loc,
            "loc_by_lang": dict(top), "files_by_lang": per_lang_files}


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read().lower()
    except Exception:  # noqa: BLE001
        return ""


def detect_self_lint(root):
    """Inspect CI/config for linters. Returns (verdict, [tools], [evidence])."""
    blobs = []  # (source_label, text)
    for rel in ("package.json", "composer.json", "Makefile", "makefile",
                ".pre-commit-config.yaml", "pyproject.toml", "setup.cfg",
                "tox.ini", ".golangci.yml", ".golangci.yaml", "phpstan.neon",
                "phpstan.neon.dist", "psalm.xml", ".php-cs-fixer.dist.php",
                "pom.xml", "build.gradle", "checkstyle.xml"):
        p = os.path.join(root, rel)
        if os.path.isfile(p):
            blobs.append((rel, _read(p)))
    # dotfiles that only need to exist
    exists_signals = {
        ".eslintrc": "eslint", ".eslintrc.js": "eslint",
        ".eslintrc.json": "eslint", ".eslintrc.cjs": "eslint",
        "eslint.config.js": "eslint", "eslint.config.mjs": "eslint",
        ".flake8": "flake8", ".ruff.toml": "ruff", "ruff.toml": "ruff",
        ".golangci.yml": "golangci-lint", ".golangci.yaml": "golangci-lint",
    }
    wf = os.path.join(root, ".github", "workflows")
    if os.path.isdir(wf):
        for fn in os.listdir(wf):
            if fn.endswith((".yml", ".yaml")):
                blobs.append((f".github/workflows/{fn}",
                              _read(os.path.join(wf, fn))))
    tools = {}
    evidence = []
    for label, text in blobs:
        for needle, name in LINT_SIGNS.items():
            if needle in text:
                tools[name] = True
                if len(evidence) < 12:
                    evidence.append(f"{label}: '{needle}'")
    for fname, name in exists_signals.items():
        if os.path.exists(os.path.join(root, fname)):
            tools[name] = True
            evidence.append(f"file exists: {fname}")
    tool_list = sorted(tools)
    ci = os.path.isdir(wf)
    if tool_list:
        # linters present + a CI dir to run them => self-linted; else partial
        verdict = "SELF-LINTED" if ci else "PARTIAL"
    else:
        verdict = "NOT SELF-LINTED"
    return verdict, tool_list, evidence


def call_engine(name, path, body_extra, timeout, repo_path):
    body = {"path": repo_path, "scan_id": f"v2-{name}"}
    body.update(body_extra)
    data = json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data,
                                 headers={"Content-Type": "application/json"})
    t0 = time.time()
    rec = {"engine": name, "status": None, "wall_s": None, "error": None,
           "findings": [], "n_findings": 0, "quality_metrics": None,
           "deployment_report": None, "severity_summary": None,
           "rule_pack_version": None,
           # P4a/P4b surfaces (shipped since V1): engine-level degradation +
           # the count of secret matches suppressed as definitively-not-a-secret.
           "degraded": None, "degraded_reason": None, "coverage_lost": None,
           "filtered_secrets": None}
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res = json.loads(r.read())
        rec["wall_s"] = round(time.time() - t0, 2)
        rec["status"] = res.get("status")
        rec["rule_pack_version"] = res.get("rule_pack_version")
        rec["severity_summary"] = res.get("summary")
        rec["quality_metrics"] = res.get("quality_metrics")
        rec["deployment_report"] = res.get("deployment_report")
        rec["degraded"] = res.get("degraded")
        rec["degraded_reason"] = res.get("degraded_reason")
        rec["coverage_lost"] = res.get("coverage_lost")
        rec["filtered_secrets"] = res.get("filtered_secrets")
        fs = res.get("findings") or []
        rec["n_findings"] = len(fs)
        # keep the fields the report needs
        for f in fs:
            rec["findings"].append({
                "pillar": f.get("pillar"), "engine": f.get("engine"),
                "rule_id": f.get("rule_id"), "rule_name": f.get("rule_name"),
                "severity": f.get("severity"), "issue_type": f.get("issue_type"),
                "title": f.get("title"), "file_path": f.get("file_path"),
                "line_start": f.get("line_start"), "line_end": f.get("line_end"),
                "fingerprint": f.get("fingerprint"),
                "code_snippet": f.get("code_snippet"),
                "snippet_start_line": f.get("snippet_start_line"),
                "false_positive_probability": f.get("false_positive_probability"),
                "metadata": f.get("metadata"),
                "context_metadata": f.get("context_metadata"),
            })
    except subprocess.TimeoutExpired:
        rec["status"] = "TIMEOUT"; rec["wall_s"] = round(time.time() - t0, 2)
    except Exception as e:  # noqa: BLE001  (URLError, timeout, JSON, conn reset)
        rec["status"] = "ERROR"; rec["error"] = str(e)
        rec["wall_s"] = round(time.time() - t0, 2)
    return rec


# An Aegis-authored rule (rules/quality/bugs.yaml) that fires on `.length < 0` and
# appears in NO registry pack — the sentinel that proves the custom packs loaded.
_SENTINEL_RULE = "aegis-bug-js-length-lt-zero"


def preflight_custom_pack():
    """Prove, through the REAL /scan/sast path, that the Aegis custom packs loaded
    on this server before we trust this repo's SAST/bug numbers. V1 discovered a
    non-rule YAML in a semgrep-loaded dir silently degraded every scan to registry
    packs only; this catches a recurrence per repo."""
    pf = os.path.join(WORK, "_preflight")
    os.makedirs(pf, exist_ok=True)
    with open(os.path.join(pf, "g.js"), "w", encoding="utf-8") as fh:
        fh.write("function g(x) {\n  if (x.length < 0) {\n    return 1;\n  }\n}\n")
    rec = call_engine("sast", "/scan/sast", {}, 300, pf)
    ids = {f["rule_id"] for f in rec["findings"]}
    aegis = sorted(r for r in ids if str(r).startswith("aegis"))
    shutil.rmtree(pf, ignore_errors=True)
    return {"loaded": _SENTINEL_RULE in ids, "sentinel": _SENTINEL_RULE,
            "sast_status": rec["status"], "aegis_rules_seen": aegis}


def scan_all(repo_path):
    return [call_engine(n, p, b, t, repo_path) for (n, p, b, t) in ENGINES]


def attach_bug_context(engines, repo_path):
    """For every bug finding, grab a guaranteed 5-line source window (line ±2)
    while the clone still exists — the report's core evidence. file_path in
    findings is repo-relative; fall back to code_snippet if the file is gone."""
    for eng in engines:
        for f in eng["findings"]:
            if f.get("issue_type") != "bug":
                continue
            rel = f.get("file_path") or ""
            ln = f.get("line_start")
            f["context5"] = None
            if not ln:
                continue
            fp = os.path.join(repo_path, rel)
            if not os.path.isfile(fp):
                continue
            try:
                with open(fp, encoding="utf-8", errors="ignore") as fh:
                    lines = fh.read().splitlines()
                lo = max(1, ln - 2)
                hi = min(len(lines), ln + 2)
                f["context5"] = {
                    "start_line": lo,
                    "lines": lines[lo - 1:hi],
                    "flagged_line": ln,
                }
            except Exception:  # noqa: BLE001
                pass


def main():
    slug = sys.argv[1]            # e.g. snipe/snipe-it
    url = sys.argv[2]
    determinism = "--determinism" in sys.argv[3:]
    os.makedirs(OUT, exist_ok=True)
    name = slug.replace("/", "__")
    done = os.path.join(OUT, name + ".done")
    outp = os.path.join(OUT, name + ".json")
    if os.path.exists(done):
        os.remove(done)

    rec = {"slug": slug, "url": url, "started": time.time(),
           "iso_start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    # fresh workdir
    if os.path.isdir(WORK):
        shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK, exist_ok=True)
    repo_path = os.path.join(WORK, name)

    # 1. verify + clone (shallow)
    t0 = time.time()
    ls = sh(["git", "ls-remote", "--exit-code", url, "HEAD"], timeout=90)
    rec["url_resolves"] = (ls.returncode == 0)
    if ls.returncode != 0:
        rec["clone_error"] = "ls-remote failed: " + (ls.stderr or "")[:300]
        rec["status"] = "CLONE_FAILED"
        _finish(rec, outp, done)
        return
    cl = sh(["git", "clone", "--depth", "1", url, repo_path], timeout=600)
    rec["clone_s"] = round(time.time() - t0, 2)
    if cl.returncode != 0:
        rec["clone_error"] = (cl.stderr or "")[:500]
        rec["status"] = "CLONE_FAILED"
        _finish(rec, outp, done)
        return

    # 2. metadata
    rec["github"] = gh_meta(slug)
    lc = sh(["git", "-C", repo_path, "log", "-1", "--format=%cI"], timeout=30)
    rec["git_last_commit"] = (lc.stdout or "").strip() or None
    rec["loc"] = count_loc(repo_path)
    verdict, tools, evidence = detect_self_lint(repo_path)
    rec["self_lint"] = {"verdict": verdict, "tools": tools, "evidence": evidence}

    # 2b. PREFLIGHT — custom packs must be loaded or the SAST/bug numbers are
    # meaningless (registry-only). Recorded per repo; the host aborts on "no".
    rec["custom_pack"] = preflight_custom_pack()

    # 3. scan
    scan_t0 = time.time()
    rec["engines"] = scan_all(repo_path)
    rec["scan_wall_s"] = round(time.time() - scan_t0, 2)
    attach_bug_context(rec["engines"], repo_path)
    rec["status"] = "COMPLETED"

    # 4. determinism (optional): re-scan the SAME tree, compare fingerprints
    if determinism:
        second = scan_all(repo_path)
        def fps(engs):
            s = set()
            for e in engs:
                for f in e["findings"]:
                    s.add((f["engine"], f["rule_id"], f["file_path"],
                           f["line_start"], f["fingerprint"]))
            return s
        a, b = fps(rec["engines"]), fps(second)
        rec["determinism"] = {
            "run1_findings": len(a), "run2_findings": len(b),
            "identical": a == b,
            "only_in_run1": [list(x) for x in list(a - b)[:20]],
            "only_in_run2": [list(x) for x in list(b - a)[:20]],
        }

    _finish(rec, outp, done, repo_path)


def _finish(rec, outp, done, repo_path=None):
    rec["ended"] = time.time()
    rec["total_wall_s"] = round(rec["ended"] - rec["started"], 2)
    with open(outp, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=1)
    # cleanup clone to protect disk
    if repo_path and os.path.isdir(os.path.dirname(repo_path)):
        shutil.rmtree(os.path.dirname(repo_path), ignore_errors=True)
    with open(done, "w") as fh:
        fh.write(rec.get("status", "?"))
    cp = rec.get("custom_pack") or {}
    cp_disp = ("PACK=YES" if cp.get("loaded") else "PACK=NO!!") if cp else "PACK=?"
    print(f"[{rec['slug']}] status={rec.get('status')} {cp_disp} "
          f"wall={rec.get('total_wall_s')}s "
          f"findings={sum(e['n_findings'] for e in rec.get('engines', []))}")


if __name__ == "__main__":
    main()
