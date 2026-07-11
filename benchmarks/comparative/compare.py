"""Track 2c comparative harness. Runs inside the scanner image (semgrep + trivy
present) against a cloned repo, producing a compact JSON comparison of:

  - Semgrep Community  (p/default — the bare community security ruleset)
  - Aegis SAST         (Aegis's fuller config + custom taint rules)
  - Trivy              (fs: dependency CVEs + secrets + IaC misconfig)

For each: total findings, severity distribution, and per-KLOC. Findings unique
to Aegis vs Semgrep-CE are reported (same engine family → directly comparable).

Usage: python compare.py <repo_path> <name> <lang>   # lang in java|python|javascript|go
"""
import json, os, re, subprocess, sys

repo, name, lang = sys.argv[1], sys.argv[2], sys.argv[3]
AEGIS_RULES = f"/aegisrules/taint/{lang}.yaml"
SRC_EXT = {".java", ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php"}

def loc(path):
    total = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "vendor", "testdata", "test", "tests")]
        for f in files:
            if os.path.splitext(f)[1] in SRC_EXT:
                try:
                    with open(os.path.join(root, f), encoding="utf-8", errors="ignore") as fh:
                        total += sum(1 for ln in fh if ln.strip())
                except OSError:
                    pass
    return total

def run(cmd, timeout=1200):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except subprocess.TimeoutExpired:
        return ""

def sev_bucket_semgrep(r):
    s = (r.get("extra") or {}).get("severity", "INFO")
    return {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(s, "low")

def semgrep(configs):
    args = ["semgrep", "scan", "--json", "--quiet", "--metrics", "off",
            "--disable-version-check", "--timeout", "60", "--jobs", str(os.cpu_count() or 4)]
    for c in configs:
        args += ["--config", c]
    args += ["--exclude", "node_modules", "--exclude", ".venv", "--exclude", "vendor",
             "--exclude", "test", "--exclude", "tests", "--exclude", "testdata", repo]
    out = run(args)
    try:
        results = json.loads(out).get("results", [])
    except json.JSONDecodeError:
        return {"total": 0, "by_sev": {}, "rules": set(), "keys": set()}
    by_sev = {}
    keys = set()
    for r in results:
        b = sev_bucket_semgrep(r)
        by_sev[b] = by_sev.get(b, 0) + 1
        keys.add((r.get("check_id"), r.get("path"), (r.get("start") or {}).get("line")))
    return {"total": len(results), "by_sev": by_sev, "keys": keys}

def trivy():
    out = run(["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,secret,misconfig",
               "--skip-dirs", "node_modules,.venv,vendor", repo])
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {"total": 0, "by_sev": {}}
    by_sev = {}
    total = 0
    for res in data.get("Results", []):
        for v in (res.get("Vulnerabilities") or []) + (res.get("Misconfigurations") or []) + (res.get("Secrets") or []):
            sev = (v.get("Severity") or "UNKNOWN").lower()
            by_sev[sev] = by_sev.get(sev, 0) + 1
            total += 1
    return {"total": total, "by_sev": by_sev}

kloc = max(loc(repo) / 1000.0, 0.001)
sg_ce = semgrep(["p/default"])
aegis_cfgs = ["p/owasp-top-ten", "p/r2c-security-audit", "p/cwe-top-25", "p/default", "p/secrets"]
if os.path.exists(AEGIS_RULES):
    aegis_cfgs.append(AEGIS_RULES)
aegis = semgrep(aegis_cfgs)
tv = trivy()

aegis_unique = len(aegis["keys"] - sg_ce["keys"])
shared = len(aegis["keys"] & sg_ce["keys"])

out = {
    "repo": name, "lang": lang, "kloc": round(kloc, 1),
    "semgrep_ce": {"total": sg_ce["total"], "by_sev": sg_ce["by_sev"], "per_kloc": round(sg_ce["total"] / kloc, 2)},
    "aegis_sast": {"total": aegis["total"], "by_sev": aegis["by_sev"], "per_kloc": round(aegis["total"] / kloc, 2)},
    "trivy": {"total": tv["total"], "by_sev": tv["by_sev"], "per_kloc": round(tv["total"] / kloc, 2)},
    "aegis_vs_ce": {"aegis_unique": aegis_unique, "shared": shared},
}
print("RESULT_JSON " + json.dumps(out))
