"""Real-world FP sampling: clone repos, run each SAST/SCA/secrets engine via the
scanner, and dump every finding WITH a code snippet (flagged line +/- 3) so the
findings can be manually adjudicated TP vs FP. Runs inside the scanner container."""
import json, os, subprocess, urllib.request, urllib.error, random

SCANNER = "http://localhost:8000"
REPOS = [
    ("express", "javascript", "https://github.com/expressjs/express", "master"),
    ("flask", "python", "https://github.com/pallets/flask", "main"),
    ("gin", "go", "https://github.com/gin-gonic/gin", "master"),
]
random.seed(42)


def post(endpoint, path, languages):
    body = json.dumps({"path": path, "scan_id": "fp-" + endpoint, "languages": languages}).encode()
    req = urllib.request.Request(f"{SCANNER}/scan/{endpoint}", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=1200) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"status": "error", "findings": [], "err": e.read()[:200].decode(errors="ignore")}


def snippet(root, rel, line):
    if not rel or not line:
        return ""
    fp = os.path.join(root, rel)
    try:
        with open(fp, encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return ""
    lo, hi = max(0, line - 2), min(len(lines), line + 1)
    return "".join(f"{i+1}: {lines[i]}" for i in range(lo, hi)).rstrip()


all_findings = []
for name, lang, url, branch in REPOS:
    d = f"/tmp/fp-{name}"
    subprocess.run(["rm", "-rf", d])
    subprocess.run(["git", "clone", "--depth", "1", "--branch", branch, url, d],
                   capture_output=True)
    for eng, langs in [("sast", [lang]), ("sca", [lang]), ("secrets", [lang])]:
        res = post(eng, d, langs)
        fs = res.get("findings") or []
        for f in fs:
            rel = f.get("file_path", "")
            ln = f.get("line_start")
            all_findings.append({
                "repo": name, "engine": eng, "rule": f.get("rule_id", ""),
                "severity": (f.get("severity") or ""), "title": f.get("title", "")[:100],
                "file": rel, "line": ln,
                "snippet": snippet(d, rel, ln) if eng == "sast" else "",
                "meta_pkg": (f.get("metadata") or {}).get("package", ""),
            })
        print(f"{name}/{eng}: {len(fs)} findings", flush=True)

with open("/tmp/fp_all.json", "w") as fh:
    json.dump(all_findings, fh, indent=1)
by_eng = {}
for f in all_findings:
    by_eng[f["engine"]] = by_eng.get(f["engine"], 0) + 1
print("TOTAL:", len(all_findings), "by engine:", by_eng, flush=True)
