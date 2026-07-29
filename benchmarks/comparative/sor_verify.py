"""Verify Steps-of-Reproduction accuracy on real comparative repos: scan each,
collect findings that carry steps_to_reproduce, then read the ACTUAL source/sink
lines from the cloned repo and confirm the reported code matches the file. Runs
inside the scanner container."""
import json, os, subprocess, urllib.request

SC = "http://localhost:8000"
REPOS = [
    ("express", "javascript", "https://github.com/expressjs/express", "master"),
    ("flask", "python", "https://github.com/pallets/flask", "main"),
    ("juice-shop", "javascript", "https://github.com/juice-shop/juice-shop", "master"),
]


def scan(path, lang):
    b = json.dumps({"path": path, "scan_id": "sorv", "languages": [lang]}).encode()
    r = urllib.request.Request(f"{SC}/scan/sast", data=b, method="POST")
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=1200) as x:
            return json.loads(x.read()).get("findings") or []
    except Exception as e:
        print("scan error", e); return []


def line_of(root, relfile, line):
    fp = os.path.join(root, relfile)
    try:
        with open(fp, encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
        return lines[line - 1].strip() if 1 <= line <= len(lines) else ""
    except OSError:
        return ""


def norm(s):
    return "".join((s or "").split())


total = matched = 0
examples = []
for name, lang, url, br in REPOS:
    d = f"/tmp/sorv-{name}"
    subprocess.run(["rm", "-rf", d])
    subprocess.run(["git", "clone", "--depth", "1", "--branch", br, url, d], capture_output=True)
    fs = scan(d, lang)
    sor_fs = [f for f in fs if (f.get("context_metadata") or {}).get("steps_to_reproduce")]
    print(f"{name}: {len(fs)} findings, {len(sor_fs)} with steps_to_reproduce", flush=True)
    for f in sor_fs:
        s = f["context_metadata"]["steps_to_reproduce"]
        for role in ("source", "sink"):
            node = s[role]
            if node.get("line") is None:
                continue
            total += 1
            actual = line_of(d, node["file"], node["line"])
            # the reported code should appear within the actual line (semgrep may
            # report a sub-expression), compared whitespace-insensitively
            ok = norm(node["code"]) in norm(actual) or norm(actual) in norm(node["code"])
            matched += ok
            if len(examples) < 12 and ok:
                examples.append((name, f["rule_id"].split(".")[-1], role, node["file"].split("/")[-1],
                                 node["line"], node["code"][:60]))
            elif not ok:
                print(f"  MISMATCH {name} {role} {node['file']}:{node['line']} reported={node['code'][:50]!r} actual={actual[:50]!r}", flush=True)
    subprocess.run(["rm", "-rf", d])

print(f"\n=== SoR source/sink nodes verified against actual code: {matched}/{total} match ===")
print("sample verified nodes (repo | rule | role | file:line | code):")
for e in examples:
    print(f"  {e[0]:11} {e[1][:26]:26} {e[2]:6} {e[3]}:{e[4]}  {e[5]}")
