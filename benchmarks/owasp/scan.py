import json, urllib.request, urllib.error, time

SCANNER = "http://scanner:8000"
PATH = "/workspaces/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode"

body = json.dumps({"path": PATH, "scan_id": "owasp-bench", "languages": ["java"]}).encode()
req = urllib.request.Request(f"{SCANNER}/scan/sast", data=body, method="POST")
req.add_header("Content-Type", "application/json")
t0 = time.time()
print(f"scanning {PATH} ...", flush=True)
try:
    with urllib.request.urlopen(req, timeout=3600) as r:
        res = json.loads(r.read())
except urllib.error.HTTPError as e:
    print("HTTP", e.code, e.read()[:500]); raise SystemExit(1)

fs = res.get("findings") or []
print(f"status={res.get('status')} findings={len(fs)} elapsed={int(time.time()-t0)}s", flush=True)

# keep only what scoring needs
slim = [{"file": f.get("file_path"), "cwe": f.get("cwe_id"),
         "rule": f.get("rule_id"), "owasp": f.get("owasp_category")} for f in fs]
with open("/v/_aegis_findings.json", "w") as fh:
    json.dump(slim, fh)
print("wrote /v/_aegis_findings.json", flush=True)

# quick CWE distribution
dist = {}
for f in slim:
    dist[f["cwe"]] = dist.get(f["cwe"], 0) + 1
print("CWE distribution:", json.dumps(dict(sorted(dist.items(), key=lambda x: -x[1])[:15])), flush=True)
