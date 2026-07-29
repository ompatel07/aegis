"""B6 Deployment-test accuracy: build known-good and known-broken projects, run
/scan/deployment, and confirm the engine PASSES the good builds and FAILS the
broken ones (deployment/build-failed finding + build_succeeded=false)."""
import json, os, shutil, urllib.request

ROOT = "/tmp/deploycorpus"
shutil.rmtree(ROOT, ignore_errors=True)

PROJECTS = {
    # name: (expect_build_ok, {relpath: content})
    "good_go": (True, {
        "go.mod": "module goodgo\n\ngo 1.22\n",
        "main.go": "package main\n\nfunc main() {\n\tprintln(\"ok\")\n}\n",
    }),
    "broken_go": (False, {
        "go.mod": "module brokengo\n\ngo 1.22\n",
        # compile error: assignment with no RHS
        "main.go": "package main\n\nfunc main() {\n\tx := \n\t_ = x\n}\n",
    }),
    "good_node": (True, {
        "package.json": json.dumps({"name": "goodnode", "version": "1.0.0",
                                     "scripts": {"build": "node -e \"require('./index.js')\""}}),
        "index.js": "module.exports = { ok: true };\n",
    }),
    "broken_node": (False, {
        "package.json": json.dumps({"name": "brokennode", "version": "1.0.0",
                                    "scripts": {"build": "node -e \"require('./index.js')\""}}),
        # syntax error
        "index.js": "module.exports = { ok: true \n",
    }),
}


def scan_deployment(path):
    body = json.dumps({"path": path, "scan_id": "deploy", "smoke_test": False}).encode()
    req = urllib.request.Request("http://localhost:8000/scan/deployment", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read())


results = []
for name, (expect_ok, files) in PROJECTS.items():
    d = os.path.join(ROOT, name)
    os.makedirs(d, exist_ok=True)
    for rel, content in files.items():
        with open(os.path.join(d, rel), "w") as fh:
            fh.write(content)
    res = scan_deployment(d)
    raw = res.get("raw") or {}
    findings = res.get("findings") or []
    build_failed_finding = any("build-failed" in (f.get("rule_id") or "") for f in findings)
    build_ok = raw.get("build_succeeded")
    # engine PASSES the build iff no build-failed finding
    verdict_ok = (not build_failed_finding) if expect_ok else build_failed_finding
    results.append((name, expect_ok, build_ok, build_failed_finding, verdict_ok))
    print(f"{name:12} expect_build_ok={expect_ok!s:5} build_succeeded={build_ok!s:5} "
          f"build_failed_finding={build_failed_finding!s:5} -> {'CORRECT' if verdict_ok else 'WRONG'}",
          flush=True)
    # show the build step tail for broken ones
    if not expect_ok:
        for s in raw.get("steps", []):
            if s.get("name") == "build":
                print(f"    build step tail: {(s.get('output_tail') or '')[-160:]}", flush=True)

allok = all(r[4] for r in results)
print("\nOVERALL:", "ALL CORRECT — passes good, fails broken" if allok else "SOME WRONG")
shutil.rmtree(ROOT, ignore_errors=True)
