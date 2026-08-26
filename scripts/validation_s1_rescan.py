#!/usr/bin/env python3
"""S1 live re-scan (in-container): clone a repo, run the security-critical engines
with the NEW code, report secrets + critical counts. Skips quality (it never emits
a critical, and it is the slow engine). Writes /workspaces/_s1out/<slug>.json."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from collections import Counter

BASE = "http://127.0.0.1:8000"
OUT = "/workspaces/_s1out"
WORK = "/workspaces/_s1clone"
ENGINES = [("sast", "/scan/sast", 1500), ("sca", "/scan/sca", 900),
           ("secrets", "/scan/secrets", 600)]


def call(path, body, timeout):
    data = json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def main():
    slug, url = sys.argv[1], sys.argv[2]
    name = slug.replace("/", "__")
    os.makedirs(OUT, exist_ok=True)
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    repo = os.path.join(WORK, name)
    subprocess.run(["git", "clone", "--depth", "1", url, repo], capture_output=True,
                   text=True, timeout=900)

    rec = {"slug": slug, "engines": {}}
    for eng, path, to in ENGINES:
        t0 = time.time()
        try:
            res = call(path, {"path": repo, "scan_id": f"s1-{eng}"}, to)
            fs = res.get("findings") or []
            rec["engines"][eng] = {
                "status": res.get("status"), "n": len(fs), "wall": round(time.time() - t0, 1),
                "sev": dict(Counter(f.get("severity") for f in fs)),
                "secret_context": dict(Counter((f.get("metadata") or {}).get("secret_context")
                                               for f in fs if (f.get("metadata") or {}).get("secret_context"))),
                "findings": [{"rule_id": f.get("rule_id"), "severity": f.get("severity"),
                              "file_path": f.get("file_path"),
                              "secret_context": (f.get("metadata") or {}).get("secret_context"),
                              "cvss_score": (f.get("metadata") or {}).get("cvss_score"),
                              "cvss_source": (f.get("metadata") or {}).get("cvss_source"),
                              "package": (f.get("metadata") or {}).get("package")} for f in fs],
            }
        except Exception as e:  # noqa: BLE001
            rec["engines"][eng] = {"status": "ERROR", "error": str(e), "wall": round(time.time() - t0, 1)}

    crit = sum(1 for e in rec["engines"].values() for f in e.get("findings", []) if f["severity"] == "critical")
    secrets_n = rec["engines"].get("secrets", {}).get("n", 0)
    rec["critical_total_secpillars"] = crit
    rec["secrets_total"] = secrets_n
    json.dump(rec, open(os.path.join(OUT, name + ".json"), "w"), indent=1)
    with open(os.path.join(OUT, name + ".done"), "w") as fh:
        fh.write("done")
    shutil.rmtree(WORK, ignore_errors=True)
    print(f"[{slug}] secrets={secrets_n} crit(sec-pillars)={crit} "
          f"ctx={rec['engines'].get('secrets',{}).get('secret_context')}")


if __name__ == "__main__":
    main()
