"""D2: run the product's semgrep engine (engines.semgrep_engine.run, the code path a real
scan takes) over one repository several times on one commit, and record, per run, the
findings and every error semgrep reports (timeouts, memory, parse). Runs inside the
scanner container from /app.

usage: python3 d2_run.py <out_dir> <runs> <repo_path> [<repo_path> ...]
       runs: a count (1..N) or a comma list of run numbers; runs are the OUTER loop
"""
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, "/app")
from config import get_settings  # noqa: E402
from engines import semgrep_engine as se  # noqa: E402
from models.scan_request import ScanRequest  # noqa: E402

out_dir, runs, repos = sys.argv[1], sys.argv[2], sys.argv[3:]
runs = [int(x) for x in runs.split(",")] if "," in runs else list(range(1, int(runs) + 1))
os.makedirs(out_dir, exist_ok=True)
settings = get_settings()
se._PARTIAL_SAMPLE = 10 ** 6  # the record needs every disclosed file, not the 25 a scan shows


def errors_of(raw):
    out = []
    for e in (raw or {}).get("errors", []) or []:
        spans = e.get("spans") or [{}]
        out.append({"type": e.get("type") if isinstance(e.get("type"), str) else json.dumps(e.get("type"))[:80],
                    "level": e.get("level"), "rule": e.get("rule_id"),
                    "path": e.get("path") or spans[0].get("file"),
                    "message": (e.get("message") or "")[:160]})
    return out


for i in runs:
    for repo in repos:
        name = os.path.basename(repo.rstrip("/"))
        out = os.path.join(out_dir, f"{name}.run{i}.json")
        if os.path.exists(out):
            print("have", out, flush=True)
            continue
        t0 = time.time()
        res = asyncio.run(se.run(ScanRequest(path=repo, scan_id=f"d2-{name}-{i}"), settings))
        doc = {"repo": name, "run": i, "status": str(res.status), "error": res.error,
               "seconds": round(time.time() - t0, 1),
               "findings": sorted({(f.rule_id, f.file_path, f.line_start or 0) for f in res.findings}),
               "errors": errors_of(res.raw),
               "partially_analysed": (res.security_coverage or {}).get("partially_analysed"),
               "quadrant": (res.security_coverage or {}).get("quadrant")}
        json.dump(doc, open(out, "w"), indent=0)
        print(name, i, doc["status"], doc["seconds"], "s", len(doc["findings"]), "findings",
              len(doc["errors"]), "errors", flush=True)
