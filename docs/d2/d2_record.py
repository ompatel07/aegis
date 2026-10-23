"""D2: is repeat-scan variance bounded by what the scan disclosed?

For each repository scanned N times on one commit (d2_run.py), checks that
  1. every run ended the same way -- all COMPLETED, or all FAILED (a repository that
     fails every run is repeatable, without findings, and is listed), and
  2. every finding not present in ALL runs lies in a file at least one run disclosed as
     partially analysed (coverage.partially_analysed) -- variance nowhere else.
Prints one row per repository and the totals; exits 1 if either check fails anywhere.

usage: python d2_record.py <d2_out_dir> [--json out.json]
"""
import collections
import glob
import json
import os
import sys


def load(out_dir):
    runs = collections.defaultdict(list)
    for f in sorted(glob.glob(os.path.join(out_dir, "*.run*.json"))):
        d = json.load(open(f, encoding="utf-8"))
        runs[d["repo"]].append(d)
    return runs


def rel(path, repo):
    marker = f"/{repo}/"
    return path.split(marker, 1)[1] if marker in path else path


def main():
    out_dir = sys.argv[1]
    rows, ok = [], True
    for repo, rs in sorted(load(out_dir).items()):
        rs.sort(key=lambda d: d["run"])
        statuses = [d["status"].split(".")[-1] for d in rs]
        sets = [{(r, rel(f, repo), l) for r, f, l in d["findings"]} for d in rs]
        stable = set.intersection(*sets) if sets else set()
        unstable = set.union(*sets) - stable if sets else set()
        disclosed = set()
        for d in rs:
            disclosed |= set((d.get("partially_analysed") or {}).get("sample") or [])
        undisclosed = sorted(x for x in unstable if x[1] not in disclosed)
        complete = all(s == "COMPLETED" for s in statuses)
        same_outcome = len(set(statuses)) == 1
        ok &= same_outcome and not undisclosed
        rows.append({
            "repo": repo, "runs": len(rs), "statuses": statuses,
            "seconds": [d["seconds"] for d in rs],
            "findings": [len(s) for s in sets], "stable": len(stable), "unstable": len(unstable),
            "disclosed_files": [(d.get("partially_analysed") or {}).get("files", 0) for d in rs],
            "unstable_in_disclosed": len(unstable) - len(undisclosed),
            "undisclosed": undisclosed, "identical": len(unstable) == 0 and complete,
            "fails_every_run": statuses[0] == "FAILED" and same_outcome,
        })
    w = max(len(r["repo"]) for r in rows)
    print(f"{'repo':{w}s}  runs  status  seconds            findings        stable unstable  "
          f"disclosed files   undisclosed")
    for r in rows:
        st = ("ok" if all(s == "COMPLETED" for s in r["statuses"])
              else "FAILS" if r["fails_every_run"] else ",".join(r["statuses"]))
        print(f"{r['repo']:{w}s}  {r['runs']:4d}  {st:6s}  {str(r['seconds']):18s} {str(r['findings']):15s} "
              f"{r['stable']:6d} {r['unstable']:8d}  {str(r['disclosed_files']):16s}  {len(r['undisclosed'])}")
        for u in r["undisclosed"]:
            print("      UNDISCLOSED", u)
    n = len(rows)
    print(f"\n{n} repositories; {sum(r['identical'] for r in rows)} identical across all runs; "
          f"{sum(r['unstable'] for r in rows)} unstable finding(s) in {sum(1 for r in rows if r['unstable'])} "
          f"repositories, {sum(r['unstable_in_disclosed'] for r in rows)} of them in disclosed files; "
          f"{sum(len(r['undisclosed']) for r in rows)} undisclosed; "
          f"failing every run: {[r['repo'] for r in rows if r['fails_every_run']] or 'none'}")
    if "--json" in sys.argv:
        json.dump(rows, open(sys.argv[sys.argv.index("--json") + 1], "w", encoding="utf-8"), indent=1)
    print("BOUNDED" if ok else "NOT BOUNDED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
