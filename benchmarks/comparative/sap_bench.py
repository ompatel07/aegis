"""Track 2b — real-world CVE detection on the SAP/Ponta MSR-2019 corpus.

For each (CVE, repo, fix_commit): fetch the fix commit + its parent by SHA
(depth 2, no full history), check out the *parent* (the vulnerable state), and
test whether Aegis's SAST flags the code the fix changed. Ground truth = the
files + parent-side line ranges the fix touched (the standard fix-commit-as-
oracle methodology; its limitation — a fix may live in a different file than the
vulnerable sink — is noted in QUALITY_BENCHMARK.md).

Two detection definitions, both reported:
  - file-level  : any Aegis finding in a fix-touched .java file  (lenient upper bound)
  - line-level  : an Aegis finding within +/-10 lines of a parent-side changed hunk
                  (strict; comparable to the paper's location match)

Baseline: FindSecBugs detected 26.5% of 170 Java CVEs (Bennett et al. 2024).

Usage: python sap_bench.py sample.tsv     # tsv: CVE\trepo_url\tfix_sha
"""
import json, os, re, subprocess, sys, tempfile, shutil

SAMPLE = sys.argv[1]
WORK = "/tmp/t2b"
WINDOW = 10
AEGIS_CFGS = ["p/owasp-top-ten", "p/r2c-security-audit", "p/cwe-top-25", "p/default", "p/secrets"]
JAVA_RULES = "/app/rules/taint/java.yaml"
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? ")


def run(cmd, cwd=None, timeout=300):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"


def parent_changed_ranges(repo_dir, sha, path):
    """Parent-side (vulnerable) line ranges the fix modified in `path`."""
    _, out, _ = run(["git", "diff", f"{sha}~1", sha, "--", path], cwd=repo_dir)
    ranges = []
    for line in out.splitlines():
        m = HUNK.match(line)
        if m:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) else 1
            if count > 0:
                ranges.append((start, start + count - 1))
    return ranges


def semgrep(repo_dir, files):
    args = ["semgrep", "scan", "--json", "--quiet", "--metrics", "off",
            "--disable-version-check", "--timeout", "60", "--jobs", str(os.cpu_count() or 4)]
    for c in AEGIS_CFGS:
        args += ["--config", c]
    if os.path.exists(JAVA_RULES):
        args += ["--config", JAVA_RULES]
    args += files
    rc, out, err = run(args, cwd=repo_dir, timeout=300)
    try:
        results = json.loads(out).get("results", [])
    except json.JSONDecodeError:
        return None, err[-200:]
    hits = []
    for r in results:
        # semgrep echoes back the (relative) paths we passed; keep as-is and match
        # on basename so no path-format mismatch can silently break line matching.
        hits.append({"path": r.get("path", ""),
                     "line": (r.get("start") or {}).get("line"),
                     "rule": r.get("check_id", "")})
    return hits, None


def evaluate(cve, repo, sha):
    d = os.path.join(WORK, cve.replace("/", "_"))
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d, exist_ok=True)
    rec = {"cve": cve, "repo": repo.split("/")[-1], "sha": sha[:10]}
    try:
        run(["git", "init", "-q"], cwd=d)
        run(["git", "remote", "add", "origin", repo], cwd=d)
        rc, _, err = run(["git", "fetch", "-q", "--depth", "2", "origin", sha], cwd=d, timeout=300)
        if rc != 0:
            rec["status"] = "fetch_failed"
            rec["err"] = (err or "")[-160:]
            return rec
        run(["git", "checkout", "-q", f"{sha}~1"], cwd=d)   # parent = vulnerable
        _, names, _ = run(["git", "show", "--pretty=format:", "--name-only", sha], cwd=d)
        touched = [p for p in names.splitlines() if p.strip().endswith(".java")]
        touched_at_parent = [p for p in touched if os.path.exists(os.path.join(d, p))]
        rec["touched_java"] = len(touched)
        rec["scanned_java"] = len(touched_at_parent)
        rec["sast_relevant"] = len(touched_at_parent) > 0
        if not touched_at_parent:
            rec["status"] = "no_java_at_parent"      # fix added-only / non-java; not source-detectable
            rec["file_detect"] = rec["line_detect"] = False
            return rec
        # ground-truth parent-side changed ranges per touched file, keyed by basename
        ranges = {os.path.basename(p): parent_changed_ranges(d, sha, p) for p in touched_at_parent}
        hits, serr = semgrep(d, touched_at_parent)
        if hits is None:
            rec["status"] = "semgrep_error"
            rec["err"] = serr
            return rec
        rec["status"] = "ok"
        rec["findings_in_touched"] = len(hits)
        rec["rules"] = sorted({h["rule"] for h in hits})[:15]  # for relevance dissection
        file_detect = len(hits) > 0
        line_detect = False
        matched_rule = None
        for h in hits:
            for (a, b) in ranges.get(os.path.basename(h["path"]), []):
                if h["line"] is not None and a - WINDOW <= h["line"] <= b + WINDOW:
                    line_detect = True
                    matched_rule = h["rule"]
                    break
            if line_detect:
                break
        rec["file_detect"] = file_detect
        rec["line_detect"] = line_detect
        if matched_rule:
            rec["matched_rule"] = matched_rule
        elif file_detect:
            rec["sample_rule"] = hits[0]["rule"]
        return rec
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    os.makedirs(WORK, exist_ok=True)
    sample = [l.rstrip("\n").split("\t") for l in open(SAMPLE, encoding="utf-8") if l.strip()]
    for cve, repo, sha in sample:
        rec = evaluate(cve, repo, sha)
        print("SAP_RESULT_JSON " + json.dumps(rec), flush=True)


if __name__ == "__main__":
    main()
