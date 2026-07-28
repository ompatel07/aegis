"""Track 2f deep-scan value harness. Runs inside the *deep* scanner image
(semgrep + Joern present) against a cloned repo, and measures what Joern's
interprocedural CPG taint analysis adds on top of Aegis's fast Semgrep pass.

It mirrors the product's real merge behaviour (orchestrator deepmerge.go): a
Joern flow is treated as *corroborating* a fast finding when they share the same
CWE + file within a 2-line window; otherwise it is *net-new*. Among net-new
flows we count the ones that are genuinely multi-hop / cross-function — the class
Semgrep's fast intra-file pass structurally cannot follow.

Usage: python deep_compare.py <repo_path> <name> <lang>   # lang java|python|javascript|typescript|go
"""
import json, os, re, subprocess, sys, time

repo, name, lang = sys.argv[1], sys.argv[2], sys.argv[3]
# Aegis's own taint rules ship inside the scanner image at /app/rules/taint/.
# TS reuses the javascript ruleset (no separate typescript.yaml).
_rule_lang = "javascript" if lang == "typescript" else lang
AEGIS_RULES = f"/app/rules/taint/{_rule_lang}.yaml"
SRC_EXT = {".java", ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php"}
DEDUPE_LINE_WINDOW = 2  # same constant as pipeline/deepmerge.go
CWE_RX = re.compile(r"(CWE-\d+)", re.I)

# The five vuln classes taint.sc emits, and the CWE each maps to — used to line
# Joern flows up against Semgrep findings on the same CWE.
JOERN_CWES = {"CWE-89", "CWE-78", "CWE-79", "CWE-918", "CWE-22"}


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


def run(cmd, timeout=1800, env=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"


def norm_cwe(val):
    """Pull the first CWE-NNN token out of a semgrep metadata.cwe field (str/list)."""
    if isinstance(val, list):
        val = " ".join(str(v) for v in val)
    m = CWE_RX.search(str(val or ""))
    return m.group(1).upper() if m else ""


def semgrep(configs):
    """Aegis fast pass. Returns finding keys plus the subset that carry a CWE in
    the Joern-overlapping classes (file, line, cwe) — the ones a Joern flow could
    corroborate."""
    args = ["semgrep", "scan", "--json", "--quiet", "--metrics", "off",
            "--disable-version-check", "--timeout", "60", "--jobs", str(os.cpu_count() or 4)]
    for c in configs:
        args += ["--config", c]
    args += ["--exclude", "node_modules", "--exclude", ".venv", "--exclude", "vendor",
             "--exclude", "test", "--exclude", "tests", "--exclude", "testdata", repo]
    _, out, _ = run(args, timeout=1200)
    try:
        results = json.loads(out).get("results", [])
    except json.JSONDecodeError:
        return {"total": 0, "keys": set(), "cwe_locs": []}
    keys = set()
    cwe_locs = []  # (cwe, rel_file, line) for findings whose CWE overlaps Joern's classes
    for r in results:
        path = os.path.relpath(r.get("path", ""), repo)
        line = (r.get("start") or {}).get("line")
        keys.add((r.get("check_id"), path, line))
        meta = ((r.get("extra") or {}).get("metadata") or {})
        cwe = norm_cwe(meta.get("cwe"))
        if cwe in JOERN_CWES and line is not None:
            # match on basename: joern and semgrep can format paths differently;
            # basename+CWE+line is deliberately generous so we never miscount a
            # corroborated flow as net-new (which would overstate Joern's value).
            cwe_locs.append((cwe, os.path.basename(path), line))
    return {"total": len(results), "keys": keys, "cwe_locs": cwe_locs}


def joern(path):
    """Build a CPG and run the Aegis taint query. Returns status + parsed flows.
    Heap is capped so a runaway CPG build fails cleanly (recorded as skipped)
    rather than getting the container OOM-killed."""
    env = dict(os.environ, _JAVA_OPTIONS="-Xmx3g")
    workdir = f"/tmp/joern-{name}"
    os.makedirs(workdir, exist_ok=True)
    cpg = os.path.join(workdir, "cpg.bin")
    out = os.path.join(workdir, "findings.json")
    script = "/app/engines/joern/taint.sc"

    t0 = time.time()
    rc, _, err = run(["joern-parse", path, "--output", cpg], timeout=1500, env=env)
    parse_s = round(time.time() - t0, 1)
    if rc == 124:
        return {"status": "timeout_parse", "parse_s": parse_s, "flows": []}
    if rc != 0 or not os.path.exists(cpg):
        return {"status": "parse_failed", "parse_s": parse_s, "flows": [], "err": (err or "")[-300:]}

    t1 = time.time()
    rc, _, err = run(["joern", "--script", script, "--param", f"cpgFile={cpg}",
                      "--param", f"outFile={out}"], timeout=1500, env=env)
    query_s = round(time.time() - t1, 1)
    if rc == 124:
        return {"status": "timeout_query", "parse_s": parse_s, "query_s": query_s, "flows": []}
    try:
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"status": "no_output", "parse_s": parse_s, "query_s": query_s, "flows": [],
                "err": (err or "")[-300:]}

    def rel(f):
        # joern already emits root-relative paths; only rebase if absolute.
        if not f:
            return ""
        return os.path.relpath(f, path) if os.path.isabs(f) else f

    flows = []
    for item in data.get("findings", []) or []:
        flow = item.get("flow", []) or []
        files = {s.get("file", "") for s in flow if s.get("file")}
        flows.append({
            "cwe": (item.get("cwe") or "").upper(),
            "vuln_class": item.get("vulnClass", ""),
            "file": rel(item.get("file", "")),
            "line": item.get("lineStart"),
            "steps": len(flow),
            "files_spanned": len(files),
            "flow": [{"file": rel(s.get("file", "")), "line": s.get("line"),
                      "code": (s.get("code") or "")[:160]} for s in flow],
        })
    return {"status": "completed", "parse_s": parse_s, "query_s": query_s, "flows": flows}


def corroborates(flow, cwe_locs):
    """True if a fast finding shares this flow's CWE + file within the 2-line
    window (mirrors deepmerge.matchingDeep)."""
    fc, ff, fl = flow["cwe"], os.path.basename(flow["file"] or ""), flow["line"]
    if not fc or not ff:
        return False
    for (cwe, base, line) in cwe_locs:
        if cwe == fc and base == ff:
            if fl is None or line is None or abs(int(fl) - int(line)) <= DEDUPE_LINE_WINDOW:
                return True
    return False


kloc = max(loc(repo) / 1000.0, 0.001)
aegis_cfgs = ["p/owasp-top-ten", "p/r2c-security-audit", "p/cwe-top-25", "p/default", "p/secrets"]
if os.path.exists(AEGIS_RULES):
    aegis_cfgs.append(AEGIS_RULES)

fast = semgrep(aegis_cfgs)
deep = joern(repo)

from collections import Counter

netnew = corroborating = 0
netnew_multifile = netnew_multistep = 0
netnew_flows = []                         # raw net-new paths (each path counted once)
sink_paths = Counter()                    # unique sink -> number of enumerated paths
sink_props = {}                           # unique sink -> {multifile, multistep, vuln_class}
for fl in deep.get("flows", []):
    if corroborates(fl, fast["cwe_locs"]):
        corroborating += 1
        continue
    netnew += 1
    multifile = fl["files_spanned"] > 1
    multistep = fl["steps"] >= 3          # source -> >=1 intermediate -> sink
    if multifile:
        netnew_multifile += 1
    if multistep:
        netnew_multistep += 1
    netnew_flows.append(fl)
    key = (fl["cwe"], os.path.basename(fl["file"] or ""), fl["line"])
    sink_paths[key] += 1
    p = sink_props.setdefault(key, {"multifile": False, "multistep": False, "vuln_class": fl["vuln_class"]})
    p["multifile"] = p["multifile"] or multifile
    p["multistep"] = p["multistep"] or multistep

# Dedup by unique sink (cwe, file, line) — the honest "distinct issue" count, vs
# the raw path count Joern enumerates (many paths can reach one sink).
uniq = list(sink_paths.keys())
uniq_multifile = sum(1 for k in uniq if sink_props[k]["multifile"])
uniq_multistep = sum(1 for k in uniq if sink_props[k]["multistep"])
top_sinks = [{"cwe": k[0], "file": k[1], "line": k[2], "paths": n,
              "vuln_class": sink_props[k]["vuln_class"]}
             for k, n in sink_paths.most_common(12)]

# Full source->sink for up to 6 distinct sinks, for manual FP/real judgement.
seen = set()
examples = []
for fl in netnew_flows:
    key = (fl["cwe"], os.path.basename(fl["file"] or ""), fl["line"])
    if key in seen:
        continue
    seen.add(key)
    examples.append({"cwe": fl["cwe"], "vuln_class": fl["vuln_class"],
                     "sink_file": fl["file"], "sink_line": fl["line"],
                     "steps": fl["steps"], "files_spanned": fl["files_spanned"],
                     "path": fl["flow"]})
    if len(examples) >= 6:
        break

out = {
    "repo": name, "lang": lang, "kloc": round(kloc, 1),
    "fast_sast_total": fast["total"],
    "fast_injection_class": len(fast["cwe_locs"]),
    "joern_status": deep["status"],
    "joern_parse_s": deep.get("parse_s"),
    "joern_query_s": deep.get("query_s"),
    "joern_flows_total": len(deep.get("flows", [])),
    "joern_corroborating": corroborating,
    "joern_netnew_paths": netnew,
    "joern_netnew_paths_multifile": netnew_multifile,
    "joern_netnew_paths_multistep": netnew_multistep,
    "joern_netnew_unique_sinks": len(uniq),
    "joern_netnew_unique_multifile": uniq_multifile,
    "joern_netnew_unique_multistep": uniq_multistep,
    "top_sinks": top_sinks,
}
if deep.get("err"):
    out["joern_err"] = deep["err"]
print("DEEP_RESULT_JSON " + json.dumps(out))
# examples are verbose — write them to a side file for inspection.
with open(f"/tmp/examples-{name}.json", "w", encoding="utf-8") as fh:
    json.dump(examples, fh, indent=2)
print(f"EXAMPLES_WRITTEN /tmp/examples-{name}.json ({len(examples)} distinct sinks)")
