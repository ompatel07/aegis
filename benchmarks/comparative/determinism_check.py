"""Phase 2F Pass 1 — determinism. Clone each repo ONCE (fixed source bytes), scan
that same directory N times via /scan/sast, and confirm every run yields an
IDENTICAL finding set: rule id, file, line, severity, CWE, the ML false-positive
probability, and the steps-to-reproduce source/sink/flow. Order is ignored (sorted
before hashing); the SET and every per-finding field must match. Runs in-container."""
import hashlib, json, os, subprocess, sys, urllib.request

SC = "http://localhost:8000"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 10
# name, lang, url  (cloned once; the resolved SHA is recorded)
REPOS = [
    ("express", "javascript", "https://github.com/expressjs/express"),
    ("flask", "python", "https://github.com/pallets/flask"),
    ("django", "python", "https://github.com/django/django"),
]


def scan(path, lang):
    b = json.dumps({"path": path, "scan_id": "det", "languages": [lang]}).encode()
    r = urllib.request.Request(f"{SC}/scan/sast", data=b, method="POST")
    r.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(r, timeout=1800) as x:
        return json.loads(x.read()).get("findings") or []


def canon(findings):
    """Canonical, order-independent representation of a finding set."""
    rows = []
    for f in findings:
        sor = (f.get("context_metadata") or {}).get("steps_to_reproduce")
        sor_key = ""
        if sor:
            s, k = sor.get("source", {}), sor.get("sink", {})
            flow = "|".join(f"{n.get('file')}:{n.get('line')}:{n.get('code')}" for n in sor.get("flow", []))
            sor_key = f"SRC({s.get('file')}:{s.get('line')}:{s.get('code')})>{flow}>SNK({k.get('file')}:{k.get('line')}:{k.get('code')})"
        rows.append("".join([
            str(f.get("rule_id")), str(f.get("file_path")), str(f.get("line_start")),
            str(f.get("severity")), str(f.get("cwe_id")),
            f"{f.get('false_positive_probability')!r}", sor_key,
        ]))
    rows.sort()
    return rows


for name, lang, url in REPOS:
    d = f"/tmp/det-{name}"
    if not os.path.isdir(d):
        subprocess.run(["git", "clone", "--depth", "1", url, d], capture_output=True)
    sha = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()[:12]
    print(f"\n==== {name} @ {sha}  (scanning {N}x) ====", flush=True)
    hashes, counts, first_rows = [], [], None
    for i in range(N):
        rows = canon(scan(d, lang))
        h = hashlib.sha256("\n".join(rows).encode()).hexdigest()[:16]
        hashes.append(h)
        counts.append(len(rows))
        if first_rows is None:
            first_rows = rows
        elif rows != first_rows:
            # show the first differing line for diagnosis
            sa, sb = set(first_rows), set(rows)
            only1 = list(sa - sb)[:3]
            only2 = list(sb - sa)[:3]
            print(f"  run {i+1}: DIFFERS. only-in-run1={only1} only-in-run{i+1}={only2}", flush=True)
        print(f"  run {i+1:2}: count={len(rows):4} hash={h}", flush=True)
    ident = len(set(hashes)) == 1 and len(set(counts)) == 1
    print(f"  RESULT: {'DETERMINISTIC (all %d runs identical)' % N if ident else 'NON-DETERMINISTIC'} "
          f"| distinct hashes={len(set(hashes))} counts={sorted(set(counts))}", flush=True)
