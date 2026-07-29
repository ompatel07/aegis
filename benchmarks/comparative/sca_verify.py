"""B3 SCA accuracy: scan dependency-heavy repos with Trivy, then cross-reference a
random sample of flagged advisories against the OSV API (package-precise ground
truth: does this CVE/GHSA actually affect this package@version?). Reports the
verified true-positive rate. Runs inside the scanner container."""
import json, random, subprocess, urllib.request, urllib.error, time

SCANNER = "http://localhost:8000"
random.seed(11)
OSV_ECO = {"javascript": "npm", "typescript": "npm", "npm": "npm", "node-pkg": "npm",
           "python": "PyPI", "pip": "PyPI", "python-pkg": "PyPI",
           "go": "Go", "gomod": "Go", "gobinary": "Go",
           "ruby": "RubyGems", "gem": "RubyGems", "rust": "crates.io", "cargo": "crates.io",
           "php": "Packagist", "composer": "Packagist", "java": "Maven", "maven": "Maven", "jar": "Maven"}

REPOS = [
    ("https://github.com/nextauthjs/next-auth", "main"),   # npm
    ("https://github.com/pallets/flask", "main"),          # PyPI
    ("https://github.com/gin-gonic/gin", "master"),        # Go
]


def scan_sca(path):
    body = json.dumps({"path": path, "scan_id": "sca-v"}).encode()
    req = urllib.request.Request(f"{SCANNER}/scan/sca", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=1200) as r:
        return json.loads(r.read()).get("findings") or []


def osv_query(ecosystem, name, version):
    """Ask OSV which vulns affect this exact package@version. Returns ids+aliases."""
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    req = urllib.request.Request("https://api.osv.dev/v1/query",
                                 data=json.dumps(payload).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    for attempt in range(3):
        ids = set()
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read())
            for v in data.get("vulns", []) or []:
                ids.add(v.get("id", ""))
                for a in v.get("aliases", []) or []:
                    ids.add(a)
            return ids
        except Exception:
            time.sleep(1.5 * (attempt + 1))
    return None


uniq = {}
total = 0
per_eco = {}
for url, br in REPOS:
    d = "/tmp/sca-" + url.rsplit("/", 1)[-1]
    subprocess.run(["rm", "-rf", d])
    subprocess.run(["git", "clone", "--depth", "1", "--branch", br, url, d], capture_output=True)
    fs = scan_sca(d)
    total += len(fs)
    for f in fs:
        m = f.get("metadata") or {}
        cve = f.get("cve_id") or f.get("rule_id")
        pkg, ver = m.get("package"), m.get("installed_version")
        eco = OSV_ECO.get((m.get("reachability_ecosystem") or "").lower())
        if cve and (cve.startswith("CVE") or cve.startswith("GHSA")) and pkg and ver and eco:
            uniq[(cve, pkg, ver)] = eco
            per_eco[eco] = per_eco.get(eco, 0) + 1
    subprocess.run(["rm", "-rf", d])

print(f"total SCA findings={total} unique advisory-with-eco={len(uniq)} per_eco={per_eco}", flush=True)

items = list(uniq.items())
sample = random.sample(items, min(40, len(items)))
confirmed = notfound = osv_err = 0
not_conf = []
print("\n=== OSV cross-reference (sample) ===", flush=True)
for (cve, pkg, ver), eco in sample:
    ids = osv_query(eco, pkg, ver)
    time.sleep(0.3)
    if ids is None:
        osv_err += 1
        continue
    if cve in ids:
        confirmed += 1
    else:
        notfound += 1
        not_conf.append(f"{cve} {pkg}@{ver} [{eco}] (OSV had {len(ids)} other ids)")

checked = confirmed + notfound
print(f"SAMPLE={len(sample)} confirmed={confirmed} not_confirmed={notfound} osv_errors={osv_err}")
if not_conf:
    print("NOT CONFIRMED:")
    for x in not_conf:
        print("  " + x)
if checked:
    print(f"\nOSV-verified true-positive rate = {confirmed}/{checked} = {100*confirmed/checked:.1f}%")
