"""B-IaC verification: run Trivy (SCA/misconfig) + Semgrep (compose) on the IaC
corpus, check tagging, example-dir skipping, recall on planted misconfigs, and FP
on the hardened good files. Runs inside the scanner container."""
import json, os, subprocess, urllib.request

SC = "http://localhost:8000"
subprocess.run(["bash", "/tmp/iac_corpus.sh"], capture_output=True)
# plant a BAD terraform inside an examples/ dir to prove it is skipped
os.makedirs("/tmp/iac/examples", exist_ok=True)
open("/tmp/iac/examples/bad.tf", "w").write(
    'resource "aws_db_instance" "x" { storage_encrypted = false\n publicly_accessible = true }\n')
# good compose file
open("/tmp/iac/good/docker-compose.yml", "w").write(
    'version: "3"\nservices:\n  web:\n    image: nginx:1.27\n    read_only: true\n    cap_drop: ["ALL"]\n    ports:\n      - "127.0.0.1:8080:80"\n')


def scan(ep, langs=None):
    body = {"path": "/tmp/iac", "scan_id": "iac"}
    if langs:
        body["languages"] = langs
    b = json.dumps(body).encode()
    r = urllib.request.Request(f"{SC}/scan/{ep}", data=b, method="POST")
    r.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(r, timeout=600) as x:
        return json.loads(x.read()).get("findings") or []


trivy = [f for f in scan("sca") if (f.get("metadata") or {}).get("category") == "iac-misconfiguration"]
compose = [f for f in scan("sast", ["yaml"]) if (f.get("metadata") or {}).get("category") == "iac-misconfiguration"]
iac = trivy + compose


def rel(f):
    return f.get("file_path", "").replace("/tmp/iac/", "")


by_file = {}
for f in iac:
    by_file.setdefault(rel(f), []).append(f)

print("=== IaC findings per file (engine tags category=iac-misconfiguration) ===")
for fpath in sorted(by_file):
    kinds = {(f.get("metadata") or {}).get("iac_type") or "?" for f in by_file[fpath]}
    print(f"  {fpath:28} {len(by_file[fpath]):3} findings  types={kinds}")

# example-dir skip
leaked = [fpath for fpath in by_file if fpath.startswith("examples/")]
print(f"\nexample-dir skip: findings under examples/ = {len(leaked)} (want 0) {leaked}")

# RECALL: each planted bad config type should be caught (keyword in any finding on that file)
def caught(fpath, *kw):
    blob = " ".join((f.get("title", "") + " " + (f.get("description") or "")).lower() for f in by_file.get(fpath, []))
    return all(any(k in blob for k in group) for group in kw)

checks = {
    "Dockerfile: latest tag":       caught("bad/Dockerfile", ("latest",)),
    "Dockerfile: root/USER":        caught("bad/Dockerfile", ("root", "user")),
    "Terraform: unencrypted/public": caught("bad/main.tf", ("encrypt", "public")),
    "Terraform: open security group": caught("bad/main.tf", ("0.0.0.0", "ingress", "public", "cidr")),
    "K8s: privileged":              caught("bad/deploy.yaml", ("privileg",)),
    "K8s: hostPath/host":           caught("bad/deploy.yaml", ("host",)),
    "Compose: privileged":          caught("bad/docker-compose.yml", ("privileg",)),
    "Compose: exposed 0.0.0.0 port": caught("bad/docker-compose.yml", ("0.0.0.0", "port", "interface")),
    "Compose: SYS_ADMIN capability": caught("bad/docker-compose.yml", ("capab", "sys_admin", "privilege")),
}
print("\n=== RECALL on planted misconfigs ===")
rec = 0
for name, ok in checks.items():
    print(f"  [{'CAUGHT' if ok else 'MISSED'}] {name}")
    rec += ok
print(f"recall: {rec}/{len(checks)} = {100*rec/len(checks):.0f}%")

# FP: good files should have no HIGH/CRITICAL misconfig (low-sev defense-in-depth allowed)
good_hi = [f for f in iac if rel(f).startswith("good/") and f.get("severity") in ("high", "critical")]
print(f"\n=== FP on hardened good files: {len(good_hi)} high/critical (want 0) ===")
for f in good_hi:
    print("  ", rel(f), f.get("severity"), f.get("title")[:70])
