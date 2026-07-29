"""B4 Gitleaks precision/recall. Builds a corpus of PLANTED synthetic secrets
(fake-but-valid-format, not real credentials) + realistic DECOYS (placeholders,
hashes, the AWS docs example key that gitleaks allowlists), runs /scan/secrets,
and scores by file prefix: planted_* flagged = TP, planted_* missed = FN,
clean_* flagged = FP, clean_* clean = TN. Runs inside the scanner container."""
import json, os, random, shutil, string, subprocess, urllib.request

random.seed(3)
CORPUS = "/tmp/secretcorpus"


def rnd(alphabet, n):
    return "".join(random.choice(alphabet) for _ in range(n))


UP = string.ascii_uppercase + string.digits
B64 = string.ascii_letters + string.digits + "/+"
ALNUM = string.ascii_letters + string.digits

# label -> (filename, content). Planted secrets are synthetic/random-format.
planted = {
    "aws_access_key": ("planted_aws_akid.py", f'AWS_ACCESS_KEY_ID = "AKIA{rnd(UP,16)}"\n'),
    "aws_secret_key": ("planted_aws_secret.py", f'aws_secret_access_key = "{rnd(B64,40)}"\n'),
    "github_pat": ("planted_ghp.env", f'GITHUB_TOKEN=ghp_{rnd(ALNUM,36)}\n'),
    "gitlab_pat": ("planted_glpat.env", f'GITLAB_TOKEN=glpat-{rnd(ALNUM,20)}\n'),
    "slack_token": ("planted_slack.txt", f'slack_token: xoxb-{rnd(string.digits,12)}-{rnd(string.digits,12)}-{rnd(ALNUM,24)}\n'),
    "stripe_key": ("planted_stripe.js", f'const stripe = "sk_live_{rnd(ALNUM,24)}";\n'),
    "google_api": ("planted_gcp.txt", f'GOOGLE_API_KEY=AIza{rnd(ALNUM+"_-",35)}\n'),
    "npm_token": ("planted_npm.txt", f'//registry.npmjs.org/:_authToken=npm_{rnd(ALNUM,36)}\n'),
    "rsa_private_key": ("planted_rsa.pem",
        "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(rnd(B64, 64) for _ in range(6)) + "\n-----END RSA PRIVATE KEY-----\n"),
    "openssh_private_key": ("planted_ssh",
        "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(rnd(B64, 64) for _ in range(5)) + "\n-----END OPENSSH PRIVATE KEY-----\n"),
    "generic_api_key": ("planted_generic.py", f'api_key = "{rnd(ALNUM,32)}"  # service token\n'),
    "jwt": ("planted_jwt.txt",
        "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + rnd(ALNUM, 40) + "." + rnd(ALNUM, 43) + "\n"),
}

# Decoys that should NOT be flagged (test precision / FP-avoidance).
clean = {
    "aws_docs_example": ("clean_aws_example.py", 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # AWS docs example (allowlisted)\n'),
    "env_lookup": ("clean_env.py", 'password = os.environ.get("DB_PASSWORD")\napi_key = get_secret("api-key")\n'),
    "placeholder": ("clean_placeholder.env", 'API_KEY=your-api-key-here\nTOKEN=<replace-me>\n'),
    "uuid": ("clean_uuid.txt", 'request_id = "550e8400-e29b-41d4-a716-446655440000"\n'),
    "git_sha": ("clean_sha.txt", 'commit = "' + rnd("0123456789abcdef", 40) + '"  # git sha\n'),
    "md5_hash": ("clean_hash.py", 'checksum = "' + rnd("0123456789abcdef", 32) + '"  # md5\n'),
    "base64_text": ("clean_b64.txt", 'greeting = "aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSBzZWNyZXQ="\n'),
    "normal_code": ("clean_code.py", 'def login(user, password):\n    return auth.check(user, password)\n'),
}

shutil.rmtree(CORPUS, ignore_errors=True)
os.makedirs(CORPUS)
for _, (fn, content) in {**planted, **clean}.items():
    with open(os.path.join(CORPUS, fn), "w", encoding="utf-8") as fh:
        fh.write(content)

body = json.dumps({"path": CORPUS, "scan_id": "sec-bench"}).encode()
req = urllib.request.Request("http://localhost:8000/scan/secrets", data=body, method="POST")
req.add_header("Content-Type", "application/json")
with urllib.request.urlopen(req, timeout=600) as r:
    findings = json.loads(r.read()).get("findings") or []

flagged_files = {}
for f in findings:
    fp = os.path.basename(f.get("file_path", ""))
    flagged_files.setdefault(fp, []).append(f.get("rule_id", "?"))

planted_files = {fn for _, (fn, _) in planted.items()}
clean_files = {fn for _, (fn, _) in clean.items()}

TP = sorted(fn for fn in planted_files if fn in flagged_files)
FN = sorted(fn for fn in planted_files if fn not in flagged_files)
FP = sorted(fn for fn in clean_files if fn in flagged_files)
TN = sorted(fn for fn in clean_files if fn not in flagged_files)

print(f"PLANTED={len(planted_files)} CLEAN={len(clean_files)} total findings={len(findings)}")
print(f"TP={len(TP)} FN={len(FN)} FP={len(FP)} TN={len(TN)}")
prec = len(TP) / (len(TP) + len(FP)) if (TP or FP) else 1.0
rec = len(TP) / (len(TP) + len(FN)) if (TP or FN) else 1.0
print(f"PRECISION={prec:.3f}  RECALL={rec:.3f}")
print("\nmissed planted (FN):", FN)
print("false positives (FP):", [(fn, flagged_files[fn]) for fn in FP])
print("\ndetected (TP) with rule:")
for fn in TP:
    print(f"  {fn}: {flagged_files[fn]}")
shutil.rmtree(CORPUS, ignore_errors=True)
