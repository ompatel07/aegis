"""B5 Quality-engine accuracy. Generates code with HAND-COMPUTED cyclomatic
complexity, parameter counts, and a known duplicated block, runs /scan/quality,
and checks the engine's reported numbers match the ground truth exactly.
McCabe CC = (number of decision points) + 1; each sequential `if` adds 1."""
import json, os, shutil, urllib.request

CORPUS = "/tmp/qualcorpus"
shutil.rmtree(CORPUS, ignore_errors=True)
os.makedirs(CORPUS)


def fn_with_ifs(name, n_ifs, params="x"):
    # n_ifs sequential ifs -> CC = n_ifs + 1 (McCabe)
    body = "".join(f"    if {params.split(',')[0]} == {i}:\n        r += {i}\n" for i in range(n_ifs))
    return f"def {name}({params}):\n    r = 0\n{body}    return r\n\n"


# EXPECTED cyclomatic complexity per function (hand-computed = n_ifs + 1)
expected_cc = {"simple": 1, "moderate": 13, "very_complex": 25}
src = fn_with_ifs("simple", 0) + fn_with_ifs("moderate", 12) + fn_with_ifs("very_complex", 24)
# a 7-parameter function (threshold is >=6)
src += "def many_params(a, b, c, d, e, f, g):\n    return a + b + c + d + e + f + g\n"
with open(os.path.join(CORPUS, "complexity_test.py"), "w") as fh:
    fh.write(src)

# Duplicated block: two functions with an identical ~30-statement body (Type-2
# clone — even the var name differs, so it tests token-normalized detection).
block = lambda var: "".join(f"    {var}_{i} = compute({i}) + transform({i} * 2) - offset({i})\n" for i in range(30))
dup = (f"def alpha(data):\n    total = 0\n{block('a')}    return total\n\n"
       f"def beta(payload):\n    total = 0\n{block('b')}    return total\n")
with open(os.path.join(CORPUS, "dup_test.py"), "w") as fh:
    fh.write(dup)

body = json.dumps({"path": CORPUS, "scan_id": "qual-bench", "languages": ["python"]}).encode()
req = urllib.request.Request("http://localhost:8000/scan/quality", data=body, method="POST")
req.add_header("Content-Type", "application/json")
with urllib.request.urlopen(req, timeout=600) as r:
    findings = json.loads(r.read()).get("findings") or []

cc_found, param_found, clone_found = {}, {}, []
for f in findings:
    rid = f.get("rule_id", "")
    md = f.get("metadata") or {}
    title = f.get("title", "")
    if rid == "quality/high-cyclomatic-complexity":
        # function name is in the title: Function 'NAME' has cyclomatic complexity N
        name = title.split("'")[1] if "'" in title else "?"
        cc_found[name] = md.get("complexity")
    elif rid == "quality/too-many-parameters":
        name = title.split("'")[1] if "'" in title else "?"
        param_found[name] = md.get("parameter_count")
    elif "duplicat" in rid or "clone" in rid:
        clone_found.append({"tokens": md.get("tokens"), "lines": md.get("lines"),
                            "file": f.get("file_path"), "sev": f.get("severity")})

print("=== Cyclomatic complexity (reported vs hand-computed) ===")
ok = True
for name, exp in expected_cc.items():
    rep = cc_found.get(name)
    flagged_expected = exp >= 11
    if flagged_expected:
        match = rep == exp
        ok &= match
        print(f"  {name:14} expected CC={exp:3} reported={rep} {'MATCH' if match else 'MISMATCH'}")
    else:
        # should NOT be flagged (below threshold 11)
        not_flagged = name not in cc_found
        ok &= not_flagged
        print(f"  {name:14} expected CC={exp:3} (below 11) -> {'correctly not flagged' if not_flagged else 'WRONGLY FLAGGED '+str(rep)}")

print("\n=== Parameter count ===")
pc = param_found.get("many_params")
print(f"  many_params expected 7 params reported={pc} {'MATCH' if pc == 7 else 'MISMATCH'}")
ok &= (pc == 7)

print("\n=== Duplication (Type-2 clone) ===")
if clone_found:
    for c in clone_found:
        print(f"  clone detected: tokens={c['tokens']} lines={c['lines']} sev={c['sev']} in {c['file']}")
    print("  -> duplicated block correctly detected")
else:
    print("  NO CLONE DETECTED (expected the alpha/beta duplicate)")
    ok = False

print("\nOVERALL:", "ALL METRICS CORRECT" if ok else "SOME MISMATCH")
shutil.rmtree(CORPUS, ignore_errors=True)
