"""(Copied from the out-of-repo working dir E:/n4work; paths refer to it.)
VulnerableApp ground truth from its own annotations: every @AttackVector on a level
method names the VulnerabilityType(s) it exposes. Map each finding to the level method
it falls inside. Runs in a scanner-image container with /workspaces and /n4."""
import glob
import json
import re

ROOT = "/workspaces/_n4/SasanLabs__VulnerableApp/src/main/java"
items = []
for path in glob.glob(f"{ROOT}/**/*.java", recursive=True):
    src = open(path, encoding="utf-8", errors="ignore").read()
    lines = src.splitlines()
    for m in re.finditer(r"@AttackVector\s*\((.*?)\)\s*(?=@|\s*public|\s*private|\s*protected)", src, re.S):
        body = m.group(1)
        types = re.findall(r"VulnerabilityType\.(\w+)", body)
        start = src.count("\n", 0, m.start()) + 1
        # the annotated method: first "public|private ... name(" after the annotation block
        mm = re.search(r"(public|private|protected)[^;{=]*?\s(\w+)\s*\(", src[m.end():])
        if not mm:
            continue
        mline = src.count("\n", 0, m.end() + mm.start()) + 1
        # method end: brace matching from the first "{" after the signature
        i = src.index("{", m.end() + mm.end())
        depth, j = 0, i
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        end = src.count("\n", 0, j) + 1
        secure = "Variant.SECURE" in src[m.end(): m.end() + mm.start()]
        items.append({"file": path.replace(ROOT.rsplit("/src", 1)[0] + "/", ""), "method": mm.group(2),
                      "start": mline, "end": end, "types": types, "secure": secure})
fs = json.load(open("/n4/scans/vulnerableapp.json"))["findings"]
for it in items:
    it["hits"] = sorted({f["rule"] for f in fs if f["file"] == it["file"] and it["start"] <= f["line"] <= it["end"]})
json.dump(items, open("/n4/vulnapp_items.json", "w"), indent=1)
by = {}
for it in items:
    for t in it["types"]:
        by.setdefault(t, []).append(it)
print(len(items), "annotated level methods;", sum(1 for i in items if i["secure"]), "marked SECURE")
for t, its in sorted(by.items()):
    hit = [i for i in its if i["hits"]]
    print(f"  {t:42s} levels={len(its):2d} hit={len(hit):2d}  {sorted({r for i in hit for r in i['hits']})}")
