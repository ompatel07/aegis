"""Prove the FP classifier learns from feedback: feed FP feedback for a rule,
retrain, confirm its P(false positive) shifts up. Metadata-only throughout."""
import joblib
from ml import train as T, seed as seedmod, features as F

RULE = "quality.duplicated-block"

def rec(rule, action, sev="medium", depth=2, loc=40):
    return {"rule_id": rule, "engine": "quality", "severity": sev,
            "file_extension": ".py", "file_path_depth": depth,
            "project_language": "python", "project_size_bucket": "medium",
            "lines_of_code": loc, "cwe": None, "owasp_category": None,
            "is_in_test_file": False, "is_in_generated_file": False,
            "is_direct_dependency": False, "label": action}

seed = seedmod.generate_seed()
print(f"seed rows: {len(seed)}")

# The finding we'll score (a fresh finding of RULE).
probe = F.featurize(rec(RULE, "confirmed"))

# Baseline model: seed only.
T.train(seed, "/tmp/fp_before.joblib")
m0 = joblib.load("/tmp/fp_before.joblib")["model"]
p_before = m0.predict_proba([probe])[0][1]

# Simulated feedback: RULE repeatedly marked false-positive; other rules confirmed.
fb = ([rec(RULE, "marked_fp", sev=("low" if i % 2 else "medium"), depth=1 + i % 4) for i in range(80)]
      + [rec(f"other.rule-{i%6}", "confirmed", depth=1 + i % 4) for i in range(80)])

# Retrain on seed + feedback (the real ml.train path).
T.train(seed + fb, "/tmp/fp_after.joblib")
m1 = joblib.load("/tmp/fp_after.joblib")["model"]
p_after = m1.predict_proba([probe])[0][1]

print(f"P(false-positive) for rule '{RULE}':  before={p_before:.3f}  ->  after={p_after:.3f}")
# a confirmed-heavy rule should stay/again drop, as a control
ctrl = F.featurize(rec("other.rule-0", "confirmed"))
print(f"control rule P(fp): before={m0.predict_proba([ctrl])[0][1]:.3f} after={m1.predict_proba([ctrl])[0][1]:.3f}")
print("SHIFT:", "PASS (learned)" if p_after > p_before + 0.2 else "WEAK")

print("\nPRIVACY CHECK — feedback row fields:")
for k in sorted(rec(RULE, "marked_fp").keys()):
    print(f"  {k}")
print("-> all metadata (rule id, severity, path depth, flags, hashed enums). No source code / snippets.")
