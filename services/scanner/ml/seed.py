"""Cold-start seed dataset for the false-positive classifier.

We cannot ship 500 literally hand-labelled findings, so this generates a
~500-row seed whose labels follow the well-known empirical priors that make
findings false positives — all expressed over METADATA ONLY (no code):

  * findings in test / generated files are very often noise
  * transitive-dependency CVEs are ignored far more than direct ones
  * low-severity style smells (magic numbers, tech-debt) are frequently dismissed
  * critical taint in first-party source is almost always a true positive

This is an honest cold-start prior, not curated ground truth; it is replaced by
real user feedback as it accumulates (source='feedback'). Deterministic (seeded)
so the baseline model is reproducible.
"""
from __future__ import annotations

import random

# (engine, rule_id, severity, ext, language, cwe, owasp, base_fp_rate)
_PROFILES = [
    ("semgrep", "aegis-js-sql-injection", "critical", ".js", "javascript", "CWE-89", "A03:2021 - Injection", 0.06),
    ("semgrep", "aegis-py-command-injection", "critical", ".py", "python", "CWE-78", "A03:2021 - Injection", 0.08),
    ("semgrep", "aegis-js-xss", "high", ".js", "javascript", "CWE-79", "A03:2021 - Injection", 0.12),
    ("semgrep", "javascript.express.security.audit.xss", "high", ".js", "javascript", "CWE-79", None, 0.28),
    ("semgrep", "generic.secrets.security.detected-generic-secret", "high", ".js", "javascript", "CWE-798", None, 0.35),
    ("trivy", "CVE-2020-8203", "high", "", "javascript", "CWE-1321", "A06:2021 - Vulnerable and Outdated Components", 0.30),
    ("trivy", "CVE-2019-10744", "critical", "", "javascript", "CWE-1321", "A06:2021 - Vulnerable and Outdated Components", 0.20),
    ("gitleaks", "aws-access-token", "critical", ".env", "javascript", None, None, 0.15),
    ("gitleaks", "generic-api-key", "high", ".js", "javascript", None, None, 0.40),
    ("quality", "quality/magic-numbers", "low", ".js", "javascript", None, None, 0.62),
    ("quality", "quality/duplicated-code", "low", ".js", "javascript", None, None, 0.45),
    ("quality", "quality/tech-debt-marker", "informational", ".js", "javascript", None, None, 0.70),
    ("quality", "quality/high-cyclomatic-complexity", "medium", ".py", "python", None, None, 0.33),
    ("joern", "joern/sql-injection", "critical", ".java", "java", "CWE-89", "A03:2021 - Injection", 0.10),
]

_LANG_SIZE = [("javascript", "medium"), ("python", "small"), ("go", "large"), ("java", "large")]


def generate_seed(n: int = 500, rng_seed: int = 1337) -> list[dict]:
    rng = random.Random(rng_seed)
    rows: list[dict] = []
    for _ in range(n):
        engine, rule, sev, ext, lang, cwe, owasp, base_fp = rng.choice(_PROFILES)
        in_test = rng.random() < 0.22
        in_generated = (not in_test) and rng.random() < 0.10
        # SCA (trivy) records dependency directness; others: n/a -> False.
        is_direct = rng.random() < 0.5 if engine == "trivy" else False

        fp = base_fp
        if in_test:
            fp = min(0.92, fp + 0.5)          # test-file findings are mostly noise
        if in_generated:
            fp = min(0.95, fp + 0.55)         # generated code even more so
        if engine == "trivy" and not is_direct:
            fp = min(0.9, fp + 0.25)          # transitive CVEs ignored more often
        if engine == "trivy" and is_direct:
            fp = max(0.03, fp - 0.15)

        # FP-ness is largely determined by these metadata priors (a finding in a
        # test file really is usually noise), with ~8% label noise to stay honest
        # about real-world disagreement.
        is_fp = fp >= 0.5
        if rng.random() < 0.08:
            is_fp = not is_fp
        if is_fp:
            action = rng.choice(["marked_fp", "suppressed", "ignored"])
        else:
            action = rng.choice(["confirmed", "fixed"])

        depth = rng.randint(1, 6) + (2 if in_test else 0)
        loc = rng.randint(20, 600)

        rows.append({
            "source": "seed",
            "rule_id": rule, "engine": engine, "severity": sev,
            "file_extension": ext, "file_path_depth": depth,
            "project_language": lang,
            "project_size_bucket": dict(_LANG_SIZE).get(lang, "medium"),
            "lines_of_code": loc, "cwe": cwe, "owasp_category": owasp,
            "is_in_test_file": in_test, "is_in_generated_file": in_generated,
            "is_direct_dependency": is_direct,
            "label": action,
        })
    return rows
