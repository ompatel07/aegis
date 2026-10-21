"""Per-language SAST coverage, measured from the rule set we actually ship (N2).

WHY THIS EXISTS
---------------
After N1 removed the Semgrep-licensed packs, a repository written in a language we
barely cover produces few findings — and few findings read as "clean". A Java-only
repository could score Security 100 / grade A because we have seven Java rules, not
because the code is safe. That is the fabricated-clean-score defect this codebase has
now shipped five times (constant-A reliability, `return 100` deployment, a fabricated
60% coverage, compliance controls reading "passing" while unassessed, and D1's
"partial coverage still scores").

So coverage is measured, surfaced, and allowed to withdraw the score.

HOW COVERAGE IS MEASURED
------------------------
`rule_index()` reads every rule Aegis ships (services/scanner/rules/**) and records,
per language semgrep would apply it to: the rule count, the rule families, and the
distinct CWE classes. Nothing here is declared — it is counted from the files, so it
moves when the rule set moves, and `tests/test_rule_coverage.py` fails if the tier
table and the measured rule set disagree.

Measured on the N1 rule set (60 Aegis rules + 114 njsscan):

    javascript   125 rules (taint 11, njsscan 114)   41 CWE classes
    python        12 rules (taint)                   10 CWE classes
    typescript    11 rules (taint)                    9 CWE classes
    java           7 rules (taint)                     7 CWE classes
    go             7 rules (taint)                     7 CWE classes
    php            5 rules (taint)                     5 CWE classes
    ruby           0 rules                              0
    csharp         0 rules                              0

WHERE THE TIERS COME FROM
-------------------------
The brief for this pass asked that tiers be grounded in the N1 per-language table
(`docs/RULE_REMOVAL_N1.md` §C.3, `docs/ACCURACY.md` "Per-language SAST"), which was
measured before and after the cut on 15 real repositories plus five
documented-vulnerability corpora. They are:

  STRONG  php, javascript, typescript
      Our taint packs are proven to fire on the vulnerability classes they target,
      across MORE THAN ONE real repository: PHP on DVWA (3/6 documented, +31 findings),
      librenms and FreshRSS; JS on NodeGoat (5/7 documented); TS on juice-shop (7/25
      documented) and nocodb. JavaScript additionally has real class breadth (41 CWE
      classes) because njsscan covers crypto, cookies, headers and DoS on top of taint.

  LIMITED java, python, go
      Rules exist and fire, but only for the injection/taint families, and the
      evidence is thinner: Java 6/6 on WebGoat but inert on every Java repository
      before T3 and 10% of pre-cut finding volume retained; Python 24% retained, H1's
      four pattern rules 17/17 TP; Go has no measured yield on real code at all —
      V2 contained no Go repository.

  NONE    everything else (ruby, csharp, c, cpp, rust, kotlin, scala, …)
      Zero shipped security rules. We do no application-code SAST on these at all.

**"Strong" means proven, not broad.** PHP is five rules covering five CWE classes: a
PHP repository with no findings may still hold deserialisation, XXE, SSRF or
file-upload flaws we have no rule for. The tier says our rules work where they aim,
not that they aim everywhere. That limit is stated on the report rather than hidden.

THE CONFIDENCE THRESHOLD
------------------------
The security score is confidently measured only when **more than half the repository's
code, by LOC, is in STRONG-covered languages** (`CONFIDENT_STRONG_FRACTION`).

Why a simple majority of strong, rather than a weighted blend: the question the score
answers is "did we look hard at this code?", and a blend lets a thinly-covered
majority hide behind a well-covered minority — exactly the inflation being fixed. Why
LOC rather than file count: one 5,000-line Java service and fifty one-line JS config
files are not equal halves of a repository.

A repository that fails the threshold does not get a different, softer score. It
reuses the contract P4b/C1 already established: semgrep reports DEGRADED with the gap
named, the security score and rating become NULL ("Not measured"), and the overall
renormalises and renders as PARTIAL with a mandatory qualifier. No new state.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# Fraction of code (by LOC) that must be in STRONG-covered languages for the security
# score to be presented as confidently measured. See module docstring.
CONFIDENT_STRONG_FRACTION = 0.5

# Tier per language. Grounded in the N1 per-language measurement (module docstring).
# `tests/test_rule_coverage.py` asserts these against the shipped rule set: a language
# named here must have rules, and a language with rules must be named here.
STRONG = ("php", "javascript", "typescript")
LIMITED = ("java", "python", "go")

TIER_NONE = "none"
TIER_LIMITED = "limited"
TIER_STRONG = "strong"

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")
_CWE = re.compile(r"CWE-\d+", re.IGNORECASE)

# Languages that carry no application code of their own: a repository is not "covered"
# or "uncovered" on account of its YAML. Our cicd/iac rules do run on them, which is
# reported separately (`always_on`), but they are excluded from the LOC fractions so a
# Kubernetes-heavy Java repo cannot look well covered because we read its manifests.
_NON_APPLICATION = ("yaml", "json", "generic", "regex", "dockerfile", "hcl", "terraform")


@dataclass
class LanguageCoverage:
    language: str
    tier: str
    rules: int
    families: dict[str, int] = field(default_factory=dict)
    cwe_classes: int = 0

    def as_dict(self) -> dict:
        return {"language": self.language, "tier": self.tier, "rules": self.rules,
                "families": self.families, "cwe_classes": self.cwe_classes}


def _iter_rule_docs():
    import yaml

    for dirpath, _dirs, files in os.walk(_RULES_DIR):
        for name in sorted(files):
            if not name.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh)
            except (OSError, yaml.YAMLError):
                continue
            if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
                continue  # manifest.yaml and friends are not rule files
            family = os.path.basename(dirpath)
            for rule in doc["rules"]:
                if isinstance(rule, dict):
                    yield family, rule


def rule_index() -> dict[str, LanguageCoverage]:
    """Security rules per language, counted from the shipped rule files.

    Quality-pillar rules (`metadata.pillar: quality`) are excluded: the reliability
    bug pack does not tell a customer whether we can find their vulnerabilities.
    """
    out: dict[str, LanguageCoverage] = {}
    cwes: dict[str, set[str]] = {}
    for family, rule in _iter_rule_docs():
        meta = rule.get("metadata") or {}
        if meta.get("pillar") == "quality":
            continue
        found = {m.group(0).upper() for m in _CWE.finditer(str(meta.get("cwe", "")))}
        for lang in rule.get("languages") or []:
            lang = str(lang).lower()
            cov = out.setdefault(lang, LanguageCoverage(language=lang, tier=TIER_NONE, rules=0))
            cov.rules += 1
            cov.families[family] = cov.families.get(family, 0) + 1
            cwes.setdefault(lang, set()).update(found)
    for lang, cov in out.items():
        cov.cwe_classes = len(cwes.get(lang, ()))
        cov.tier = tier_of(lang)
    return out


def tier_of(language: str) -> str:
    lang = (language or "").lower()
    if lang in STRONG:
        return TIER_STRONG
    if lang in LIMITED:
        return TIER_LIMITED
    return TIER_NONE


def summarise(language_loc: dict[str, int], unreadable: dict[str, int] | None = None) -> dict | None:
    """Coverage for one scan, from its per-language LOC.

    Returns None when there is no application code to describe (an empty repo, or one
    that is entirely YAML/config) — absent is honest there; a 0% coverage figure on a
    repo with no code would read as a gap that does not exist.
    """
    app = {l: n for l, n in (language_loc or {}).items()
           if n > 0 and l.lower() not in _NON_APPLICATION}
    total = sum(app.values())
    if total <= 0:
        return None

    index = rule_index()
    by_tier: dict[str, int] = {TIER_STRONG: 0, TIER_LIMITED: 0, TIER_NONE: 0}
    langs = []
    for lang, loc in sorted(app.items(), key=lambda kv: -kv[1]):
        tier = tier_of(lang)
        by_tier[tier] += loc
        cov = index.get(lang)
        langs.append({"language": lang, "tier": tier, "loc": loc,
                      "share": round(loc / total, 4),
                      "rules": cov.rules if cov else 0,
                      "cwe_classes": cov.cwe_classes if cov else 0})

    strong_fraction = by_tier[TIER_STRONG] / total
    confident = strong_fraction > CONFIDENT_STRONG_FRACTION
    return {
        "total_code_lines": total,
        "strong_fraction": round(strong_fraction, 4),
        "limited_fraction": round(by_tier[TIER_LIMITED] / total, 4),
        "uncovered_fraction": round(by_tier[TIER_NONE] / total, 4),
        "confident": confident,
        "threshold": CONFIDENT_STRONG_FRACTION,
        "languages": langs,
        "summary": headline(langs),
        "gap": None if confident else gap_sentence(langs),
        # The always-on, language-independent rules. Stated so a Ruby or C# repo is not
        # described as having had nothing run against it at all.
        "always_on": ["dependency CVEs (trivy)", "secrets (gitleaks)",
                      "IaC misconfiguration (trivy + aegis-compose-*)",
                      "CI/CD pipeline (aegis-cicd-*)"],
        # Source files whose lines could not be counted. Stated rather than treated
        # as empty: an unreadable file is not zero lines of a language.
        "unreadable_files": sum((unreadable or {}).values()) or None,
    }


_TIER_WORD = {TIER_STRONG: "strong", TIER_LIMITED: "limited", TIER_NONE: "none"}
_DISPLAY = {"javascript": "JS", "typescript": "TS", "csharp": "C#", "php": "PHP",
            "cpp": "C++", "c": "C", "java": "Java", "python": "Python", "go": "Go",
            "ruby": "Ruby", "rust": "Rust", "kotlin": "Kotlin", "scala": "Scala"}


def display_name(language: str) -> str:
    return _DISPLAY.get((language or "").lower(), (language or "").title())


def headline(langs: list[dict], limit: int = 4) -> str:
    """e.g. "PHP strong; Java limited; Ruby none" -- what a customer is getting."""
    parts = [f"{display_name(l['language'])} {_TIER_WORD[l['tier']]}"
             for l in langs[:limit] if l["share"] >= 0.01]
    if not parts:
        return "no application code detected"
    extra = len([l for l in langs if l["share"] >= 0.01]) - len(parts)
    return "; ".join(parts) + (f"; +{extra} more" if extra > 0 else "")


def gap_sentence(langs: list[dict]) -> str:
    """Why the security score is not confidently measured, naming the languages."""
    thin = [l for l in langs if l["tier"] != TIER_STRONG and l["share"] >= 0.05]
    thin.sort(key=lambda l: -l["share"])
    named = ", ".join(
        f"{display_name(l['language'])} {round(l['share'] * 100)}%"
        f"{' (no rules)' if l['tier'] == TIER_NONE else f' ({l['rules']} rules)'}"
        for l in thin[:3]
    )
    return (f"most of this repository is in languages Aegis covers thinly or not at all "
            f"({named}), so an absence of findings is not evidence of safety")
