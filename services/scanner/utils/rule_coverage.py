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

Measured on the N3 rule set (70 Aegis rules + 89 njsscan; N3's 18 unproven rules
are in rules_staging/ and are not counted -- docs/OWASP_CATEGORIES_N3.md):

    javascript   102 rules (taint 13, njsscan 89)    39 CWE classes
    typescript   102 rules (taint 13, njsscan 89)    39 CWE classes   (see _ALSO_RUNS_ON)
    python        13 rules (taint)                   12 CWE classes
    java           9 rules (taint)                   10 CWE classes
    php            9 rules (taint)                   11 CWE classes
    go             8 rules (taint)                    8 CWE classes
    ruby           0 rules                              0
    csharp         0 rules                              0

(N2b: javascript/typescript 100 / 38, python 12 / 10, java 7 / 7, go 7 / 7, php
5 / 5. N3 added 10 rules proven on real code; no tier changed, because no new rule
adds a documented-vulnerability proof -- see STRONG_EVIDENCE.)

(N1/N2 reported javascript 125 / 41 classes and typescript 11 / 9. N2b pruned 25
njsscan rules, three of which had only ever been excluded at run time, and found
TypeScript had been undercounted: semgrep runs javascript rules on .ts.)

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
      documented) and nocodb. The rules each of those proofs rests on are named in
      STRONG_EVIDENCE and tested to still ship.

      Class breadth is NOT part of the claim. N1/N2 said JavaScript "has real class
      breadth (41 CWE classes)". N2b measured it: of the 38 classes left after the
      prune, 11 have a true positive on real code (V2 + F1 corpora; 13 at most), and
      for 23 no rule of ours fired on any of the 20 repositories.
      38 is how many classes we have rules for, not how many we have shown we find.

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

# What a STRONG tier actually rests on (N2b). STRONG is "proven on documented
# vulnerabilities", so it is tied to the shipped rules that produced that proof: the
# ground-truth items each rule catches (F2 / N1 C2 definitions, re-run in N2b). A
# prune that removes one of these must re-measure and re-tier the language;
# tests/test_rule_coverage.py fails until it does. Rule counts and CWE-class counts
# are NOT the test -- N2b showed a count can fall by 25 without the evidence moving,
# and could just as easily stay put while the evidence goes.
STRONG_EVIDENCE: dict[str, dict[str, str]] = {
    "php": {
        "aegis-php-sql-injection": "DVWA sqli + sqli_blind (low.php)",
        "aegis-php-command-injection": "DVWA exec (low.php)",
    },
    "javascript": {
        "aegis-js-code-injection": "NodeGoat GT1 eval (contributions.js:32-34)",
        "aegis-js-nosql-where-injection": "NodeGoat GT2 $where (allocations-dao.js:78)",
        "ajinabraham.njsscan.redirect.open_redirect.express_open_redirect":
            "NodeGoat GT3 open redirect (index.js:72) -- the only rule that catches it",
        "ajinabraham.njsscan.ssrf.ssrf_node.node_ssrf":
            "NodeGoat GT4 SSRF (research.js:15) -- the only rule that catches it",
        "aegis-js-redos-nested-quantifier": "NodeGoat GT7 ReDoS (profile.js:59)",
    },
    "typescript": {
        "aegis-js-sql-injection": "juice-shop login*/union/dbSchema challenges (5)",
        "aegis-js-nosql-injection": "juice-shop noSqlReviews + forgedReview challenges",
    },
}

# Semgrep applies a rule to more languages than it declares: a `languages:
# [javascript]` rule also runs on .ts/.tsx (measured on semgrep 1.97.0 in N2b; a
# `[typescript]` rule does NOT run on .js). Coverage counts what runs, so a
# javascript-only rule is counted for typescript too. Before N2b this was missed and
# TypeScript was reported as 11 rules while all 114 njsscan rules ran on it.
_ALSO_RUNS_ON = {"javascript": ("typescript",)}

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
        if not counts_as_coverage(rule):
            continue
        found = {m.group(0).upper() for m in _CWE.finditer(str(meta.get("cwe", "")))}
        for lang in applies_to(rule):
            cov = out.setdefault(lang, LanguageCoverage(language=lang, tier=TIER_NONE, rules=0))
            cov.rules += 1
            cov.families[family] = cov.families.get(family, 0) + 1
            cwes.setdefault(lang, set()).update(found)
    for lang, cov in out.items():
        cov.cwe_classes = len(cwes.get(lang, ()))
        cov.tier = tier_of(lang)
    return out


# N4 three-tier staging policy. A shipped rule is either PROVEN (fired on real code,
# 0 FP after triage) or SILENT-CLEAN: API-shaped, fixtures pass, ran on the whole
# measured corpus with 0 FP, but never fired -- so its recall is unvalidated. A
# silent-clean rule runs and its findings are labelled, but it is NOT coverage: it
# does not count toward a language's rules, CWE classes, tier evidence or any claim.
# (STAGED rules live in rules_staging/ and never run.)
SILENT_CLEAN = "silent-clean"


def validation_of(rule: dict) -> str:
    return str((rule.get("metadata") or {}).get("aegis-validation") or "proven")


def counts_as_coverage(rule: dict) -> bool:
    """Quality-pillar rules and silent-clean rules are not security coverage."""
    meta = rule.get("metadata") or {}
    return meta.get("pillar") != "quality" and validation_of(rule) != SILENT_CLEAN


def silent_clean_rule_ids() -> set[str]:
    return {str(r.get("id")) for _f, r in _iter_rule_docs() if validation_of(r) == SILENT_CLEAN}


def applies_to(rule: dict) -> list[str]:
    """The languages semgrep will run `rule` on: its declared languages plus the
    ones semgrep extends them to (`_ALSO_RUNS_ON`), each once."""
    out: list[str] = []
    for lang in rule.get("languages") or []:
        for l in (str(lang).lower(), *_ALSO_RUNS_ON.get(str(lang).lower(), ())):
            if l not in out:
                out.append(l)
    return out


def shipped_rule_languages() -> dict[str, set[str]]:
    """rule id -> languages it runs on, for every shipped security rule."""
    out: dict[str, set[str]] = {}
    for _family, rule in _iter_rule_docs():
        if not counts_as_coverage(rule):
            continue
        out.setdefault(str(rule.get("id")), set()).update(applies_to(rule))
    return out


def tier_evidence_gaps(shipped: dict[str, set[str]] | None = None) -> list[str]:
    """STRONG tiers whose evidence rules are no longer shipped for that language.
    Empty means every STRONG tier still has the rules it was proven with."""
    shipped = shipped_rule_languages() if shipped is None else shipped
    gaps = []
    for lang, rules in STRONG_EVIDENCE.items():
        for rule_id, proves in rules.items():
            if lang not in shipped.get(rule_id, ()):
                gaps.append(f"{lang} is STRONG on '{proves}', but {rule_id} no longer ships "
                            f"for {lang}: re-measure the ground truth and re-tier {lang}")
    return gaps


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
