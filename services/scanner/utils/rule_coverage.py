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

Measured on the N5 rule set (81 Aegis rules + 89 njsscan; 6 SILENT-CLEAN rules run but
are not counted, 9 STAGED rules do not run -- docs/GROUND_TRUTH_N5.md). The tier column
is not declared here; it is what utils/tier_bar.py computes from accuracy/:

    javascript   102 rules (taint 13, njsscan 89)    39 CWE classes   limited
    typescript   102 rules (taint 13, njsscan 89)    39 CWE classes   limited  (_ALSO_RUNS_ON)
    python        15 rules (taint)                   15 CWE classes   limited
    java          10 rules (taint)                   11 CWE classes   limited
    go            10 rules (taint)                   12 CWE classes   limited
    php            9 rules (taint)                   11 CWE classes   limited
    ruby           0 rules                              0             none
    csharp         0 rules                              0             none

(N4 declared php, javascript, typescript, java and python STRONG. Under the N5 bar each
fails at least one criterion; the failing criteria travel with the tier.)

WHERE THE TIERS COME FROM
-------------------------
Nowhere in this file. Since N5 a tier is COMPUTED (utils/tier_bar.py) from the
measured evidence that ships in the image, accuracy/gt_items.json (every documented
vulnerability of every qualifying ground-truth corpus) and accuracy/triage.json (every
hand-triaged finding of a shipped rule). A language is STRONG only if its shipped rules
caught documented vulnerabilities in >= 2 corpora, its HELD-OUT recall is >= 25%, and
their precision over every triaged finding is >= 70%. Any language with rules that
fails a criterion is LIMITED, and the failing criterion is carried with the tier.
Languages with zero shipped security rules are NONE.

The coverage line carries the measured recall next to every language, so a tier name
cannot hide 15% against 50% (docs/GROUND_TRUTH_N5.md).

**"Strong" means proven, not broad.** A STRONG language's rules work where they aim on
code nobody tuned them on. It does not mean they aim everywhere: PHP's rules cover a
handful of CWE classes, and the misses per corpus are listed in gt_items.json.

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

import functools
import os
import re
from dataclasses import dataclass, field

from utils import tier_bar

# Fraction of code (by LOC) that must be in STRONG-covered languages for the security
# score to be presented as confidently measured. See module docstring.
CONFIDENT_STRONG_FRACTION = 0.5

# Semgrep applies a rule to more languages than it declares: a `languages:
# [javascript]` rule also runs on .ts/.tsx (measured on semgrep 1.97.0 in N2b; a
# `[typescript]` rule does NOT run on .js). Coverage counts what runs, so a
# javascript-only rule is counted for typescript too. Before N2b this was missed and
# TypeScript was reported as 11 rules while all 114 njsscan rules ran on it.
_ALSO_RUNS_ON = {"javascript": ("typescript",)}

TIER_NONE, TIER_LIMITED, TIER_STRONG = tier_bar.TIER_NONE, tier_bar.TIER_LIMITED, tier_bar.TIER_STRONG

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


@functools.lru_cache(maxsize=1)
def measured_tiers() -> dict[str, tier_bar.LanguageEvidence]:
    """Every language with shipped security rules, tiered by the N5 bar from the
    evidence in accuracy/. Nothing here is declared."""
    shipped = shipped_rule_languages()
    langs = {l for ls in shipped.values() for l in ls if l not in _NON_APPLICATION}
    gt, triage = tier_bar.ledger()
    return tier_bar.evaluate(gt, triage, shipped, langs)


def tier_of(language: str) -> str:
    ev = measured_tiers().get((language or "").lower())
    return ev.tier if ev else TIER_NONE


def evidence_of(language: str) -> tier_bar.LanguageEvidence | None:
    return measured_tiers().get((language or "").lower())


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
        ev = evidence_of(lang)
        langs.append({"language": lang, "tier": tier, "loc": loc,
                      "share": round(loc / total, 4),
                      "rules": cov.rules if cov else 0,
                      "cwe_classes": cov.cwe_classes if cov else 0,
                      # N5: the measured evidence behind the tier, so a tier name never
                      # stands alone (15% and 50% recall are both "limited" otherwise).
                      "evidence": ev.as_dict() if ev else None})

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


def recall_phrase(ev: dict | None) -> str:
    """The measured recall behind a tier, e.g. "12% held-out recall on 2 corpora".

    Held-out recall is the headline because it is the one the rules were not tuned on;
    a language whose corpora were all used for tuning says so instead."""
    if not ev or not ev.get("corpora"):
        return "recall not measured"
    if ev.get("held_out_recall") is not None:
        n = ev["held_out_corpora"]
        return f"{round(ev['held_out_recall'] * 100)}% held-out recall on {n} {'corpus' if n == 1 else 'corpora'}"
    n = ev["corpora"]
    pct = round(ev["tuning_recall"] * 100) if ev.get("tuning_recall") is not None else 0
    return f"{pct}% recall on {n} tuning {'corpus' if n == 1 else 'corpora'}, none held out"


def language_line(l: dict) -> str:
    """e.g. "Java — limited · 12% held-out recall on 2 corpora"."""
    name, tier = display_name(l["language"]), _TIER_WORD[l["tier"]]
    if l["tier"] == TIER_NONE:
        return f"{name} — none · no rules"
    return f"{name} — {tier} · {recall_phrase(l.get('evidence'))}"


def headline(langs: list[dict], limit: int = 4) -> str:
    """What a customer is getting, with the measured recall next to every tier, e.g.
    "Java — limited · 15% held-out recall on 2 corpora; Ruby — none · no rules"."""
    parts = [language_line(l) for l in langs[:limit] if l["share"] >= 0.01]
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
