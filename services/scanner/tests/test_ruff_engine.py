"""Ruff type-aware Python bug source tests (Q3).

Ruff is our second bug source (after the Semgrep pack) and makes the same
high-trust-cost claim — "your code is wrong" — so it carries the same gates:

1. The allowlist is EXPLICIT and disciplined: every entry names a single ruff
   code, caps severity at medium (no reliability bug grades a repo below C on
   day one), types itself bug/code_smell, and never ingests a style (E/W) or
   security (S — bandit) category. This runs without the binary so it always
   guards the map.
2. The map is the single source of truth for issue_type: every ruff rule typed
   `bug` loads into enricher._QUALITY_BUG_RULES, so Ruff findings are tagged
   issue_type=bug and drive the Reliability rating exactly like Semgrep bugs.
3. DEDUP: the two ids Ruff now owns (B006 mutable-default, F632 is-literal) were
   removed from the Semgrep pack, so a finding is never double-reported.
4. Binary-gated behavioural gates (recall, determinism, config isolation) — the
   Pass-1 invariants — run as permanent regressions when the ruff binary exists.
"""
from __future__ import annotations

import json
import os
import subprocess

import pytest

from config import get_settings
from engines import ruff_engine
from utils.sandbox import binary_available

settings = get_settings()
_ALLOWLIST = ruff_engine._load_map()

# The 10 codes hand-picked and gate-proven in Q3. If this set changes, the FP
# gate must be re-run by hand (see PER_ENGINE_ACCURACY.md) before editing here.
_EXPECTED_CODES = {
    "F502", "F506", "F632", "F701", "F702", "F706", "F811",
    "B006", "B015", "PLE0101", "ASYNC251",
}


def test_allowlist_matches_the_gated_set():
    assert set(_ALLOWLIST) == _EXPECTED_CODES, (
        "ruff allowlist changed — re-run the by-hand FP gate before editing this"
    )


def test_no_style_or_security_category_ingested():
    """E/W = pycodestyle style (not bugs); S = bandit security (would double-count
    the security pillar). Neither may ever enter the quality bug source."""
    for code in _ALLOWLIST:
        assert not code.startswith(("E", "W", "S")), (
            f"{code}: style (E/W) or security (S) category must never be selected"
        )


def test_every_entry_is_capped_and_well_formed():
    for code, entry in _ALLOWLIST.items():
        assert isinstance(entry, dict), f"{code}: entry must be a mapping"
        assert entry.get("aegis_rule_id"), f"{code}: missing aegis_rule_id"
        assert entry.get("issue_type") in ("bug", "code_smell"), (
            f"{code}: issue_type must be bug or code_smell"
        )
        # Severity cap — same as the Semgrep pack. A bug rule never emits high or
        # critical, so one reliability bug caps the Reliability rating at C.
        assert str(entry.get("severity", "")).lower() in ("low", "medium"), (
            f"{code} declares severity {entry.get('severity')!r}; bug rules cap at medium"
        )


def test_ruff_version_is_pinned():
    import yaml

    with open(ruff_engine._MAP_PATH, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    assert doc.get("ruff_version"), "ruff_version must be pinned for determinism"


def test_bug_ids_load_into_quality_bug_rules():
    """Every ruff rule typed `bug` must be tagged issue_type=bug by the enricher,
    exactly like the Semgrep pack — otherwise Ruff findings wouldn't move the
    Reliability rating."""
    from enrichment import enricher

    for rid in ruff_engine.bug_rule_ids():
        assert rid in enricher._QUALITY_BUG_RULES, f"{rid} not tagged as a bug"


def test_dedup_semgrep_rules_removed():
    """B006 and F632 are now owned by Ruff; the Semgrep pack must NOT still define
    them, or the same bug would be reported twice."""
    import yaml

    # bugs.yaml lives under rules/quality/; ruff_map.yaml lives under config/ (it
    # is NOT a semgrep rule file and must stay out of semgrep-loaded dirs).
    scanner_dir = os.path.dirname(os.path.dirname(ruff_engine._MAP_PATH))
    with open(os.path.join(scanner_dir, "rules", "quality", "bugs.yaml"),
              encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    semgrep_ids = {r["id"] for r in doc["rules"]}
    for owned in ("aegis-bug-mutable-default-arg", "aegis-bug-py-is-literal-comparison"):
        assert owned in ruff_engine.bug_rule_ids(), f"{owned} must be owned by Ruff"
        assert owned not in semgrep_ids, f"{owned} double-defined in the Semgrep pack"


# ── Binary-gated behavioural gates (Pass-1 invariants) ───────────────────────

_SKIP = pytest.mark.skipif(
    not binary_available(settings.ruff_bin),
    reason="ruff binary not available",
)


def _run_ruff(path: str) -> list[dict]:
    select = ",".join(sorted(_ALLOWLIST))
    proc = subprocess.run(
        [settings.ruff_bin, "check", "--output-format=json", "--no-cache",
         "--isolated", "--exclude", ruff_engine._EXCLUDE_DIRS,
         "--select", select, "--exit-zero", path],
        capture_output=True, text=True, timeout=300,
    )
    return json.loads(proc.stdout) if proc.stdout.strip() else []


@_SKIP
def test_recall_every_allowlisted_code_fires(tmp_path):
    """Each kept code must actually fire on a planted bug — proof the allowlist is
    live, not aspirational."""
    (tmp_path / "f.py").write_text(
        "import time\n"
        "def redef(): pass\n"          # F811
        "def redef(): pass\n"
        'def islit(x): return x is "a"\n'          # F632
        'def fmt(): return "%(a)s" % ("x",)\n'     # F502
        'def fmt2(): return "%s %(a)s" % {}\n'     # F506
        "def mut(a, items=[]): return items\n"     # B006
        "def cmp(x): x == 1\n"                      # B015
        "async def slp(): time.sleep(1)\n"         # ASYNC251
        "break\n",                                  # F701
        encoding="utf-8",
    )
    (tmp_path / "g.py").write_text("continue\n", encoding="utf-8")   # F702
    (tmp_path / "h.py").write_text("return 5\n", encoding="utf-8")   # F706
    (tmp_path / "i.py").write_text(
        "class C:\n    def __init__(self): return 1\n", encoding="utf-8")  # PLE0101
    fired = {r["code"] for r in _run_ruff(str(tmp_path))}
    missing = _EXPECTED_CODES - fired
    assert not missing, f"codes did not fire on planted bugs: {sorted(missing)}"


@_SKIP
def test_determinism_repeat_scan_is_identical(tmp_path):
    (tmp_path / "a.py").write_text(
        "def r(): pass\ndef r(): pass\ndef m(x=[]): return x\n", encoding="utf-8")
    first = json.dumps(_run_ruff(str(tmp_path)), sort_keys=True)
    second = json.dumps(_run_ruff(str(tmp_path)), sort_keys=True)
    assert first == second, "repeat ruff scan differed — determinism broken"


@_SKIP
def test_config_isolation_hostile_pyproject_cannot_silence(tmp_path):
    """A customer's pyproject.toml must not be able to silence our findings."""
    (tmp_path / "a.py").write_text("def m(x=[]): return x\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.ruff]\nlint.ignore = ["ALL"]\nlint.select = []\nexclude = ["a.py"]\n',
        encoding="utf-8",
    )
    assert _run_ruff(str(tmp_path)), "hostile pyproject.toml silenced ruff (--isolated failed)"
