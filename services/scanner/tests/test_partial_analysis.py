"""D2: semgrep's analysis is cut short on wall-clock limits, and that is disclosed.

Semgrep bounds every function's taint fixpoint by time (0.2 s) and keeps the partial
result, so a large function's findings depend on CPU load (docs/D2_DETERMINISM.md).
Nothing in semgrep moves the limit, so a scan cannot be made deterministic -- these tests
hold the scanner to disclosing every file it happened to, and to never leaking the
matched code that the --debug log needed for the detection carries.
"""
from __future__ import annotations

from config import get_settings
from engines import semgrep_engine as se

ROOT = "/workspaces/repo"
FIXPOINT = ("[05.39][\x1b[33mWARNING\x1b[0m]: Fixpoint timeout while performing taint analysis "
            "[rule: tmp.aegis-taint-x.aegis-php-xss file: {f} func: ???]")


def test_fixpoint_timeouts_in_the_debug_log_name_their_files():
    stderr = "\n".join([
        "semgrep version 1.97.0",
        FIXPOINT.format(f="htdocs/adherents/card.php"),
        FIXPOINT.format(f="htdocs/adherents/card.php"),  # a second rule, same file
        FIXPOINT.format(f=f"{ROOT}/htdocs/takepos/invoice.php"),
        "running 412 rules from 9 configs",
    ])
    p = se.partial_analysis(stderr, {"errors": []}, ROOT)
    assert p["files"] == 2 and p["fixpoint_timeouts"] == 3 and p["rule_timeouts"] == 0
    assert p["sample"] == ["htdocs/adherents/card.php", "htdocs/takepos/invoice.php"]
    assert "differ between scans" in p["reason"]


def test_rule_timeouts_in_the_json_errors_count_too():
    raw = {"errors": [
        {"type": "Timeout", "path": f"{ROOT}/htdocs/includes/jquery/js/jquery.js", "rule_id": "node_ssrf"},
        {"type": ["PartialParsing", []], "path": f"{ROOT}/a.php"},  # not a time limit
        {"type": "Syntax error", "path": f"{ROOT}/b.php"},
    ]}
    p = se.partial_analysis("", raw, ROOT)
    assert p["files"] == 1 and p["rule_timeouts"] == 1 and p["fixpoint_timeouts"] == 0
    assert p["sample"] == ["htdocs/includes/jquery/js/jquery.js"]


def test_a_complete_analysis_discloses_nothing():
    assert se.partial_analysis("semgrep version 1.97.0\nran 4 rules", {"errors": []}, ROOT) is None
    assert se.partial_analysis("", None, ROOT) is None


def test_the_sample_is_bounded_and_sorted():
    stderr = "\n".join(FIXPOINT.format(f=f"f{i:03d}.php") for i in range(60, 0, -1))
    p = se.partial_analysis(stderr, {}, ROOT)
    assert p["files"] == 60 and len(p["sample"]) == se._PARTIAL_SAMPLE and p["sample"][0] == "f001.php"


def test_the_scan_runs_with_the_debug_log_the_detection_reads():
    args = se._build_args(get_settings(), ["/rules/a.yaml"], ROOT)
    assert "--debug" in args and "--quiet" not in args


# ── the debug log carries matched code: it never reaches a stored error ─────────
SECRET = "AEGIS-PLANTED-MATCHED-CODE-7f3e"  # stands for any matched literal, a secret included
DEBUG_NOISE = "\n".join([
    f"match_key = ('password = \"{SECRET}\"', PosixPath('app/config.php'), 'hardcoded-secret')",
    f"    \"{SECRET}\" match_id = 2f1c",  # a continuation line of a multi-line key
    f"  value: {SECRET}",
])


def test_a_failure_message_never_carries_matched_code():
    stderr = DEBUG_NOISE + "\n[ERROR] invalid rule schema in /rules/a.yaml\n" + DEBUG_NOISE
    msg = se._failure_message(stderr, "", 2)
    assert SECRET not in msg
    assert "invalid rule schema" in msg


def test_a_failure_prefers_semgrep_json_errors():
    stdout = '{"errors": [{"type": "InvalidRuleSchemaError", "message": "rule a: bad key"}], "results": []}'
    msg = se._failure_message(DEBUG_NOISE, stdout, 7)
    assert msg == "rule a: bad key" and SECRET not in msg


def test_a_failure_with_nothing_safe_to_say_names_the_exit_code():
    assert se._failure_message(DEBUG_NOISE, "", 2) == "semgrep failed (exit code 2)"
