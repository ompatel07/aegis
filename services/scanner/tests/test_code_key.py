"""Path-independent finding identity (J4 Part B).

`fingerprint` = rule + file_path + normalized code + ordinal. file_path has to
stay in it — identical code in two files is two findings — but that means moving
a file resolves every finding in it and opens an identical set as new. In a
compliance artifact whose value is open-vs-closed, that is a wave of fake
regressions and fake fixes on the same day.

`code_key` is the same identity without the path. The orchestrator uses it only
as a fallback and only for a strictly 1:1 pairing, so these tests pin the two
properties that make that safe: it must be stable across a move, and it must
still separate findings that are genuinely different.
"""
from __future__ import annotations

import os

import pytest

from models.scan_result import Engine, Finding, Pillar, Severity
from utils import snippet

SRC = '''import os


def run_backup(target):
    """Take a backup."""
    os.system("tar czf /backups/out.tgz " + target)


def ping_host(host):
    os.system("ping -c 1 " + host)
'''


def _write(root, rel, text=SRC):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _finding(rel, line, rule="aegis-py-shell-command-construction"):
    return Finding(rule_id=rule, rule_name=rule, engine=Engine.SEMGREP, pillar=Pillar.SECURITY,
                   severity=Severity.HIGH, title="t", file_path=rel, line_start=line, line_end=line)


def _keys(root, rel, line, rule="aegis-py-shell-command-construction"):
    f = _finding(rel, line, rule)
    snippet.attach([f], root)
    return f.fingerprint, f.code_key


def test_both_keys_are_emitted(tmp_path):
    _write(str(tmp_path), "app/tasks.py")
    fp, ck = _keys(str(tmp_path), "app/tasks.py", 6)
    assert fp and len(fp) == 32
    assert ck and len(ck) == 32
    assert fp != ck


def test_code_key_survives_a_file_move(tmp_path):
    """The property the whole feature rests on."""
    a, b = tmp_path / "a", tmp_path / "b"
    _write(str(a), "app/tasks.py")
    _write(str(b), "src/api/app/tasks.py")
    fp_a, ck_a = _keys(str(a), "app/tasks.py", 6)
    fp_b, ck_b = _keys(str(b), "src/api/app/tasks.py", 6)
    assert fp_a != fp_b, "fingerprint must still change — it is path-scoped by design"
    assert ck_a == ck_b, "code_key must survive the move, or the lifecycle cannot follow it"


def test_code_key_survives_a_line_shift(tmp_path):
    """J4 must not weaken the line-shift resilience F1 established."""
    a, b = tmp_path / "a", tmp_path / "b"
    _write(str(a), "app/tasks.py")
    _write(str(b), "app/tasks.py", "# pad\n" * 20 + SRC)
    fp_a, ck_a = _keys(str(a), "app/tasks.py", 6)
    fp_b, ck_b = _keys(str(b), "app/tasks.py", 26)
    assert fp_a == fp_b, "fingerprint line-shift resilience regressed"
    assert ck_a == ck_b


def test_a_different_rule_on_the_same_line_is_a_different_finding(tmp_path):
    _write(str(tmp_path), "app/tasks.py")
    _, ck1 = _keys(str(tmp_path), "app/tasks.py", 6, rule="rule-one")
    _, ck2 = _keys(str(tmp_path), "app/tasks.py", 6, rule="rule-two")
    assert ck1 != ck2


def test_changed_code_produces_a_different_code_key(tmp_path):
    """A fixed finding must NOT be migrated onto its replacement."""
    a, b = tmp_path / "a", tmp_path / "b"
    _write(str(a), "app/tasks.py")
    _write(str(b), "app/tasks.py", SRC.replace(
        'os.system("tar czf /backups/out.tgz " + target)',
        'subprocess.run(["tar", "czf", "/backups/out.tgz", target])'))
    _, ck_a = _keys(str(a), "app/tasks.py", 6)
    _, ck_b = _keys(str(b), "app/tasks.py", 6)
    assert ck_a != ck_b


def test_duplicate_identical_lines_keep_distinct_code_keys(tmp_path):
    """The ordinal must apply to code_key too, or two copies of the same line in
    one file would collapse into one identity."""
    dup = 'import os\n\n\ndef a(t):\n    os.system("x " + t)\n\n\ndef b(t):\n    os.system("x " + t)\n'
    _write(str(tmp_path), "d.py", dup)
    fs = [_finding("d.py", 5), _finding("d.py", 9)]
    snippet.attach(fs, str(tmp_path))
    assert fs[0].code_key != fs[1].code_key


def test_identical_code_in_two_files_shares_a_code_key(tmp_path):
    """Not a bug — it is why the orchestrator requires a strictly 1:1 pairing
    before migrating. Two candidates means it declines and falls back."""
    _write(str(tmp_path), "a.py")
    _write(str(tmp_path), "b.py")
    _, ck_a = _keys(str(tmp_path), "a.py", 6)
    _, ck_b = _keys(str(tmp_path), "b.py", 6)
    assert ck_a == ck_b


def test_code_key_is_set_even_when_the_file_cannot_be_read(tmp_path):
    """Best-effort path: a missing file must still leave a deterministic id."""
    f = _finding("does/not/exist.py", 3)
    snippet.attach([f], str(tmp_path))
    assert f.fingerprint
    assert f.code_key
