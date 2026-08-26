"""Secret down-ranking precision tests (S1).

Down-rank test-fixture / placeholder / expired secrets to LOW + tag, but NEVER
down-rank a live-format provider credential, even in a test path.
"""
from __future__ import annotations

import base64
import json
import time

from enrichment import secret_context
from models.scan_result import Engine, Finding, Pillar, Severity


def mk(rule_id, file_path, match, *, engine=Engine.GITLEAKS, entropy=None,
       sev=Severity.CRITICAL, snippet=None):
    return Finding(
        pillar=Pillar.SECURITY, engine=engine, rule_id=rule_id, rule_name=rule_id,
        severity=sev, title=rule_id, file_path=file_path,
        code_snippet=snippet,
        metadata={"match": match, "entropy": entropy},
    )


def _jwt(exp_delta_seconds: int) -> str:
    hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = {"sub": "1234", "exp": int(time.time()) + exp_delta_seconds}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{hdr}.{body}.c2lnbmF0dXJl"


def ctx(f):
    return (f.metadata or {}).get("secret_context")


# ── mandatory override: provider keys never down-ranked, even in test paths ──
def test_aws_key_in_testdata_stays_critical():
    f = mk("generic-api-key", "testdata/seed.go", "AKIA1234567890ABCDEF")
    secret_context.annotate([f])
    assert f.severity == Severity.CRITICAL
    assert ctx(f) == "live-format"


def test_github_pat_in_test_file_stays_critical():
    f = mk("generic-api-key", "internal/api_test.go",
           "ghp_0123456789abcdefghijklmnopqrstuvwxyz")
    secret_context.annotate([f])
    assert f.severity == Severity.CRITICAL


def test_pem_private_key_body_in_fixtures_stays_critical():
    body = "\n".join("MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT" + "a" * 20 for _ in range(4))
    f = mk("private-key", "tests/fixtures/key.pem",
           f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----")
    secret_context.annotate([f])
    assert f.severity == Severity.CRITICAL


# ── expired-JWT check governs jwt findings ───────────────────────────────────
def test_expired_jwt_in_test_downranked():
    f = mk("jwt", "apis/backup_test.go", "token=" + _jwt(-3600))
    secret_context.annotate([f])
    assert f.severity == Severity.LOW
    assert ctx(f) == "expired"


def test_future_jwt_in_test_unchanged():
    f = mk("jwt", "apis/backup_test.go", "token=" + _jwt(+3600))
    secret_context.annotate([f])
    assert f.severity == Severity.CRITICAL  # could be live; path prior must NOT apply
    assert ctx(f) is None


def test_malformed_jwt_unchanged():
    f = mk("jwt", "apis/backup_test.go", "eyJhbGc.NOTBASE64!!!.sig")
    secret_context.annotate([f])
    assert f.severity == Severity.CRITICAL


# ── placeholder shape ────────────────────────────────────────────────────────
def test_placeholder_env_example_downranked():
    f = mk("aegis-db-connection-string", ".env.example",
           "postgresql://user:password@localhost:5432/db", entropy=2.75)
    secret_context.annotate([f])
    assert f.severity == Severity.LOW
    assert ctx(f) == "placeholder"


def test_your_api_key_placeholder_downranked():
    f = mk("generic-api-key", "config/app.php", "your-api-key-here")
    secret_context.annotate([f])
    assert f.severity == Severity.LOW
    assert ctx(f) == "placeholder"


# ── path prior (non-jwt, non-placeholder) ────────────────────────────────────
def test_random_secret_in_tests_dir_downranked_as_fixture():
    f = mk("generic-api-key", "tests/Support/Settings.php",
           "a8f3k2mZ9qWx7Lp0RtBcYvN4hJ6dGe1", entropy=4.6)
    secret_context.annotate([f])
    assert f.severity == Severity.LOW
    assert ctx(f) == "test-fixture"


def test_bcrypt_hash_in_factories_downranked():
    f = mk("generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash",
           "database/factories/UserFactory.php", None, engine=Engine.SEMGREP,
           sev=Severity.HIGH,
           snippet="'password' => '$2y$10$abcdefghijklmnopqrstuvwxyABCDEF012345'")
    secret_context.annotate([f])
    assert f.severity == Severity.LOW
    assert ctx(f) == "test-fixture"


# ── real secret in a real path is left alone ─────────────────────────────────
def test_real_looking_secret_in_src_unchanged():
    f = mk("generic-api-key", "src/config.py",
           "a8f3k2mZ9qWx7Lp0RtBcYvN4hJ6dGe1", entropy=4.6)
    secret_context.annotate([f])
    assert f.severity == Severity.CRITICAL
    assert ctx(f) is None
