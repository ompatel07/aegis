"""Secret precision tests (S1 + P1).

P1 splits the three S1 signals by what they definitively mean:
  - placeholder shape / expired JWT -> SUPPRESSED (removed) + counted in stats.
  - test-fixture path -> KEPT at LOW + tagged (may be a real secret in a test file).
A live-format provider credential is NEVER suppressed or down-ranked, even in a
test path — it wins over every other signal.
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


# ── JWT policy: expired is decisive -> SUPPRESS; future/undecodable could be live
def test_expired_jwt_anywhere_suppressed():
    # expired is decisive regardless of path (here: a non-fixture path)
    f = mk("jwt", "src/auth.go", "token=" + _jwt(-3600))
    lst = [f]
    stats = secret_context.annotate(lst)
    assert lst == []                      # removed from findings
    assert stats["expired_jwt"] == 1      # counted
    assert ctx(f) == "expired"            # tagged before removal


def test_future_jwt_in_fixture_path_kept_low():
    # future JWT is NOT expired -> fixture-path prior applies -> KEPT at LOW.
    f = mk("jwt", "apis/backup_test.go", "token=" + _jwt(+3600))
    lst = [f]
    stats = secret_context.annotate(lst)
    assert lst == [f]                     # kept
    assert f.severity == Severity.LOW
    assert ctx(f) == "test-fixture"
    assert stats["expired_jwt"] == 0


def test_future_jwt_outside_fixture_unchanged():
    f = mk("jwt", "src/auth.go", "token=" + _jwt(+3600))
    secret_context.annotate([f])
    assert f.severity == Severity.CRITICAL  # could be live, and not in a fixture path
    assert ctx(f) is None


def test_malformed_jwt_outside_fixture_unchanged():
    f = mk("jwt", "src/auth.go", "eyJhbGc.NOTBASE64!!!.sig")
    secret_context.annotate([f])
    assert f.severity == Severity.CRITICAL


# ── placeholder shape -> SUPPRESSED + counted ────────────────────────────────
def test_placeholder_env_example_suppressed():
    f = mk("aegis-db-connection-string", ".env.example",
           "postgresql://user:password@localhost:5432/db", entropy=2.75)
    lst = [f]
    stats = secret_context.annotate(lst)
    assert lst == []                      # removed from findings
    assert stats["placeholder"] == 1      # counted
    assert ctx(f) == "placeholder"


def test_your_api_key_placeholder_suppressed():
    f = mk("generic-api-key", "config/app.php", "your-api-key-here")
    lst = [f]
    stats = secret_context.annotate(lst)
    assert lst == []
    assert stats["placeholder"] == 1


def test_stats_returned_zero_when_nothing_filtered():
    f = mk("generic-api-key", "src/config.py",
           "a8f3k2mZ9qWx7Lp0RtBcYvN4hJ6dGe1", entropy=4.6)
    stats = secret_context.annotate([f])
    assert stats == {"placeholder": 0, "expired_jwt": 0}


def test_provider_key_with_placeholder_path_still_wins():
    # A real AWS key whose surrounding text also looks placeholder-y: provider wins,
    # so it is KEPT at full severity, never suppressed.
    f = mk("generic-api-key", ".env.example", "AKIA1234567890ABCDEF")
    lst = [f]
    stats = secret_context.annotate(lst)
    assert lst == [f]
    assert f.severity == Severity.CRITICAL
    assert ctx(f) == "live-format"
    assert stats["placeholder"] == 0


# ── documentation-path prior (P2) -> LOW + tagged, not suppressed ────────────
def test_secret_in_mdx_doc_downranked():
    f = mk("generic-api-key", "apps/docs/content/docs/developers/api/recipients.mdx",
           "a8f3k2mZ9qWx7Lp0RtBcYvN4hJ6dGe1", entropy=4.6)
    lst = [f]
    secret_context.annotate(lst)
    assert lst == [f]                      # kept, not suppressed
    assert f.severity == Severity.LOW
    assert ctx(f) == "documentation"


def test_secret_in_docs_dir_downranked():
    f = mk("private-key", "documentation/self-hosting/email.md",
           "a8f3k2mZ9qWx7Lp0RtBcYvN4hJ6dGe1", entropy=4.6)
    secret_context.annotate([f])
    assert f.severity == Severity.LOW
    assert ctx(f) == "documentation"


def test_provider_key_in_doc_still_wins():
    f = mk("generic-api-key", "docs/api/example.mdx", "AKIA1234567890ABCDEF")
    secret_context.annotate([f])
    assert f.severity == Severity.CRITICAL
    assert ctx(f) == "live-format"


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


# ── enrich_all threads the suppression counts (the "N filtered" surface) ──────
def test_enrich_all_threads_filtered_stats():
    from enrichment import enricher

    findings = [
        mk("generic-api-key", "config/app.php", "your-api-key-here"),   # placeholder
        mk("aws-access-token", "src/c.py", "AKIAIOSFODNN7REALKEY0"),     # provider, kept
    ]
    stats: dict = {}
    enricher.enrich_all(findings, "", stats=stats)
    assert [f.rule_id for f in findings] == ["aws-access-token"]  # placeholder removed
    assert stats.get("placeholder") == 1
    assert stats.get("expired_jwt") == 0
