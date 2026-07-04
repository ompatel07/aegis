# Test fixture for ai_code_taint/python.yaml (run via semgrep --test).
import hashlib
import random
import secrets

import jwt


def weak_crypto(payload):
    # ruleid: ai-code-weak-crypto
    digest = hashlib.md5(payload).hexdigest()
    # ruleid: ai-code-weak-crypto
    other = hashlib.sha1(payload).hexdigest()
    # ok: ai-code-weak-crypto
    strong = hashlib.sha256(payload).hexdigest()
    return digest, other, strong


def random_tokens(user):
    # ruleid: ai-code-insecure-random
    session_token = random.randint(0, 999999)
    # ok: ai-code-insecure-random
    dice = random.randint(1, 6)
    # ok: ai-code-insecure-random
    good_token = secrets.token_hex(16)
    return session_token, dice, good_token


def broad_except(data):
    # ruleid: ai-code-broad-except-pass
    try:
        return data["key"]
    except Exception:
        pass

    # ok: ai-code-broad-except-pass
    try:
        return data["other"]
    except KeyError:
        return None


def decode_token(token):
    # ruleid: ai-code-jwt-no-verify
    claims = jwt.decode(token, verify=False)
    # ruleid: ai-code-jwt-no-verify
    claims2 = jwt.decode(token, key, options={"verify_signature": False})
    # ok: ai-code-jwt-no-verify
    good = jwt.decode(token, key, algorithms=["HS256"])
    return claims, claims2, good


def run_query(cursor, uid):
    # ruleid: ai-code-sql-string-build
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    # ruleid: ai-code-sql-string-build
    cursor.execute("SELECT * FROM users WHERE id = %s" % uid)
    # ok: ai-code-sql-string-build
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))


# ruleid: ai-code-hardcoded-secret-default
def connect(host, password="s3cr3t-default"):
    return (host, password)


# ok: ai-code-hardcoded-secret-default
def connect_ok(host, password=None):
    return (host, password)


# ok: ai-code-hardcoded-secret-default
def connect_timeout(host, timeout=30):
    return (host, timeout)
