# Fixtures for rules_staging/python_weakness.yaml (Pass N3, staged).
import hashlib
import hmac
import random
import secrets
import string
import uuid

from Crypto.Cipher import AES, ARC4, DES, DES3
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, request, session

app = Flask(__name__)
CHARS = string.ascii_letters + string.digits


# ── weak random ──────────────────────────────────────────────────────────────
def weak_random_bad(user):
    # ruleid: aegis-py-weak-random-secret
    reset_token = "".join(random.choice(CHARS) for _ in range(32))
    # ruleid: aegis-py-weak-random-secret
    user.password_salt = str(random.getrandbits(64))
    n = random.randint(0, 10**9)
    # ruleid: aegis-py-weak-random-secret
    payload = {"csrf_token": hex(n)}
    # ruleid: aegis-py-weak-random-secret
    session["api_key"] = hashlib.sha256(str(random.random()).encode()).hexdigest()
    # ruleid: aegis-py-weak-random-secret
    invite = create_invite(invite_code=str(uuid.uuid1()))
    return reset_token, payload, invite


def generate_otp():
    # ruleid: aegis-py-weak-random-secret
    return "%06d" % random.randint(0, 999999)


def weak_random_ok(items, user):
    # sampling, shuffling and jitter are not secrets
    # ok: aegis-py-weak-random-secret
    backoff = 1.0 + random.random()
    # ok: aegis-py-weak-random-secret
    sample = random.sample(items, 3)
    # the secret word is not the head noun
    # ok: aegis-py-weak-random-secret
    token_ttl = 3600 + random.randint(0, 60)
    # a random value passed to a call does not make its result a weak secret
    # ok: aegis-py-weak-random-secret
    session_token = fetch_token(nonce_hint=None, jitter=random.random())
    # the fix
    # ok: aegis-py-weak-random-secret
    api_key = secrets.token_urlsafe(32)
    # ok: aegis-py-weak-random-secret
    password = "".join(secrets.choice(CHARS) for _ in range(20))
    # ok: aegis-py-weak-random-secret
    pin = random.SystemRandom().randint(0, 9999)
    # a race / correlation "token" and a protocol nonce are not secrets
    # ok: aegis-py-weak-random-secret
    fetch_token = str(random.random())
    # ok: aegis-py-weak-random-secret
    nonce = str(random.getrandbits(32))
    # CSPRNG output mixed in
    # ok: aegis-py-weak-random-secret
    csrf_token = secrets.token_hex(8) + str(random.random())
    return backoff, sample, token_ttl, session_token, api_key, password, pin, fetch_token, nonce, csrf_token


# ── weak hash, by what the digest is used for ────────────────────────────────
def weak_hash_bad(raw, user, payload, key):
    # ruleid: aegis-py-weak-hash-security-use
    user.password_hash = hashlib.md5(raw.encode()).hexdigest()
    # ruleid: aegis-py-weak-hash-security-use
    signature = hashlib.sha1(key + payload).hexdigest()
    # a digest that BECOMES a password (a generated value) is not a password store
    # ok: aegis-py-weak-hash-security-use
    create_user(password=hashlib.md5(raw.encode()).hexdigest())
    return signature


def hash_password(raw):
    # ruleid: aegis-py-weak-hash-security-use
    return hashlib.sha1(raw.encode()).hexdigest()


def weak_hash_ok(blob, key, payload):
    # a digest used as a cache key / ETag / checksum is not a security use
    # ok: aegis-py-weak-hash-security-use
    cache_key = hashlib.md5(blob).hexdigest()
    # ok: aegis-py-weak-hash-security-use
    etag = hashlib.sha1(blob).hexdigest()
    # an explicit non-security declaration is respected
    # ok: aegis-py-weak-hash-security-use
    token = hashlib.md5(blob, usedforsecurity=False).hexdigest()
    # HMAC-MD5 is not broken by MD5 collisions
    # ok: aegis-py-weak-hash-security-use
    signature = hmac.new(key, payload, hashlib.md5).hexdigest()
    # ok: aegis-py-weak-hash-security-use
    password_hash = hashlib.sha256(blob).hexdigest()
    return cache_key, etag, token, signature, password_hash


# ── weak cipher / key size: no context needed ────────────────────────────────
def ciphers(key, iv):
    a = DES.new(key, DES.MODE_CBC, iv)
    b = DES3.new(key, DES3.MODE_CBC, iv)
    c = ARC4.new(key)
    d = AES.new(key, AES.MODE_ECB)
    e = Cipher(algorithms.AES(key), modes.ECB())
    f = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    g = AES.new(key, AES.MODE_GCM)
    h = Cipher(algorithms.AES(key), modes.GCM(iv))
    return a, b, c, d, e, f, g, h


def keys():
    k1 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    k2 = RSA.generate(1024)
    k3 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    k4 = RSA.generate(3072)
    return k1, k2, k3, k4


# ── session cookie ───────────────────────────────────────────────────────────
def cookies(resp, token, opts):
    resp.set_cookie("session_id", token)
    resp.set_cookie("auth_token", token, httponly=True)
    resp.set_cookie("remember_token", token, secure=True, httponly=False)
    resp.set_cookie("auth_token", token, secure=True, httponly=True, samesite="Lax")
    resp.set_cookie("csrftoken", token)
    resp.set_cookie("theme", "dark")
    resp.set_cookie("session_id", token, **opts)
    return resp


SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SECURE"] = True


# ── trust boundary ───────────────────────────────────────────────────────────
@app.route("/prefs", methods=["POST"])
def prefs():
    # ruleid: aegis-py-session-trust-boundary
    session[request.form["name"]] = request.form["value"]
    # ruleid: aegis-py-session-trust-boundary
    session["is_admin"] = request.args.get("admin") == "1"
    # ok: aegis-py-session-trust-boundary
    session["locale"] = request.args.get("lang", "en")
    # ok: aegis-py-session-trust-boundary
    session["role"] = lookup_role(current_user_id())
    return "ok"


def django_view(request):
    # ruleid: aegis-py-session-trust-boundary
    request.session["role"] = request.POST.get("role")
    # ok: aegis-py-session-trust-boundary
    request.session["cart_note"] = request.POST.get("note")
