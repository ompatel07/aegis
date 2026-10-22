# Fixtures for rules/taint/python_weakness.yaml (Pass N3).
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
    reset_token = "".join(random.choice(CHARS) for _ in range(32))
    user.password_salt = str(random.getrandbits(64))
    n = random.randint(0, 10**9)
    payload = {"csrf_token": hex(n)}
    session["api_key"] = hashlib.sha256(str(random.random()).encode()).hexdigest()
    invite = create_invite(invite_code=str(uuid.uuid1()))
    return reset_token, payload, invite


def generate_otp():
    return "%06d" % random.randint(0, 999999)


def weak_random_ok(items, user):
    # sampling, shuffling and jitter are not secrets
    backoff = 1.0 + random.random()
    sample = random.sample(items, 3)
    # the secret word is not the head noun
    token_ttl = 3600 + random.randint(0, 60)
    # a random value passed to a call does not make its result a weak secret
    session_token = fetch_token(nonce_hint=None, jitter=random.random())
    # the fix
    api_key = secrets.token_urlsafe(32)
    password = "".join(secrets.choice(CHARS) for _ in range(20))
    pin = random.SystemRandom().randint(0, 9999)
    # a race / correlation "token" and a protocol nonce are not secrets
    fetch_token = str(random.random())
    nonce = str(random.getrandbits(32))
    # CSPRNG output mixed in
    csrf_token = secrets.token_hex(8) + str(random.random())
    return backoff, sample, token_ttl, session_token, api_key, password, pin, fetch_token, nonce, csrf_token


# ── weak hash, by what the digest is used for ────────────────────────────────
def weak_hash_bad(raw, user, payload, key):
    user.password_hash = hashlib.md5(raw.encode()).hexdigest()
    signature = hashlib.sha1(key + payload).hexdigest()
    # a digest that BECOMES a password (a generated value) is not a password store
    create_user(password=hashlib.md5(raw.encode()).hexdigest())
    return signature


def hash_password(raw):
    return hashlib.sha1(raw.encode()).hexdigest()


def weak_hash_ok(blob, key, payload):
    # a digest used as a cache key / ETag / checksum is not a security use
    cache_key = hashlib.md5(blob).hexdigest()
    etag = hashlib.sha1(blob).hexdigest()
    # an explicit non-security declaration is respected
    token = hashlib.md5(blob, usedforsecurity=False).hexdigest()
    # HMAC-MD5 is not broken by MD5 collisions
    signature = hmac.new(key, payload, hashlib.md5).hexdigest()
    password_hash = hashlib.sha256(blob).hexdigest()
    return cache_key, etag, token, signature, password_hash


# ── weak cipher / key size: no context needed ────────────────────────────────
def ciphers(key, iv):
    # ruleid: aegis-py-weak-cipher
    a = DES.new(key, DES.MODE_CBC, iv)
    # ruleid: aegis-py-weak-cipher
    b = DES3.new(key, DES3.MODE_CBC, iv)
    # ruleid: aegis-py-weak-cipher
    c = ARC4.new(key)
    # ruleid: aegis-py-weak-cipher
    d = AES.new(key, AES.MODE_ECB)
    # ruleid: aegis-py-weak-cipher
    e = Cipher(algorithms.AES(key), modes.ECB())
    # ruleid: aegis-py-weak-cipher
    f = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    # ok: aegis-py-weak-cipher
    g = AES.new(key, AES.MODE_GCM)
    # ok: aegis-py-weak-cipher
    h = Cipher(algorithms.AES(key), modes.GCM(iv))
    return a, b, c, d, e, f, g, h


def keys():
    # ruleid: aegis-py-weak-key-size
    k1 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    # ruleid: aegis-py-weak-key-size
    k2 = RSA.generate(1024)
    # ok: aegis-py-weak-key-size
    k3 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # ok: aegis-py-weak-key-size
    k4 = RSA.generate(3072)
    return k1, k2, k3, k4


# ── session cookie ───────────────────────────────────────────────────────────
def cookies(resp, token, opts):
    # ruleid: aegis-py-insecure-session-cookie
    resp.set_cookie("session_id", token)
    # ruleid: aegis-py-insecure-session-cookie
    resp.set_cookie("auth_token", token, httponly=True)
    # ruleid: aegis-py-insecure-session-cookie
    resp.set_cookie("remember_token", token, secure=True, httponly=False)
    # ok: aegis-py-insecure-session-cookie
    resp.set_cookie("auth_token", token, secure=True, httponly=True, samesite="Lax")
    # ok: aegis-py-insecure-session-cookie
    resp.set_cookie("csrftoken", token)
    # ok: aegis-py-insecure-session-cookie
    resp.set_cookie("theme", "dark")
    # ok: aegis-py-insecure-session-cookie
    resp.set_cookie("session_id", token, **opts)
    # an empty value deletes the cookie
    # ok: aegis-py-insecure-session-cookie
    resp.set_cookie("session_id", "", expires=0)
    return resp


# ruleid: aegis-py-insecure-session-cookie
SESSION_COOKIE_SECURE = False
# ok: aegis-py-insecure-session-cookie
CSRF_COOKIE_SECURE = False
# ruleid: aegis-py-insecure-session-cookie
app.config["SESSION_COOKIE_HTTPONLY"] = False
# ok: aegis-py-insecure-session-cookie
app.config["SESSION_COOKIE_SECURE"] = True


# ── trust boundary ───────────────────────────────────────────────────────────
@app.route("/prefs", methods=["POST"])
def prefs():
    session[request.form["name"]] = request.form["value"]
    session["is_admin"] = request.args.get("admin") == "1"
    session["locale"] = request.args.get("lang", "en")
    session["role"] = lookup_role(current_user_id())
    return "ok"


def django_view(request):
    request.session["role"] = request.POST.get("role")
    request.session["cart_note"] = request.POST.get("note")
