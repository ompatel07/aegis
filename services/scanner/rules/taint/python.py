# Test fixtures for rules/taint/python.yaml — consumed by `semgrep --test`.
#
# Each rule has a positive case (annotation says the rule MUST fire on the next
# line) and a sanitized negative case (annotation says it must NOT fire). These
# files live beside the rules per the semgrep --test convention; they are never
# scanned in production (real scans target the cloned repo, and --config only
# loads *.yaml as rules).
import ast
import io  # noqa: F401
import os
import shutil  # noqa: F401
import subprocess

import ldap
import requests
from bson import ObjectId
from flask import render_template_string, request, send_file  # noqa: F401
from ldap.filter import escape_filter_chars
from markupsafe import Markup, escape  # noqa: F401
from werkzeug.utils import secure_filename


def validate_url(url):
    """Allowlist helper — declared as a sanitizer by aegis-py-ssrf."""
    return url


# ── SQL injection ────────────────────────────────────────────────────────────
def sqli_bad(cur):
    user_id = request.args.get("id")
    # ruleid: aegis-py-sql-injection
    cur.execute("SELECT * FROM users WHERE id = " + user_id)


def sqli_ok(cur):
    user_id = request.args.get("id")
    # ok: aegis-py-sql-injection
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def sqli_ok_cast(cur):
    user_id = int(request.args.get("id"))
    # ok: aegis-py-sql-injection
    cur.execute("SELECT * FROM users WHERE id = " + str(user_id))


# ── Reflected XSS ────────────────────────────────────────────────────────────
def xss_bad():
    name = request.args.get("name")
    # ruleid: aegis-py-xss
    return render_template_string("<h1>Hello " + name + "</h1>")


def xss_ok():
    name = request.args.get("name")
    # ok: aegis-py-xss
    return render_template_string("<h1>Hello " + escape(name) + "</h1>")


# ── OS command injection ─────────────────────────────────────────────────────
def cmd_bad_system():
    host = request.args.get("host")
    # ruleid: aegis-py-command-injection
    os.system("ping -c 1 " + host)


def cmd_bad_shell():
    host = request.args.get("host")
    # ruleid: aegis-py-command-injection
    subprocess.call("nslookup " + host, shell=True)


def cmd_ok():
    host = request.args.get("host")
    # ok: aegis-py-command-injection
    subprocess.run(["ping", "-c", "1", host])


# ── SSRF ─────────────────────────────────────────────────────────────────────
def ssrf_bad():
    url = request.args.get("url")
    # ruleid: aegis-py-ssrf
    return requests.get(url).text


def ssrf_ok():
    url = request.args.get("url")
    safe_url = validate_url(url)
    # ok: aegis-py-ssrf
    return requests.get(safe_url).text


# ── Path traversal ───────────────────────────────────────────────────────────
def path_bad():
    fname = request.args.get("file")
    # ruleid: aegis-py-path-traversal
    with open("/var/data/" + fname) as f:
        return f.read()


def path_ok():
    fname = request.args.get("file")
    safe = secure_filename(fname)
    # ok: aegis-py-path-traversal
    with open(os.path.join("/var/data", safe)) as f:
        return f.read()


# ── NoSQL injection ──────────────────────────────────────────────────────────
def nosql_bad(collection):
    creds = request.get_json()
    # ruleid: aegis-py-nosql-injection
    return collection.find_one(creds)


def nosql_ok(collection):
    user_id = request.args.get("id")
    # ok: aegis-py-nosql-injection
    return collection.find_one({"_id": ObjectId(user_id)})


# ── LDAP injection ───────────────────────────────────────────────────────────
def ldap_bad(conn):
    username = request.args.get("user")
    filt = "(uid=" + username + ")"
    # ruleid: aegis-py-ldap-injection
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filt)


def ldap_ok(conn):
    username = request.args.get("user")
    filt = "(uid=" + escape_filter_chars(username) + ")"
    # ok: aegis-py-ldap-injection
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filt)


# ── Code injection ───────────────────────────────────────────────────────────
def code_bad():
    expr = request.args.get("expr")
    # ruleid: aegis-py-code-injection
    return eval(expr)


def code_ok():
    expr = request.args.get("expr")
    # ok: aegis-py-code-injection
    return ast.literal_eval(expr)
