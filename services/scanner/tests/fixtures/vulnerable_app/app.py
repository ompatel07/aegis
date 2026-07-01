"""Deliberately vulnerable Flask app — a smoke fixture for the scanning engines.

Every engine should find issues here:
  * gitleaks / semgrep : hardcoded secrets below + the .env in this directory
  * semgrep            : SQLi, command injection, code injection
  * trivy              : the pinned vulnerable packages in requirements.txt
  * quality            : the too-many-parameters + high-complexity function

DO NOT copy any of this into real code. It exists only to prove the scanners
are alive (guards against silent engine death like the pkg_resources bug).
"""
import os
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

# Hardcoded secrets (secrets detectors + semgrep should flag these).
API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc0000000000"
STRIPE_SECRET_KEY = "sk_test_51H8xExampleFakeStripeKey1234567890abcd"


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # SQL injection: user input concatenated straight into the query.
    cur.execute("SELECT * FROM users WHERE id = " + user_id)
    return cur.fetchall()


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Command injection: unsanitized user input into a shell command.
    os.system("ping -c 1 " + host)
    subprocess.call("nslookup " + host, shell=True)
    return "ok"


@app.route("/run")
def run_code():
    code = request.args.get("code")
    # Code injection: eval of attacker-controlled input.
    return str(eval(code))


def configure(alpha, beta, gamma, delta, epsilon, zeta, eta):
    """Too many parameters + branchy body — a quality smell."""
    total = 0
    for i in range(alpha):
        if i % 2 == 0:
            total += beta
        elif i % 3 == 0:
            total += gamma
        elif i % 5 == 0:
            total += delta
        else:
            total += epsilon
    return total + zeta + eta


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
