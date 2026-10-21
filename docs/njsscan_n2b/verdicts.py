"""N2b hand-triage verdicts (copied from the out-of-repo working dir E:/n2bwork; the
paths below refer to it) for all 475 njsscan findings (V2 + F1 corpora).

Every finding was read in its source at the scanned commit (show.py). The per-rule
default below is the verdict for every finding of that rule NOT listed in OVERRIDES;
each default was checked finding by finding, not assumed. Confidence: high / medium /
low. Root-cause groups (RC*) are defined in ROOT_CAUSES.

Writes verdicts.json and prints the per-rule table (python verdicts.py).
"""
import collections
import json

ROOT_CAUSES = {
    "RC1": "provenance-blind source: $REQ/$RES are unconstrained metavariables, so any 2-parameter "
           "function is a 'request handler' and any a.b is 'request data' (dom_xss: the page's own "
           "DOM text/attributes are treated as attacker input)",
    "RC2": "sink never inspected: the dangerous property (a catastrophic regex; an HTML output "
           "context) is never checked",
    "RC3": "API/identifier name flagged without context (Math.random, a variable named *user*/*key*/"
           "*secret*/*password*, a comparison involving 'password'/'token')",
    "RC4": "framework idiom misread: Sequelize findOne({where}) treated as a Mongo query",
    "RC5": "not a vulnerability by construction: 'good' rules report a control that IS present",
    "RC6": "flags logging/console output, not disclosure to a client",
    "RC7": "value is server configuration, not attacker input",
    "RC8": "fires inside vendored/minified third-party code (no first-party decision possible)",
}

# rule -> (default verdict, confidence, root cause or None)
DEFAULT = {
    "regex_dos": ("FP", "high", "RC1+RC2"),
    "node_insecure_random_generator": ("FP", "high", "RC3"),
    "node_username": ("FP", "high", "RC3"),
    "node_api_key": ("FP", "high", "RC3"),
    "node_secret": ("FP", "high", "RC3"),
    "node_password": ("FP", "high", "RC3"),
    "generic_error_disclosure": ("FP", "high", "RC6"),
    "node_nosqli_injection": ("FP", "high", "RC4"),
    "node_timing_attack": ("FP", "high", "RC3"),
    "eval_nodejs": ("FP", "high", "RC1"),
    "regex_injection_dos": ("FP", "high", "RC1"),
    "dom_xss": ("FP", "high", "RC1"),
    "express_open_redirect": ("FP", "medium", "RC7"),
    "node_md5": ("FP", "high", "RC3"),
    "node_nosqli_js_injection": ("TP", "high", None),
    "eval_require": ("FP", "high", "RC1"),
    "express_lfr_warning": ("FP", "high", "RC1"),
    "node_logic_bypass": ("FP", "high", "RC3"),
    "helmet_header_feature_policy": ("FP", "high", "RC5"),
    "helmet_header_frame_guard": ("FP", "high", "RC5"),
    "helmet_header_nosniff": ("FP", "high", "RC5"),
    "helmet_header_x_powered_by": ("FP", "high", "RC5"),
    "cookie_session_default": ("TP", "high", None),
    "cookie_session_no_samesite": ("TP", "high", None),
    "cookie_session_no_secure": ("TP", "high", None),
    "express_cors": ("TP", "medium", None),
    "generic_cors": ("TP", "medium", None),
    "node_ssrf": ("TP", "high", None),
    "express_xss": ("UNCERTAIN", "low", None),
    "handlebars_noescape": ("FP", "medium", "RC2"),
}

# id -> (verdict, confidence, note)
OVERRIDES = {
    # node_insecure_random_generator
    4: ("TP", "medium", "FreshRSS extra.js poormanSalt: Math.random bcrypt-salt fallback"),
    36: ("TP", "medium", "juice-shop insecurity.ts denyAll: JWT secret from Math.random"),
    64: ("TP", "high", "nocodb useOAuthPopup.ts: OAuth `state` (CSRF token) from Math.random"),
    47: ("UNCERTAIN", "low", "TeamPass CreateRandomString: client-side request token"),
    50: ("UNCERTAIN", "low", "TeamPass CreateRandomString (copy): client-side request token"),
    # node_md5
    73: ("TP", "high", "juice-shop insecurity.ts hash(): md5 used for password hashing"),
    75: ("FP", "medium", "nocodb socket.gateway getHash: md5 of a telemetry client id"),
    # node_timing_attack
    86: ("TP", "medium", "nocodb users.service: invite token compared with !== server-side"),
    # node_nosqli_injection
    98: ("TP", "high", "juice-shop likeProductReviews: marsdb findOne({_id: req.body.id})"),
    99: ("TP", "high", "juice-shop likeProductReviews: marsdb findOne({_id: req.body.id})"),
    # node_password
    419: ("TP", "medium", "juice-shop login.component: hardcoded testingPassword literal"),
    # eval_nodejs: NodeGoat GT1 (three lines)
    372: ("TP", "high", "NodeGoat GT1 eval(req.body.preTax)"),
    373: ("TP", "high", "NodeGoat GT1 eval(req.body.afterTax)"),
    374: ("TP", "high", "NodeGoat GT1 eval(req.body.roth)"),
    # dom_xss
    470: ("FP", "medium", "FreshRSS integration.js: share template built from its own DOM"),
    472: ("UNCERTAIN", "low", "librenms popup.js: data-popup-content attribute -> innerHTML"),
    469: ("FP", "high", "vendored minified highlight.js"),
    # express_open_redirect
    461: ("TP", "high", "NodeGoat GT3 res.redirect(req.query.url)"),
    462: ("TP", "medium", "nocodb Noco.ts: redirect(req.path.slice(...)) -> '//evil.com' is protocol-relative"),
}

VENDORED = ("/includes/", "/plugins/", "/lib_npm/", "/vendor/", ".min.js", "/wwwroot/lib")

if __name__ == "__main__":
    rows = json.load(open("E:/n2bwork/findings.json"))
    out = []
    for r in rows:
        rule = r["rule"].split(".")[-1]
        v, c, rc = DEFAULT[rule]
        note = ""
        if r["id"] in OVERRIDES:
            v, c, note = OVERRIDES[r["id"]]
            rc = None if v != "FP" else rc
        if v == "FP" and any(s in r["file"] for s in VENDORED):
            rc = (rc + "+RC8") if rc else "RC8"
        out.append({**r, "rule_short": rule, "verdict": v, "confidence": c, "root_cause": rc, "note": note})
    json.dump(out, open("E:/n2bwork/verdicts.json", "w"), indent=0)

    by = collections.defaultdict(collections.Counter)
    for o in out:
        by[o["rule_short"]][o["verdict"]] += 1
    tot = collections.Counter(o["verdict"] for o in out)
    print(f"{'rule':34s} {'n':>4s} {'TP':>3s} {'FP':>4s} {'UNC':>3s}  TP-rate  note")
    for rule, c in sorted(by.items(), key=lambda kv: (-(kv[1]['TP'] / sum(kv[1].values())), -sum(kv[1].values()))):
        n = sum(c.values())
        dec = c["TP"] + c["FP"]
        rate = c["TP"] / dec if dec else 0
        print(f"{rule:34s} {n:4d} {c['TP']:3d} {c['FP']:4d} {c['UNCERTAIN']:3d}  {rate:6.0%}   {'n<5' if n < 5 else ''}")
    dec = tot["TP"] + tot["FP"]
    print(f"\nALL {sum(tot.values())}: TP {tot['TP']} FP {tot['FP']} UNC {tot['UNCERTAIN']}  "
          f"TP rate {tot['TP'] / dec:.1%} (UNC excluded); bounds {tot['TP'] / sum(tot.values()):.1%}"
          f"-{(tot['TP'] + tot['UNCERTAIN']) / sum(tot.values()):.1%}")
    rc = collections.Counter()
    for o in out:
        if o["verdict"] == "FP":
            for x in (o["root_cause"] or "unclassified").split("+"):
                rc[x] += 1
    print("\nFP root causes (a finding can carry two):")
    for k, n in rc.most_common():
        print(f"  {k:12s} {n:4d}  {ROOT_CAUSES.get(k, '')[:100]}")
    fp_ = [o for o in out if not any(s in o["file"] for s in VENDORED)]
    t = collections.Counter(o["verdict"] for o in fp_)
    print(f"\nfirst-party only: {len(fp_)} findings, TP {t['TP']} FP {t['FP']} UNC {t['UNCERTAIN']} -> "
          f"{t['TP'] / (t['TP'] + t['FP']):.1%}")
    vend = sum(1 for o in out if any(s in o["file"] for s in VENDORED))
    print(f"\nfindings in vendored/minified third-party paths: {vend}/{len(out)}")
