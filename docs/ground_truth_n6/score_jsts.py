"""Pass N6: score the JS/TS corpora (jsts_items.py) on the N6 scans and triage every
security finding. Statuses were read in code: DET needs a TRUE-POSITIVE finding of the
item's class at the item (or the helper it documents); CEIL is an engine ceiling
(template-side, client-side, cross-function); GAP is a rule gap.

usage: python score_jsts.py <scan_dir> <out.json>
"""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jsts_items as J  # noqa: E402

DET, GAP, CEIL = "DET", "GAP", "CEIL"
# (corpus, item id) -> (status, catching rules, reason)
STATUS = {
    "dvna": {
        "sqli": (DET, ["aegis-js-sql-injection"], ""),
        "cmdi": (DET, ["aegis-js-command-injection"], ""),
        "sensitive-logging": (GAP, [], "no sensitive-logging rule"),
        "xxe": (DET, ["ajinabraham.njsscan.xml.xxe_node.node_xxe"], ""),
        "xss-reflected": (CEIL, [], "template-side: <%- %> in an .ejs view"),
        "xss-stored": (CEIL, [], "template-side and second-order"),
        "xss-dom": (CEIL, [], "client-side innerHTML"),
        "deserialization": (DET, ["ajinabraham.njsscan.eval.eval_deserialize.node_deserialize"], ""),
        "redirect": (DET, ["ajinabraham.njsscan.redirect.open_redirect.express_open_redirect"], ""),
    },
    "vulnerable-node": {
        "02-ssrf": (DET, ["aegis-js-ssrf"], "routes/tools.js:21"),
        "03-sqli-login": (CEIL, [], "SQL built in model/db.js from function arguments (cross-function)"),
        "03-sqli-search": (CEIL, [], "SQL built in model/db.js from function arguments (cross-function)"),
        "03-sqli-sort": (CEIL, [], "SQL built in model/db.js from function arguments (cross-function)"),
        "03b-nosql": (DET, ["aegis-js-nosql-injection"], "routes/shop.js:41,58"),
        "05-xss": (CEIL, [], "template-side: <%- %> in an .ejs view"),
        "08-pan": (GAP, [], "no cleartext-storage rule"),
        "09-debug": (GAP, [], "no Express debug / verbose-error rule"),
        "10-secrets-in-logs": (GAP, [], "no sensitive-logging rule"),
        "10-log-injection": (GAP, [], "no log-injection rule"),
        "13-prototype-pollution": (GAP, [], "no prototype-pollution rule"),
        "14-redos": (DET, ["ajinabraham.njsscan.dos.regex_injection.regex_injection_dos"], "user-controlled pattern, routes/tools.js:41"),
        "15-path-traversal": (DET, ["aegis-js-path-traversal"], ""),
        "16-cmdi": (DET, ["aegis-js-command-injection"], ""),
    },
    "dvws-node": {
        "01-sqli": (DET, ["aegis-js-sql-injection"], ""),
        "02-nosql": (DET, ["aegis-js-nosql-where-injection"], ""),
        "03-cmdi": (DET, ["aegis-js-command-injection"], ""),
        "04-xxe": (GAP, [], "the SOAP library's parser is not a modelled XXE sink"),
        "06-ssrf": (DET, ["ajinabraham.njsscan.ssrf.ssrf_node.node_ssrf"], ""),
        "07-deserialization": (DET, ["ajinabraham.njsscan.eval.eval_deserialize.node_deserialize"], ""),
        "08-xpath": (GAP, [], "no XPath rule"),
        "09-ldap": (GAP, [], "no JS LDAP finding (ldapjs filter not a modelled sink)"),
        "10-path-traversal": (DET, ["ajinabraham.njsscan.traversal.resolve_path_traversal.join_resolve_path_traversal"], ""),
        "11-soap-injection": (GAP, [], "no SOAP / XML-injection rule"),
        "12-xml-injection-export": (GAP, [], "no XML-injection rule (an XSS finding at the same response is a different class)"),
        "20-open-redirect": (DET, ["ajinabraham.njsscan.redirect.open_redirect.express_open_redirect"], ""),
        "21-xss": (DET, ["aegis-js-xss"], "the SOAP XML response, user-service.js:73"),
        "23-cors": (GAP, [], "no CORS rule"),
        "24-log-pollution": (GAP, [], "no log-injection rule"),
        "28-prototype-pollution": (GAP, [], "no prototype-pollution rule"),
        "34-gql-file-write": (GAP, [], "GraphQL resolver arguments are not a modelled source"),
        "37-upload": (GAP, [], "no upload rule"),
        "41-cookie": (GAP, [], "res.cookie options built by a helper; no finding"),
        "44-ssti": (DET, ["aegis-js-code-injection"], "the template is compiled with new Function"),
        "45-yaml": (DET, ["ajinabraham.njsscan.eval.eval_yaml_deserialize.yaml_deserialize"], ""),
        "46-report-path": (DET, ["aegis-js-path-traversal"], ""),
    },
    "oopssec-store": {
        "cross-site-scripting-xss": (CEIL, [], "rendered client-side (React)"),
        "insecure-randomness-gift-card": (GAP, [], "Math.random in a library function; weak-random rule needs a secret-shaped receiver in the same scope"),
        "malicious-file-upload": (GAP, [], "Next.js App Router request (formData) is not a modelled source"),
        "open-redirect": (CEIL, [], "client-side (router.push in a React component)"),
        "path-traversal": (GAP, [], "Next.js App Router request (nextUrl.searchParams) is not a modelled source"),
        "plaintext-password-in-logs": (GAP, [], "no sensitive-logging rule"),
        "product-search-sql-injection": (GAP, [], "Prisma $queryRawUnsafe is not a modelled sink; App Router source not modelled"),
        "second-order-sql-injection": (CEIL, [], "second-order"),
        "self-xss-profile-injection": (CEIL, [], "rendered client-side (React)"),
        "server-side-request-forgery": (GAP, [], "Next.js App Router request is not a modelled source"),
        "sql-injection": (GAP, [], "Prisma $queryRawUnsafe is not a modelled sink; App Router source not modelled"),
        "weak-md5-hashing": (DET, ["ajinabraham.njsscan.crypto.crypto_node.node_md5"], "hashMD5 in lib/server-auth.ts:15, used for the credential"),
        "x-forwarded-for-sql-injection": (GAP, [], "Prisma $queryRawUnsafe is not a modelled sink; header source not modelled"),
        "xxe-supplier-order-import": (DET, ["ajinabraham.njsscan.xml.xxe_node.node_xxe"], ""),
    },
    "vunapi": {
        "redos": (GAP, [], "NestJS decorator parameters (@Query/@Body) are not a modelled source"),
        "cmdi": (GAP, [], "NestJS decorator parameters (@Query/@Body) are not a modelled source"),
        "sqli": (GAP, [], "NestJS decorator parameters are not a modelled source"),
    },
}

# Triage. DEFAULT per (corpus, rule-suffix); EXCEPT per (corpus, file-suffix, line, rule-suffix).
FP_JSON = "a JSON / object body (or text/plain), not HTML"
FP_SEQ = "Sequelize find with a request value: SQL ORM, values are bound"
FP_LFR = "res.render with a constant template; request data only in the locals"
DEFAULT = {
    ("dvna", "aegis-js-sql-injection"): ("TP", ""), ("dvna", "aegis-js-command-injection"): ("TP", ""),
    ("dvna", "express_open_redirect"): ("TP", ""), ("dvna", "node_deserialize"): ("TP", ""),
    ("dvna", "node_xxe"): ("TP", ""), ("dvna", "sequelize_tls"): ("UNCERTAIN", "database connection without TLS: depends on deployment"),
    ("dvna", "aegis-js-nosql-injection"): ("FP", FP_SEQ), ("dvna", "express_lfr_warning"): ("FP", FP_LFR),
    ("dvna", "cookie_session_no_samesite"): ("TP", "express-session without SameSite"),
    ("dvna", "cookie_session_no_secure"): ("TP", "express-session without Secure"),
    ("dvna", "cookie_session_default"): ("TP", "default session cookie name"),
    ("vulnerable-node", "express_lfr_warning"): ("FP", FP_LFR),
    ("vulnerable-node", "aegis-js-command-injection"): ("TP", ""), ("vulnerable-node", "generic_os_command_exec"): ("TP", ""),
    ("vulnerable-node", "aegis-js-code-injection"): ("TP", ""), ("vulnerable-node", "eval_nodejs"): ("TP", ""),
    ("vulnerable-node", "aegis-js-ssrf"): ("TP", ""), ("vulnerable-node", "regex_injection_dos"): ("TP", ""),
    ("vulnerable-node", "aegis-js-nosql-injection"): ("TP", "operator objects from the JSON body reach Mongo"),
    ("vulnerable-node", "node_deserialize"): ("TP", ""), ("vulnerable-node", "hardcoded_jwt_secret"): ("TP", ""),
    ("vulnerable-node", "node_md5"): ("TP", "md5 of a password"),
    ("vulnerable-node", "cookie_session_no_samesite"): ("TP", ""), ("vulnerable-node", "cookie_session_no_secure"): ("TP", ""),
    ("vulnerable-node", "aegis-js-path-traversal"): ("TP", ""), ("vulnerable-node", "join_resolve_path_traversal"): ("TP", ""),
    ("dvws-node", "aegis-js-xss"): ("FP", FP_JSON), ("dvws-node", "express_xss"): ("FP", "pattern on an assignment; the value reaches no HTML response"),
    ("dvws-node", "aegis-js-sql-injection"): ("TP", ""), ("dvws-node", "aegis-js-command-injection"): ("TP", ""),
    ("dvws-node", "generic_os_command_exec"): ("TP", ""), ("dvws-node", "aegis-js-nosql-where-injection"): ("TP", ""),
    ("dvws-node", "node_nosqli_js_injection"): ("TP", ""), ("dvws-node", "aegis-js-code-injection"): ("TP", ""),
    ("dvws-node", "eval_nodejs"): ("TP", ""), ("dvws-node", "yaml_deserialize"): ("TP", ""),
    ("dvws-node", "node_deserialize"): ("TP", ""), ("dvws-node", "aegis-js-path-traversal"): ("TP", ""),
    ("dvws-node", "join_resolve_path_traversal"): ("TP", ""), ("dvws-node", "express_open_redirect"): ("TP", ""),
    ("dvws-node", "node_ssrf"): ("TP", ""),
    ("dvws-node", "node_nosqli_injection"): ("FP", "the value is a string (decoded token, parsed XML or route param)"),
    ("dvws-node", "aegis-js-nosql-injection"): ("FP", "the value is a string (decoded token, parsed XML or route param)"),
    ("oopssec-store", "node_xxe"): ("TP", ""),
    ("oopssec-store", "node_md5"): ("FP", "md5 in a test / seed helper, not a security use"), ("oopssec-store", "aegis-js-redos-nested-quantifier"): ("FP", "each repetition needs a / separator: linear"),
}
_BODY_USER = "username from the JSON body: an operator object reaches Mongoose"
EXCEPT = {
    ("vulnerable-node", "db/init.js", 12, "node_sqli_injection"): ("FP", "runs the bundled init.sql file"),
    ("vulnerable-node", "model/db.js", 114, "node_sqli_injection"): ("TP", "UPDATE column names taken from request body keys"),
    ("vulnerable-node", "middleware/auth.js", 8, "express_open_redirect"): ("FP", "redirects to the app's own /login with the URL encoded"),
    ("vulnerable-node", "routes/auth.js", 34, "express_open_redirect"): ("TP", "documented VULN: redirect target from the request"),
    ("vulnerable-node", "routes/auth.js", 38, "express_open_redirect"): ("FP", "redirects to the app's own /login with the value encoded"),
    ("vulnerable-node", "routes/shop.js", 84, "express_open_redirect"): ("FP", "redirects to the app's own /products/<id>"),
    ("vulnerable-node", "routes/progress.js", 62, "generic_path_traversal"): ("UNCERTAIN", "lab-progress file read; validation not traced"),
    ("vulnerable-node", "routes/progress.js", 62, "join_resolve_path_traversal"): ("UNCERTAIN", "lab-progress file read; validation not traced"),
    ("vulnerable-node", "routes/progress.js", 67, "aegis-js-path-traversal"): ("UNCERTAIN", "lab-progress file read; validation not traced"),
    ("vulnerable-node", "sast/seeds/clean-escaped.js", 14, "express_xss"): ("FP", "the 'clean' seed: escapeHtml applied"),
    ("vulnerable-node", "sast/seeds/clean-escaped.js", 18, "express_open_redirect"): ("FP", "the 'clean' seed"),
    ("vulnerable-node", "sast/seeds/eval-code.js", 16, "express_xss"): ("FP", "new Function, not an HTML response (code injection is the TP here)"),
    ("vulnerable-node", "sast/seeds/eval-code.js", 17, "aegis-js-xss"): ("TP", "the request value is reflected in the response"),
    ("vulnerable-node", "sast/seeds/open-redirect.js", 6, "express_open_redirect"): ("TP", ""),
    ("vulnerable-node", "sast/seeds/path-traversal.js", 12, "aegis-js-xss"): ("FP", "image/png body"),
    ("vulnerable-node", "sast/seeds/ssrf-fetch.js", 14, "aegis-js-xss"): ("FP", "text body of a fetched page"),
    ("vulnerable-node", "sast/seeds/xss-raw-echo.js", 6, "express_xss"): ("TP", ""),
    ("vulnerable-node", "sast/seeds/xss-raw-echo.js", 7, "aegis-js-xss"): ("TP", ""),
    ("vulnerable-node", "sast/seeds/xss-raw-echo.js", 17, "aegis-js-xss"): ("TP", ""),
    ("dvws-node", "services/soap/user-service.js", 73, "aegis-js-xss"): ("TP", "documented XSS in the SOAP response"),
    ("dvws-node", "controllers/users.js", 288, "aegis-js-xss"): ("UNCERTAIN", "an XML body built from request values"),
    **{("dvws-node", "controllers/users.js", ln, r): ("TP", _BODY_USER) for ln in (71, 148, 222)
       for r in ("node_nosqli_injection", "aegis-js-nosql-injection")},
    **{("dvws-node", "controllers/passphrase.js", 85, r): ("TP", _BODY_USER)
       for r in ("node_nosqli_injection", "aegis-js-nosql-injection")},
    ("dvws-node", "controllers/users.js", 398, "node_nosqli_injection"): ("TP", "email from the JSON body"),
    ("dvws-node", "controllers/users.js", 398, "aegis-js-nosql-injection"): ("TP", "email from the JSON body"),
    ("dvws-node", "controllers/users.js", 398, "express_xss"): ("FP", "pattern on a query, no HTML response"),
    ("dvws-node", "controllers/notes.js", 175, "aegis-js-nosql-injection"): ("TP", "the documented $where query"),
    ("oopssec-store", "lib/server-auth.ts", 15, "node_md5"): ("TP", "hashMD5 used for credentials (documented weak MD5 hashing)"),
}

EXT = {".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".ejs": "javascript",
       ".ts": "typescript", ".tsx": "typescript"}


def verdict(corpus, f):
    for (c, suf, ln, rs), (v, why) in EXCEPT.items():
        if c == corpus and f["file"].endswith(suf) and f["line"] == ln and f["rule"].endswith(rs):
            return v, why
    for (c, rs), (v, why) in DEFAULT.items():
        if c == corpus and f["rule"].endswith(rs):
            return v, why
    return "UNTRIAGED", ""


def run(scan_dir):
    items, triage, problems = {}, [], []
    for corpus, c in J.CORPORA.items():
        fs = [f for f in json.load(open(os.path.join(scan_dir, corpus + ".json")))["findings"]
              if f.get("pillar") in (None, "security")]
        tp_rules = collections.defaultdict(set)
        for f in fs:
            v, why = verdict(corpus, f)
            lang = EXT.get(os.path.splitext(f["file"])[1].lower(), "yaml" if f["file"].endswith((".yml", ".yaml")) else "other")
            triage.append({"corpus": corpus, "kind": "ground-truth", "language": lang, "file": f["file"],
                           "line": f["line"], "rule": f["rule"], "verdict": v, "why": why})
            if v == "TP":
                tp_rules[f["rule"]].add(f["file"])
        out = []
        for iid, text, loc, scope in c["items"]:
            st, rules, why = STATUS[corpus].get(iid, ("n/a", [], "")) if scope == "IN" else ("n/a", [], "")
            if scope == "IN" and iid not in STATUS[corpus]:
                problems.append(f"{corpus} {iid}: IN with no status")
            if st == DET and not any(r in tp_rules for r in rules):
                problems.append(f"{corpus} {iid}: DET but no TP finding of {rules}")
            out.append({"id": iid, "item": text, "location": loc, "scope": scope, "status": st,
                        "rules": rules if st == DET else [], "rule_or_reason": why})
        items[corpus] = {"language": c["language"], "commit": c["commit"], "documented_list": c["documented_list"],
                         "licence": c["licence"], "items": out}
    return items, triage, problems


if __name__ == "__main__":
    items, triage, problems = run(sys.argv[1])
    json.dump({"items": items, "triage": triage}, open(sys.argv[2], "w"), indent=1)
    for p in problems:
        print("CHECK", p)
    for t in triage:
        if t["verdict"] == "UNTRIAGED" and t["language"] in ("javascript", "typescript"):
            print("UNTRIAGED", t["corpus"], t["file"], t["line"], t["rule"])
    for c, v in items.items():
        ins = [i for i in v["items"] if i["scope"] == "IN"]
        d = sum(i["status"] == DET for i in ins)
        print(f"{c:16s} in-scope {len(ins):2d} detected {d:2d} ({d / len(ins):.0%})")
    print(collections.Counter((t["language"], t["verdict"]) for t in triage))
