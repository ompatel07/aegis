"""Pass N6 Part C: CodeQL's detections on the held-out ground truth, decided item by item
by the rule Aegis is scored by -- an alert of the item's class at the item (or at the
helper / route file the corpus documents for it). Read from the SARIF of
codeql_run.sh (CodeQL CLI 2.27.3, security-extended). An item not listed is a MISS.

corpus -> {item id: "query @ file:line"}
"""
DETECTED = {
    "django-nv": {
        "injection": "py/sql-injection @ taskManager/views.py:184",
        "redirects": "py/url-redirection @ taskManager/views.py:387",
    },
    "dsvw": {},  # 0 alerts: DSVW serves requests from a raw http.server handler CodeQL does not model as a source
    "lets-be-bad-guys": {
        "injection-file": "py/path-injection @ badguys/vulnerable/views.py:42",
        "injection-code": "py/code-injection @ badguys/vulnerable/views.py:72",
        "redirect": "py/url-redirection @ badguys/vulnerable/views.py:178",
    },
    "dvja": {
        "sqli": "java/sql-injection @ services/UserService.java:75",
        "cmdi": "java/command-line-injection @ controllers/PingAction.java:46",
        "log-password": "java/sensitive-log @ services/UserService.java:93",
    },
    "dvna": {
        "sqli": "js/sql-injection @ core/appHandler.js:11",
        "cmdi": "js/command-line-injection @ core/appHandler.js:39",
        "xxe": "js/xxe @ core/appHandler.js:235",
        "xss-reflected": "js/xss @ views/app/products.ejs:20",
        "deserialization": "js/code-injection @ core/appHandler.js:218 (node-serialize unserialize)",
        "redirect": "js/server-side-unvalidated-url-redirection @ core/appHandler.js:188",
    },
    "vulnerable-node": {
        "02-ssrf": "js/request-forgery @ routes/tools.js:21",
        "03-sqli-login": "js/sql-injection @ model/db.js:14 (across the route -> model call)",
        "03-sqli-search": "js/sql-injection @ model/db.js:26",
        "03-sqli-sort": "js/sql-injection @ model/db.js:101",
        "03b-nosql": "js/sql-injection (NoSQL, CWE-943) @ routes/shop.js:41,58",
        "09-debug": "js/stack-trace-exposure @ routes/shop.js:26 (a file the lab documents)",
        "10-secrets-in-logs": "js/clear-text-logging @ routes/auth.js:23",
        "10-log-injection": "js/log-injection @ routes/pages.js:26",
        "13-prototype-pollution": "js/prototype-pollution-utility @ model/merge.js:14",
        "14-redos": "js/regex-injection @ routes/tools.js:44",
        "15-path-traversal": "js/path-injection @ routes/extras.js:17",
        "16-cmdi": "js/command-line-injection @ routes/extras.js:33",
    },
    "damn-vulnerable-golang": {
        "G304": "go/path-injection @ main.go:47",
        "G402": "go/insecure-tls @ main.go:97",
        "G107": "go/request-forgery @ main.go:129",
        "G109": "go/incorrect-integer-conversion @ main.go:138",
    },
    "go-test-bench": {},  # 18 alerts, all go/log-injection: the dispatcher defeats it too
    "not-going-anywhere": {},  # alerts only in the undocumented cmd/web demo N4 excluded
    "oopssec-store": {
        "weak-md5-hashing": "js/insufficient-password-hash @ lib/server-auth.ts:15",
    },
    "vunapi": {
        "redos": "js/redos @ noauth/src/api/redos/redos.controller.ts:11",
        "cmdi": "js/command-line-injection @ noauth/src/api/cmdinject/cmdinject.controller.ts:13",
    },
}
