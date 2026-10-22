"""Pass N5 decisions for build_ledger.py: corpus commits and scan names, the re-scoring
of N4 items that N5's rule changes reached (each read in code), and verdicts for findings
on ground-truth corpora that no earlier pass triaged. Reasons: docs/GROUND_TRUTH_N5.md.
"""
N4_COMMITS = {
    "go-test-bench": "92445700823205281369911a72b7127f18c8c9ed", "govwa": "4058f79f31eeb4a36d8f1e64bba1f0c899646e6f",
    "dvga-go": "9f0d051ef819370ec78c4ad9fd6c15d122984054", "damn-vulnerable-golang": "fad5655a69879d37010b40044a5d4f4d305ee916",
    "not-going-anywhere": "3ea1a49de1c399633e513f0348752b7f0098b7c1", "pygoat": "46fef968f3f44d1191363baf936aaa3335dc5c6d",
    "dsvw": "9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908", "dvgraphql": "a961308c02d1fb462b192681c336b0739e432da7",
    "django-nv": "a48901f106da4888417339b7b44b8ed56b64c63f", "lets-be-bad-guys": "7cbf11014bfc6dc9e199dc0b8a64e4597bc2338f",
    "dvpwa-full": "a1d8f89fac2e57093189853c6527c2b01fc1d9c1", "vulnerableapp": "d80329e5f34975924e1e21b9d48749149b31c6a3",
    "java-sec-code": "4711f4e186258c6e0dd5c3863e7c9592e7e9026a", "dvja": "597ece1ab79ffffea7289d49b0c443bb2ebcbd16",
    "javavulnerablelab": "626a106a49777507beb51955d19ef9d271a9d4a5", "javulna": "56f2102420a066a94152c99454fd4091aaeb4044",
    "securityshepherd": "cff3958abf7a18cfc84fe6bed9dd6698631b2cee",
}
# (ledger corpus, final scan file, keys earlier verdict files use for the same commit)
GT_SCANS = [(c, c, [c, "dvpwa"] if c == "dvpwa-full" else [c]) for c in N4_COMMITS] + [
    ("nodegoat", "NodeGoat", ["NodeGoat", "OWASP__NodeGoat"]),
    ("juice-shop", "juice-shop", ["juice-shop", "juice-shop__juice-shop"]),
    ("dvwa", "DVWA", ["DVWA"]),
    ("webgoat", "WebGoat", ["WebGoat"]),
]
REAL = {"Dolibarr__dolibarr", "FreshRSS__FreshRSS", "chatwoot__chatwoot", "getredash__redash",
        "jellyfin__jellyfin", "librenms__librenms", "mastodon__mastodon", "nilsteampassnet__TeamPass",
        "nocodb__nocodb", "nopSolutions__nopCommerce", "spring-petclinic"} | {
    f"cmp-{n}" for n in ("ansible", "cobra", "consul", "django", "express", "fastapi", "flask", "gin", "guava",
                         "jackson", "kafka", "nest", "netty", "nextauth", "prisma", "react", "spring", "terraform", "vault")}

DET, GAP, CEIL = "DET", "GAP", "CEIL"
JX, JS = "aegis-java-xss", "aegis-java-sql-injection"
PC, PD, PF = "aegis-py-command-injection", "aegis-py-unsafe-deserialization", "aegis-py-flask-debug-enabled"
# (corpus, item id) -> (status, rules, reason). Each read in code on the final N5 scan.
OVERRIDES = {
    # tuning corpora -- the gaps N5's rules were written from
    ("pygoat", "cmd-lab1"): (DET, [PC], "shell=True no longer needs to be the last argument (N5)"),
    ("pygoat", "insec-des"): (DET, [PD], "pickle.loads of base64-decoded form data (N5 rule)"),
    ("pygoat", "integrity-lab1"): (DET, [PD], "pickle.loads of a cookie (N5 rule)"),
    ("pygoat", "a9-yaml"): (DET, [PD], "yaml.load(Loader=yaml.Loader) of an uploaded file (N5 rule)"),
    ("pygoat", "sde-debug"): (DET, [PF], "app.config['DEBUG'] = True (N5 rule)"),
    ("pygoat", "misconfig-lab2"): (DET, [PF], "app.debug = True and app.run(debug=True) (N5 rule)"),
    ("pygoat", "ba-debug"): (DET, [PF], "app.run(debug=True) at broken_auth_lab/app.py:147 (N5 rule)"),
    **{("vulnerableapp", i): (DET, [JS], "JdbcTemplate.query/queryForObject with concatenated SQL (N5 sink)") for i in (
        "BLIND_SQL_INJECTION@getCarInformationLevel1:88", "BLIND_SQL_INJECTION@getCarInformationLevel2:129",
        "UNION_BASED_SQL_INJECTION@getCarInformationLevel1:81", "UNION_BASED_SQL_INJECTION@getCarInformationLevel2:111",
        "ERROR_BASED_SQL_INJECTION@doesCarInformationExistsLevel1:76",
        "ERROR_BASED_SQL_INJECTION@doesCarInformationExistsLevel2:136",
        "ERROR_BASED_SQL_INJECTION@doesCarInformationExistsLevel3:197")},
    ("vulnerableapp", "REFLECTED_XSS@getVulnerablePayloadLevel1:62"): (DET, [JX], "ResponseEntity<String> body (N5 sink)"),
    ("vulnerableapp", "REFLECTED_XSS@getVulnerablePayloadLevel2:87"): (DET, [JX], "ResponseEntity<String> body (N5 sink)"),
    **{("vulnerableapp", f"PERSISTENT_XSS@getVulnerablePayloadLevel{n}:{ln}"): (
        DET, [JX], "ResponseEntity<String> body of the stored comments (N5 sink; through the getCommentsPayload helper)")
       for n, ln in ((1, 111), (2, 135), (3, 163), (4, 194), (5, 226), (6, 260))},
    # held-out -- generalisation, counted
    ("java-sec-code", "XSS"): (DET, [JX], "the stored-XSS endpoint returns the cookie from an @ResponseBody String (N5 sink), XSS.java:58"),
}
# Verdicts for ground-truth findings no earlier pass triaged.
SEQ = "Sequelize findOne/update with a request value: an authorization (IDOR) issue at most; Sequelize treats object keys as values, not operators"
GT_DEFAULT = {   # (corpus, rule) -> (verdict, why)
    ("nodegoat", "aegis-js-code-injection"): ("TP", "GT1 eval(req.body.*)"),
    ("nodegoat", "aegis-js-nosql-where-injection"): ("TP", "GT2 $where"),
    ("nodegoat", "aegis-js-redos-nested-quantifier"): ("TP", "GT7 ReDoS"),
    ("juice-shop", "aegis-js-nosql-injection"): ("FP", SEQ),
    ("juice-shop", "aegis-js-xss"): ("FP", "JSON or text/event-stream body, not HTML"),
    ("dvwa", "aegis-php-command-injection"): ("TP", "ping built from the request at this security level"),
    ("dvwa", "aegis-php-sql-injection"): ("TP", "query concatenated from the request at this security level"),
    ("dvwa", "aegis-php-path-traversal"): ("TP", "file path built from raw $_GET['id'] (help / source viewers)"),
    ("dvwa", "aegis-php-xss"): ("TP", "JSONP callback reflected"),
    ("webgoat", "aegis-java-sql-injection"): ("TP", "documented SQLi lesson"),
    ("webgoat", "aegis-java-ssrf"): ("TP", "GT SSRF JKU"),
    ("webgoat", "aegis-java-path-traversal"): ("TP", "GT path traversal"),
    ("pygoat", PF): ("TP", "the lab app is started with debug mode on"),
    ("pygoat", PD): ("TP", "request data deserialized"),
    ("pygoat", PC): ("TP", "shell=True command from request data"),
    ("vulnerableapp", JS): ("TP", "JdbcTemplate SQL concatenated from the request"),
    ("vulnerableapp", JX): ("TP", "request data in a ResponseEntity<String> body"),
}
GT_VERDICTS = {  # (corpus, file-suffix, line, rule) -> (verdict, why)
    **{("juice-shop", f"codefixes/chatbotGreedyInjectionChallenge_{n}.ts", ln, "aegis-js-nosql-where-injection"):
       ("TP", "wrong-fix variant: $where still concatenated") for n, ln in ((1, 65), (3, 66), (4, 66))},
    ("juice-shop", "codefixes/chatbotGreedyInjectionChallenge_2_correct.ts", 66, "aegis-js-nosql-where-injection"): ("FP", "the correct fix variant"),
    **{("juice-shop", f, ln, "aegis-js-sql-injection"): ("TP", "wrong-fix variant / documented SQLi") for f, ln in (
        ("codefixes/dbSchemaChallenge_1.ts", 5), ("codefixes/dbSchemaChallenge_3.ts", 11),
        ("codefixes/unionSqlInjectionChallenge_1.ts", 6), ("codefixes/unionSqlInjectionChallenge_3.ts", 10),
        ("routes/login.ts", 34), ("routes/search.ts", 23))},
    ("juice-shop", "routes/chat.ts", 149, "aegis-js-nosql-where-injection"): ("TP", "$where concatenated from a tool-call argument the prompt controls"),
    ("juice-shop", "routes/showProductReviews.ts", 36, "aegis-js-nosql-where-injection"): ("FP", "$where with Number(id): numeric, not injectable"),
    ("juice-shop", "routes/showProductReviews.ts", 36, "aegis-js-nosql-injection"): ("FP", "$where with Number(id): numeric, not injectable"),
    ("juice-shop", "routes/trackOrder.ts", 18, "aegis-js-nosql-where-injection"): ("TP", "$where from the raw order id while the challenge is enabled"),
    ("juice-shop", "routes/trackOrder.ts", 18, "aegis-js-nosql-injection"): ("TP", "$where from the raw order id while the challenge is enabled"),
    ("juice-shop", "routes/userProfile.ts", 65, "aegis-js-code-injection"): ("TP", "eval of the username template (documented SSTI)"),
    ("juice-shop", "routes/userProfile.ts", 101, "aegis-js-xss"): ("TP", "pug template compiled with the username"),
    ("juice-shop", "routes/profileImageFileUpload.ts", 42, "aegis-js-path-traversal"): ("FP", "path from the user id and a detected file type"),
    ("juice-shop", "routes/profileImageUrlUpload.ts", 24, "aegis-js-ssrf"): ("TP", "server fetches a request URL"),
    ("juice-shop", "routes/vulnCodeFixes.ts", 81, "aegis-js-path-traversal"): ("FP", "key checked against the known challenges first"),
    ("juice-shop", "routes/vulnCodeSnippet.ts", 90, "aegis-js-path-traversal"): ("FP", "key checked against the known challenges first"),
    **{("juice-shop", f"codefixes/{c}.ts", 5 if c != "noSqlReviewsChallenge_1" else 11, "aegis-js-nosql-injection"):
       ("TP", "wrong-fix variant: _id from the body (operator injection)") for c in (
        "forgedReviewChallenge_1", "forgedReviewChallenge_3", "noSqlReviewsChallenge_1", "noSqlReviewsChallenge_2")},
    ("juice-shop", "codefixes/forgedReviewChallenge_2_correct.ts", 5, "aegis-js-nosql-injection"): ("FP", "the correct fix variant"),
    ("juice-shop", "codefixes/noSqlReviewsChallenge_3_correct.ts", 11, "aegis-js-nosql-injection"): ("FP", "the correct fix variant"),
    **{("juice-shop", "routes/likeProductReviews.ts", ln, "aegis-js-nosql-injection"): ("TP", "MarsDB _id from the body (operator injection)")
       for ln in (25, 36, 43, 51)},
    ("juice-shop", "routes/updateProductReviews.ts", 18, "aegis-js-nosql-injection"): ("TP", "documented noSqlReviews / forgedReview vuln-line"),
    ("dvwa", "instructions.php", 26, "aegis-php-path-traversal"): ("FP", "file chosen from an allow-list"),
    ("dvwa", "exec/source/impossible.php", 22, "aegis-php-command-injection"): ("FP", "impossible level: octets validated and rebuilt"),
    ("dvwa", "exec/source/impossible.php", 26, "aegis-php-command-injection"): ("FP", "impossible level: octets validated and rebuilt"),
    ("dvwa", "bac/source/medium.php", 22, "aegis-php-sql-injection"): ("FP", "id must match ^[0-9]+$ first"),
    ("dvwa", "bac/source/medium.php", 29, "aegis-php-sql-injection"): ("FP", "id must match ^[0-9]+$ first"),
    ("dvwa", "bac/source/medium.php", 73, "aegis-php-sql-injection"): ("UNCERTAIN", "log query; inputs not fully traced"),
    ("dvwa", "api/src/HealthController.php", 88, "aegis-php-command-injection"): ("TP", "API health check pings a request value"),
    ("vulnerableapp", "BlindSQLInjectionVulnerability.java", 185, JS): ("FP", "SECURE level: the id must match \\d+ first"),
    ("vulnerableapp", "UnionBasedSQLInjectionVulnerability.java", 130, JS): ("FP", "SECURE level: quotes stripped inside a quoted literal"),
    **{("vulnerableapp", "PersistentXSSInHTMLTagVulnerability.java", ln, JX): ("FP", why) for ln, why in (
        (295, "level 7: the helper applies escapeHtml4 to every comment"),
        (326, "SECURE level 8: input containing < or > is rejected first"),
        (348, "SECURE level 9: the helper applies htmlEscapeHex"))},
    ("java-sec-code", "controller/Fastjson.java", 24, JX): ("TP", "a request JSON field returned as a String body"),
    ("java-sec-code", "controller/FileUpload.java", 154, JX): ("TP", "the uploaded file's original name returned in a String body"),
    ("java-sec-code", "controller/IPForge.java", 36, JX): ("UNCERTAIN", "an X-Real-IP header reflected: a browser cannot set it cross-site"),
    ("java-sec-code", "controller/XSS.java", 58, JX): ("TP", "documented stored XSS: the cookie returned as the body"),
    ("django-nv", "highlight.pack.js", 1, "ajinabraham.njsscan.xss.xss_dom.dom_xss"): ("FP", "vendored minified highlighter"),
    ("dvgraphql", "static/jquery/graphql.js", 1, "ajinabraham.njsscan.ssrf.ssrf_node.node_ssrf"): ("FP", "vendored minified client library"),
    ("webgoat", "webwolf/FileServer.java", 95, "aegis-java-path-traversal"): ("FP", "fires on log.debug(new File(...)); the sink is at :91-93 (N1 C.4)"),
}
