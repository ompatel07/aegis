"""The five original ground-truth corpora (F2/G2/N1 definitions, docs/RULE_REMOVAL_N1.md
C.2), restated item by item with N4's scope taxonomy so the N5 bar can read them.

Scope uses N4's taxonomy: OUT for runtime, authentication, authorization, logic, SCA,
secrets and transport. Status comes from scoring the N4 final scans with N1's matcher
(E:/n1work/gt_score.py). The causes of misses were read from each corpus's source.
dvpwa is not restated here: N4's `dvpwa-full` supersedes it.
"""
COMMITS = {  # the F1 clones every pass since F1 scored
    "nodegoat": "c5cb68a7084e4ae7dcc60e6a98768720a81841e8",
    "juice-shop": "1618a611b173b4bf114028e6e02549950606e29d",
    "dvwa": "5d5c76cced604e54462b13723f5c69af58e78748",
    "webgoat": "38096af4c90d74a770b1162edbd2259fcc03d20a",
}
D = "DET"
ITEMS = {
    "nodegoat": ("javascript", "F2 §B.2 GT1-GT7 (NodeGoat's own 'the Fix:' comments)", [
        ("GT1", "server-side JS eval", "app/routes/contributions.js:32", "IN", D, ["aegis-js-code-injection", "ajinabraham.njsscan.eval.eval_node.eval_nodejs"], ""),
        ("GT2", "NoSQL $where injection", "app/data/allocations-dao.js:78", "IN", D, ["aegis-js-nosql-where-injection"], ""),
        ("GT3", "open redirect", "app/routes/index.js:72", "IN", D, ["ajinabraham.njsscan.redirect.open_redirect.express_open_redirect"], ""),
        ("GT4", "SSRF", "app/routes/research.js:15", "IN", D, ["ajinabraham.njsscan.ssrf.ssrf_node.node_ssrf"], ""),
        ("GT5", "missing CSRF middleware", "server.js:106", "IN", "GAP", [], "no CSRF-middleware rule"),
        ("GT6", "weak crypto (unencrypted SSN/DOB)", "app/data/profile-dao.js:32", "IN", "GAP", [], "no cleartext-storage rule"),
        ("GT7", "ReDoS", "app/routes/profile.js:59", "IN", D, ["aegis-js-redos-nested-quantifier"], ""),
    ]),
    "juice-shop": ("typescript", "the project's own `vuln-code-snippet vuln-line` markers (25 challenges)", [
        ("accessLogDisclosureChallenge", "access log served by directory listing", "server.ts:300", "IN", "GAP", [], "express directory-listing rule removed in N1"),
        ("adminSectionChallenge", "admin route without guard", "frontend/src/app/app.routing.ts:79", "OUT:authorization", "n/a", [], ""),
        ("changeProductChallenge", "product update without authorization", "server.ts:389", "OUT:authorization", "n/a", [], ""),
        ("chatbotGreedyInjectionChallenge", "chatbot prompt manipulation", "routes/chat.ts:179", "OUT:logic", "n/a", [], ""),
        ("chatbotPromptInjectionChallenge", "chatbot prompt injection", "routes/chat.ts:179", "OUT:logic", "n/a", [], ""),
        ("dbSchemaChallenge", "SQL injection (schema)", "routes/search.ts:23", "IN", D, ["aegis-js-sql-injection"], ""),
        ("directoryListingChallenge", "directory listing", "server.ts:288", "IN", "GAP", [], "express directory-listing rule removed in N1"),
        ("exposedMetricsChallenge", "unauthenticated metrics endpoint", "server.ts:750", "OUT:authorization", "n/a", [], ""),
        ("forgedReviewChallenge", "NoSQL injection (review author)", "routes/updateProductReviews.ts:16", "IN", D, ["aegis-js-nosql-injection"], ""),
        ("localXssChallenge", "DOM XSS (bypassSecurityTrustHtml)", "frontend/src/app/search-result/search-result.component.ts:144", "IN", "CEIL", [], "client-side Angular"),
        ("loginAdminChallenge", "SQL injection (login)", "routes/login.ts:34", "IN", D, ["aegis-js-sql-injection"], ""),
        ("loginBenderChallenge", "SQL injection (login)", "routes/login.ts:34", "IN", D, ["aegis-js-sql-injection"], ""),
        ("loginJimChallenge", "SQL injection (login)", "routes/login.ts:34", "IN", D, ["aegis-js-sql-injection"], ""),
        ("noSqlReviewsChallenge", "NoSQL injection (multi update)", "routes/updateProductReviews.ts:18", "IN", D, ["aegis-js-nosql-injection"], ""),
        ("redirectChallenge", "redirect allow-list bypass", "lib/insecurity.ts:136", "OUT:logic", "n/a", [], ""),
        ("redirectCryptoCurrencyChallenge", "redirect allow-list bypass", "lib/insecurity.ts:124", "OUT:logic", "n/a", [], ""),
        ("registerAdminChallenge", "mass assignment of role", "server.ts:530", "OUT:authorization", "n/a", [], ""),
        ("resetPasswordMortyChallenge", "reset brute force (rate limit)", "server.ts:365", "OUT:logic", "n/a", [], ""),
        ("restfulXssChallenge", "DOM XSS (bypassSecurityTrustHtml)", "frontend/src/app/search-result/search-result.component.ts:111", "IN", "CEIL", [], "client-side Angular"),
        ("scoreBoardChallenge", "hidden route", "frontend/src/app/app.routing.ts:186", "OUT:logic", "n/a", [], ""),
        ("tokenSaleChallenge", "hidden route", "frontend/src/app/app.routing.ts:261", "OUT:logic", "n/a", [], ""),
        ("unionSqlInjectionChallenge", "UNION SQL injection", "routes/search.ts:23", "IN", D, ["aegis-js-sql-injection"], ""),
        ("weakPasswordChallenge", "weak admin password", "models/user.ts:73", "OUT:authentication", "n/a", [], ""),
        ("web3SandboxChallenge", "hidden route", "frontend/src/app/app.routing.ts:239", "OUT:logic", "n/a", [], ""),
        ("xssBonusChallenge", "DOM XSS (bypassSecurityTrustHtml)", "frontend/src/app/search-result/search-result.component.ts:144", "IN", "CEIL", [], "client-side Angular"),
    ]),
    "dvwa": ("php", "G2's six modules (vulnerabilities/<module>/source/low.php)", [
        ("sqli", "SQL injection", "vulnerabilities/sqli/source/low.php", "IN", D, ["aegis-php-sql-injection"], ""),
        ("sqli_blind", "blind SQL injection", "vulnerabilities/sqli_blind/source/low.php", "IN", D, ["aegis-php-sql-injection"], ""),
        ("exec", "command injection", "vulnerabilities/exec/source/low.php", "IN", D, ["aegis-php-command-injection"], ""),
        ("fi", "file inclusion", "vulnerabilities/fi/source/low.php", "IN", "CEIL", [], "low.php sets $file; the include is in fi/index.php (cross-file)"),
        ("xss_r", "reflected XSS", "vulnerabilities/xss_r/source/low.php", "IN", "CEIL", [], "low.php builds $html; index.php prints it (cross-file)"),
        ("xss_s", "stored XSS", "vulnerabilities/xss_s/source/low.php", "IN", "CEIL", [], "second-order: stored, then printed by the page"),
    ]),
    "webgoat": ("java", "G2's six lesson sinks (line windows)", [
        ("SQLi Challenge", "SQL injection", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java:55", "IN", D, ["aegis-java-sql-injection"], ""),
        ("SQLi Servers", "SQL injection (ORDER BY)", "src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/Servers.java:45", "IN", D, ["aegis-java-sql-injection"], ""),
        ("SQLi challenge5", "SQL injection", "src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java:40", "IN", D, ["aegis-java-sql-injection"], ""),
        ("PathTrav retrieval", "path traversal", "src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java:95", "IN", D, ["aegis-java-path-traversal"], ""),
        ("PathTrav FileServer", "path traversal", "src/main/java/org/owasp/webgoat/webwolf/FileServer.java:88", "IN", D, ["aegis-java-path-traversal"], "generous: fires at :95, four lines below the sink (N1 C.2)"),
        ("SSRF JKU", "SSRF", "src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderJKUEndpoint.java:50", "IN", D, ["aegis-java-ssrf"], ""),
    ]),
}
