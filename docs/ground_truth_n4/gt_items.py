"""(Copied from the out-of-repo working dir E:/n4work; paths refer to it.)
N4 ground-truth items for every qualifying corpus, with scope, detection and miss
class. Each corpus's list is the project's OWN published list (README table, in-app
tutorials, solution docs, code annotations, route registry, menu). Statuses were
assigned by reading the code at the documented location (see docs/GROUND_TRUTH_N4.md).

S = (id, documented item, location, scope, status, rule-or-reason)
  scope:  IN | OUT:<why> | CONST (documented, but no attacker input exists in the code as
          written -- scored only in the strict count)
  status: DET | GAP (rule gap, closeable) | CEIL (engine ceiling: cross-function/file,
          template, unparsed language, second-order) | n/a
"""
import json

GT = {}
GT["damn-vulnerable-golang"] = ("go", "in-code CWE annotations (main.go)", [
    ("G101", "hard-coded credentials", "main.go:26", "OUT:secrets pillar, not SAST", "n/a", ""),
    ("G501a", "md5 of a constant", "main.go:36", "CONST", "GAP", "no purpose: md5(\"test\")"),
    ("G304", "path traversal", "main.go:46", "IN", "DET", "aegis-go-path-traversal"),
    ("G204", "command from a constant", "main.go:60", "CONST", "GAP", "constant command string"),
    ("G104", "errors unhandled", "main.go:64", "OUT:reliability", "n/a", ""),
    ("G201", "SQL from constants", "main.go:76", "CONST", "GAP", "constant query inputs"),
    ("G401", "DES", "main.go:88", "IN", "DET", "aegis-go-weak-cipher"),
    ("G402", "TLS MinVersion SSL 3.0", "main.go:96", "IN", "GAP", "no Go TLS-config rule"),
    ("G404", "math/rand token", "main.go:106", "IN", "GAP", "weak-random rule staged; bare `token`"),
    ("G501b", "RC4", "main.go:114", "IN", "DET", "aegis-go-weak-cipher"),
    ("G107", "SSRF", "main.go:128", "IN", "DET", "aegis-go-ssrf"),
    ("G109", "int16(Atoi) overflow", "main.go:137", "IN", "GAP", "no integer-conversion rule"),
    ("G110", "gzip decompression bomb", "main.go:148", "IN", "GAP", "no decompression rule"),
])
GT["go-test-bench"] = ("go", "route registry (internal/*: common.Route + Sinks)", [
    (f"{c}:{s}", c, f, "IN", "CEIL", "sink receives `in string` from common.GenericHandler; source is in pkg/serve*")
    for c, s, f in [
        ("Unvalidated Redirect", "redirect", "internal/unvalidated/unvalidated-redirect.go"),
        ("SQL Injection", "sqlite3.exec", "internal/injection/sqli/sql-injection.go"),
        ("Command Injection", "exec.Command", "internal/injection/cmdi/cmd-injection.go"),
        ("Command Injection", "exec.CommandContext", "internal/injection/cmdi/cmd-injection.go"),
        ("Path Traversal", "os.ReadFile", "internal/pathtraversal/path-traversal.go"),
        ("Path Traversal", "os.Open", "internal/pathtraversal/path-traversal.go"),
        ("Path Traversal", "os.WriteFile", "internal/pathtraversal/path-traversal.go"),
        ("Path Traversal", "os.Create", "internal/pathtraversal/path-traversal.go"),
        ("Reflected XSS", "reflectedXss", "internal/xss/xss.go"),
        ("SSRF", "net/http", "internal/ssrf/ssrf.go")]])
GT["govwa"] = ("go", "the app's own menu (templates/template.sidebar.html) -> vulnerability/<class>/", [
    ("SQLI1", "SQLi (uid cookie)", "vulnerability/sqli/function.go:37", "IN", "CEIL", "util.GetCookie + query built in UnsafeQueryGetData"),
    ("SQLI2", "SQLi (uid param)", "vulnerability/sqli/function.go:37", "IN", "CEIL", "handler -> UnsafeQueryGetData"),
    ("XSS1", "reflected XSS", "vulnerability/xss/xss.go:59", "IN", "GAP", "template.HTML(...) is not an aegis-go-xss sink"),
    ("XSS2", "reflected XSS (inline JS)", "vulnerability/xss/xss.go:100", "IN", "GAP", "template.HTML(...) sink"),
    ("IDOR1", "IDOR", "vulnerability/idor/idor.go", "OUT:authorization", "n/a", ""),
    ("IDOR2", "IDOR", "vulnerability/idor/idor.go", "OUT:authorization", "n/a", ""),
    ("CSA", "client-side authentication", "vulnerability/csa/csa.go", "OUT:authentication", "n/a", ""),
])
GT["dvga-go"] = ("go", "README module table -> internal/modules/<cat>/<module>.go", [
    ("sqli", "SQLi", "internal/modules/injection/sqli.go:52", "IN", "CEIL", "serveSQLi -> sqliEasy(input)"),
    ("sqli-blind", "blind SQLi", "internal/modules/injection/sqli_blind.go", "IN", "CEIL", "serve -> level func"),
    ("cmdi", "command injection", "internal/modules/injection/cmdi.go:55", "IN", "CEIL", "serveCmdI -> cmdiEasy(input)"),
    ("xss-reflected", "reflected XSS", "internal/modules/injection/xss_reflected.go", "IN", "CEIL", "serve -> level func"),
    ("xss-stored", "stored XSS", "internal/modules/injection/xss_stored.go", "IN", "CEIL", "second-order (DB -> render)"),
    ("path-traversal", "path traversal", "internal/modules/brokenac/pathtraversal.go:52", "IN", "CEIL", "serve -> ptEasy(filename)"),
    ("weak-passwd", "MD5 password storage", "internal/modules/crypto/weakpasswd.go:91", "IN", "DET", "aegis-go-weak-hash-credential (promoted in N4)"),
    ("data-exposure", "secrets stored plaintext/base64", "internal/modules/crypto/dataexposure.go:89", "IN", "GAP", "no cleartext-storage rule"),
    ("debug-info", "env vars + stack trace disclosed", "internal/modules/misconfig/debuginfo.go:51", "IN", "GAP", "no info-disclosure rule"),
    ("security-headers", "missing security headers", "internal/modules/misconfig/headers.go", "IN", "GAP", "no Go header rule"),
    ("idor", "IDOR", "internal/modules/brokenac/idor.go", "OUT:authorization", "n/a", ""),
    ("privesc", "privilege escalation", "internal/modules/brokenac/privesc.go", "OUT:authorization", "n/a", ""),
    ("brute-force", "brute force", "internal/modules/insecuredesign/bruteforce.go", "OUT:logic", "n/a", ""),
    ("pwd-reset", "insecure password reset", "internal/modules/insecuredesign/pwdreset.go", "OUT:logic", "n/a", ""),
] + [(f"API{i}", d, "internal/modules/apisec/*", "OUT:authorization/authn/resource", "n/a", "")
     for i, d in [(1, "BOLA (3 scenarios)"), (2, "broken authentication (2)"), (3, "BOPLA (3)"),
                  (4, "unrestricted resource consumption (2)"), (5, "BFLA (3)")]])
GT["not-going-anywhere"] = ("go", "per-program READMEs under cmd/", [
    ("integers-atoi", "int32(Atoi) truncation", "cmd/integers/atoi.md", "IN", "GAP", "no integer-conversion rule"),
    ("integers-parseInt", "ParseInt exponent overflow", "cmd/integers/parseInt.md", "IN", "GAP", "no integer-conversion rule"),
    ("symlink_attack", "following a planted symlink", "cmd/symlink_attack/symlink_attack.go", "IN", "GAP", "no symlink/TOCTOU rule"),
    ("errors", "ignored / shadowed errors", "cmd/errors", "OUT:reliability", "n/a", ""),
    ("goroutines", "loop-variable capture", "cmd/goroutines", "OUT:concurrency", "n/a", ""),
    ("slices", "append aliasing", "cmd/slices", "OUT:reliability", "n/a", ""),
])

GT["pygoat"] = ("python", "per-lab READMEs (dockerized_labs/<lab>/README.md)", [
    ("cmd-lab1", "command injection (nslookup)", "command_injection_lab/app.py:29", "IN", "GAP", "aegis-py-command-injection sink needs shell=True LAST"),
    ("cmd-lab2", "eval()", "command_injection_lab/app.py:49", "IN", "DET", "aegis-py-code-injection"),
    ("crypto-lab1", "MD5 password", "crypto_failure_lab/app.py:38", "IN", "DET", "aegis-py-weak-hash-credential"),
    ("crypto-lab2", "SHA-1 password", "crypto_failure_lab/app.py:25", "IN", "DET", "aegis-py-weak-hash-credential"),
    ("crypto-lab3", "hard-coded credentials", "crypto_failure_lab/app.py", "OUT:secrets/auth", "n/a", ""),
    ("insec-des", "pickle.loads(user data)", "insec_des_lab/main.py:40", "IN", "GAP", "no Python deserialization rule"),
    ("integrity-lab1", "pickle.loads(cookie)", "software_integrity_lab/app.py:44", "IN", "GAP", "no deserialization rule"),
    ("integrity-lab2", "client-side script injection", "software_integrity_lab", "OUT:client-side/SRI", "n/a", ""),
    ("a9-yaml", "yaml.load(Loader=yaml.Loader)", "a9_uckv_lab/app.py:62", "IN", "GAP", "no insecure-YAML rule"),
    ("a9-pillow", "vulnerable Pillow", "a9_uckv_lab", "OUT:SCA", "n/a", ""),
    ("sde-debug", "DEBUG=True", "sde/app.py:7", "IN", "GAP", "no Flask debug rule"),
    ("misconfig-lab1", "header-based auth", "sec_misconfig/app.py:28", "OUT:authentication", "n/a", ""),
    ("misconfig-lab2", "debug mode", "sec_misconfig/app.py", "IN", "GAP", "no Flask debug rule"),
    ("misconfig-lab3", "JWT signed with 'secret123'", "sec_misconfig/app.py:98", "IN", "GAP", "no hard-coded JWT key rule"),
    ("sqli", "SQL injection (login)", "sql_injection_lab/app.py:57", "IN", "DET", "aegis-py-sql-injection"),
    ("ssrf-lab1", "path traversal (file read)", "ssrf_lab/app.py:22", "IN", "DET", "aegis-py-path-traversal"),
    ("ssrf-lab2", "SSRF", "ssrf_lab/app.py:37", "IN", "DET", "aegis-py-ssrf"),
    ("ssti", "SSTI via a written template file", "template_injection_lab/app.py:20-112", "IN", "CEIL", "file-mediated, cross-route"),
    ("xss-lab1", "reflected XSS", "xss_lab/templates/lab1.html (|safe)", "IN", "CEIL", "template-side"),
    ("xss-lab2", "stored XSS filter bypass", "xss_lab/templates/lab2.html (|safe)", "IN", "CEIL", "template-side"),
    ("xss-lab3", "DOM XSS", "xss_lab/templates/lab3.html", "IN", "CEIL", "client-side"),
    ("xxe", "XXE (external entities enabled)", "xxe_lab/app.py:58", "IN", "GAP", "no Python XXE rule"),
    ("ba-weak-pw", "weak password requirements", "broken_auth_lab", "OUT:logic", "n/a", ""),
    ("ba-plaintext", "plaintext password storage", "broken_auth_lab/app.py:84", "IN", "GAP", "no cleartext-storage rule"),
    ("ba-session", "predictable session token", "broken_auth_lab/app.py:56", "IN", "GAP", "base64(user:time); weak-random staged, no time source"),
    ("ba-remember", "insecure remember-me cookie", "broken_auth_lab/app.py:64", "IN", "DET", "aegis-py-insecure-session-cookie"),
    ("ba-reset", "predictable reset token md5(email:now)", "broken_auth_lab/app.py:103", "IN", "GAP", "time-based token"),
    ("ba-bruteforce", "no brute-force protection", "broken_auth_lab", "OUT:logic", "n/a", ""),
    ("ba-debug", "debug mode in production", "broken_auth_lab", "IN", "GAP", "no Flask debug rule"),
    ("auth-otp", "OTP brute force", "auth_failure_lab", "OUT:logic", "n/a", ""),
    ("auth-admin", "admin panel lockout", "auth_failure_lab", "OUT:logic", "n/a", ""),
    ("broken-access", "cookie-based access control", "broken_access_lab", "OUT:authorization", "n/a", ""),
    ("insecure-design", "insecure design", "insecure_design_lab", "OUT:logic", "n/a", ""),
    ("logging", "insufficient logging x2", "insufficient_logging_lab", "OUT:logging", "n/a", ""),
    ("supply-chain", "dependency / OSS / typosquat labs (3)", "dependency_attack_lab etc.", "OUT:SCA", "n/a", ""),
])
GT["dsvw"] = ("python", "the index page's attack-case table (dsvw.py)", [
    ("sqli-blind-bool", "blind SQLi (boolean)", "dsvw.py:22", "IN", "DET", "aegis-py-sql-string-construction"),
    ("sqli-blind-time", "blind SQLi (time)", "dsvw.py:22", "IN", "DET", "aegis-py-sql-string-construction"),
    ("sqli-union", "UNION SQLi", "dsvw.py:22", "IN", "DET", "aegis-py-sql-string-construction"),
    ("login-bypass", "login bypass", "dsvw.py:61", "IN", "DET", "aegis-py-sql-string-construction"),
    ("hpp", "HTTP parameter pollution", "dsvw.py:61", "OUT:parsing logic", "n/a", ""),
    ("xss-reflected", "reflected XSS (v)", "dsvw.py:24", "IN", "GAP", "http.server `params` is not a modelled source"),
    ("xss-stored", "stored XSS (comment)", "dsvw.py:42", "IN", "CEIL", "second-order (DB -> page)"),
    ("xss-dom", "DOM XSS", "dsvw.py (inline JS)", "IN", "CEIL", "client-side"),
    ("xss-jsonp", "JSONP callback XSS", "dsvw.py:59", "IN", "GAP", "source not modelled"),
    ("xxe-local", "XXE (local)", "dsvw.py:33", "IN", "GAP", "no XXE rule (lxml resolve_entities=True)"),
    ("xxe-remote", "XXE (remote)", "dsvw.py:33", "IN", "GAP", "no XXE rule"),
    ("ssrf", "SSRF (path with ://)", "dsvw.py:29", "IN", "GAP", "source not modelled"),
    ("xpath", "blind XPath injection", "dsvw.py:35", "IN", "GAP", "no XPath rule; source"),
    ("csrf", "CSRF", "dsvw.py", "OUT:missing control", "n/a", ""),
    ("frame-phish", "frame injection (phishing)", "dsvw.py:24", "IN", "GAP", "source not modelled"),
    ("frame-spoof", "frame injection (spoofing)", "dsvw.py:24", "IN", "GAP", "source not modelled"),
    ("redirect", "unvalidated redirect", "dsvw.py:70", "IN", "GAP", "no Python redirect rule; source"),
    ("ace", "arbitrary code execution (nslookup)", "dsvw.py:31", "IN", "DET", "aegis-py-shell-command-construction"),
    ("fpd", "full path disclosure", "dsvw.py:29", "OUT:runtime error", "n/a", ""),
    ("source-disclosure", "source code disclosure", "dsvw.py:29", "IN", "GAP", "path traversal; source not modelled"),
    ("path-traversal", "path traversal", "dsvw.py:29", "IN", "GAP", "source not modelled"),
    ("rfi", "remote file inclusion", "dsvw.py:47", "IN", "GAP", "source not modelled"),
    ("header-injection", "HTTP header injection (charset)", "dsvw.py:70", "IN", "GAP", "no header-injection rule"),
    ("pickle", "pickle (known-vulnerable component)", "dsvw.py:26", "IN", "GAP", "no deserialization rule"),
    ("dos-memory", "memory DoS (size)", "dsvw.py:37", "OUT:resource consumption", "n/a", ""),
    ("ssti", "server-side template injection", "dsvw.py:54", "IN", "GAP", "no SSTI rule; source"),
])
GT["dvgraphql"] = ("python", "README scenarios + templates/partials/solutions/", [
    ("cmd1", "OS command injection #1 (importPaste)", "core/views.py:211 -> helpers.run_cmd", "IN", "CEIL", "resolver args + sink in core/helpers.py"),
    ("cmd2", "OS command injection #2 (systemDiagnostics)", "core/views.py:345 -> helpers.run_cmd", "IN", "CEIL", "sink in helpers.py"),
    ("ssrf", "SSRF (importPaste curl)", "core/views.py:211", "IN", "CEIL", "helpers.run_cmd"),
    ("file-write", "arbitrary file write / path traversal", "core/views.py:186 -> helpers.save_file", "IN", "CEIL", "sink in helpers.py"),
    ("sqli", "SQL injection (pastes filter)", "core/views.py:320", "IN", "DET", "aegis-py-sql-string-construction"),
    ("xss-stored", "stored XSS", "client rendering", "IN", "CEIL", "rendered client-side"),
    ("html-injection", "HTML injection", "client rendering", "IN", "CEIL", "rendered client-side"),
    ("log-injection", "log spoofing", "core/models.py Audit", "IN", "GAP", "no log-injection rule"),
] + [(s, s, "graphql layer", "OUT:" + why, "n/a", "") for s, why in [
    ("batch-query", "DoS"), ("deep-recursion", "DoS"), ("resource-intensive", "DoS"),
    ("field-duplication", "DoS"), ("aliases", "DoS"), ("introspection", "configuration/info"),
    ("graphiql", "configuration/info"), ("field-suggestions", "configuration/info"),
    ("stack-trace", "runtime error"), ("jwt-forge", "authentication"),
    ("interface-protection-bypass", "authorization"), ("deny-list-bypass", "authorization"),
    ("weak-password", "authentication"), ("discovering", "reconnaissance"), ("fingerprinting", "reconnaissance")]])
GT["django-nv"] = ("python", "in-app tutorials (taskManager/templates/.../tutorials/partials)", [
    ("injection", "SQLi in upload()", "taskManager/views.py:184", "IN", "DET", "aegis-py-sql-injection"),
    ("xss", "{{ user.username|safe }}", "taskManager/templates/*/base.html", "IN", "CEIL", "template-side"),
    ("brokenauth-mass", "mass assignment (UserForm)", "taskManager/forms.py", "OUT:logic", "n/a", ""),
    ("brokenauth-session", "cookie sessions + PickleSerializer", "taskManager/settings.py:109", "IN", "GAP", "no session-serializer rule"),
    ("idor", "task_delete", "taskManager/views.py", "OUT:authorization", "n/a", ""),
    ("misconfig-debug", "DEBUG = True", "taskManager/settings.py", "IN", "GAP", "no Django DEBUG rule"),
    ("exposure", "MD5PasswordHasher", "taskManager/settings.py", "IN", "GAP", "no PASSWORD_HASHERS rule"),
    ("access", "manage_groups", "taskManager/views.py", "OUT:authorization", "n/a", ""),
    ("csrf", "@csrf_exempt", "taskManager/views.py", "IN", "GAP", "no csrf_exempt rule"),
    ("components", "old Django", "requirements", "OUT:SCA", "n/a", ""),
    ("redirects", "logout redirect(request.GET['redirect'])", "taskManager/views.py", "IN", "GAP", "no Python open-redirect rule"),
])
GT["lets-be-bad-guys"] = ("python", "exercise views (badguys/vulnerable/views.py + templates)", [
    ("injection-sql", "SQL injection (simulated; no query is run)", "views.py:17", "OUT:simulated, not a flaw in code", "n/a", ""),
    ("injection-file", "file access / path traversal", "views.py:42", "IN", "DET", "aegis-py-path-traversal"),
    ("injection-code", "code execution (exec)", "views.py:72", "IN", "DET", "aegis-py-code-injection"),
    ("xss-form", "XSS form field", "templates/vulnerable/xss/form.html (|safe)", "IN", "CEIL", "template-side"),
    ("xss-path", "XSS path", "templates/vulnerable/xss/path.html (|safe)", "IN", "CEIL", "template-side"),
    ("xss-query", "XSS query", "templates/vulnerable/xss/query.html (|safe)", "IN", "CEIL", "template-side"),
    ("broken-auth", "broken auth", "templates only", "OUT:authentication", "n/a", ""),
    ("dor", "direct object references", "views.py:128", "OUT:authorization", "n/a", ""),
    ("misconfig", "DEBUG = True (boom)", "badguys/settings.py:10", "IN", "GAP", "no Django DEBUG rule"),
    ("exposure", "data exposure", "templates", "OUT:transport", "n/a", ""),
    ("access-control", "missing access control", "views.py:155", "OUT:authorization", "n/a", ""),
    ("csrf", "@csrf_exempt + CsrfViewMiddleware off", "views.py:164", "IN", "GAP", "no csrf_exempt rule"),
    ("components", "vulnerable components", "requirements", "OUT:SCA", "n/a", ""),
    ("redirect", "unvalidated redirect", "views.py:178", "IN", "GAP", "no Python open-redirect rule"),
    ("forward", "unvalidated forward (globals()[fwd])", "views.py:183", "IN", "GAP", "no unsafe-reflection rule"),
])
GT["dvpwa-full"] = ("python", "README 'Vulnerabilities' section (all four)", [
    ("session-fixation", "session fixation", "sqli/views.py", "OUT:session logic", "n/a", ""),
    ("sqli", "SQL injection", "sqli/dao/student.py:42", "IN", "DET", "aegis-py-sql-string-construction"),
    ("stored-xss", "stored XSS (Jinja autoescape=False)", "sqli/app.py:35", "IN", "GAP", "no Jinja autoescape rule"),
    ("md5", "MD5 password storage", "sqli/dao/user.py:41", "IN", "DET", "aegis-py-weak-hash-credential"),
])

GT["java-sec-code"] = ("java", "README per-controller links", [
    ("CommandInject", "command injection", "controller/CommandInject.java:45", "IN", "DET", "aegis-java-command-injection"),
    ("FileUpload", "file upload path", "controller/FileUpload.java:62", "IN", "DET", "aegis-java-path-traversal"),
    ("SQLI", "SQL injection", "controller/SQLI.java:67", "IN", "DET", "aegis-java-sql-injection"),
    ("SSRF", "SSRF", "controller/SSRF.java:127", "IN", "DET", "aegis-java-ssrf"),
    ("PathTraversal", "path traversal", "controller/PathTraversal.java:25", "IN", "GAP", "unannotated Spring param; helper"),
    ("XSS", "reflected/stored XSS", "controller/XSS.java:29", "IN", "GAP", "unannotated param; @ResponseBody return not a sink"),
    ("URLRedirect", "open redirect", "controller/URLRedirect.java:33", "IN", "GAP", "no Java redirect rule"),
    ("URLWhiteList", "URL allow-list bypass", "controller/URLWhiteList.java", "IN", "GAP", "no rule"),
] + [(n, n, f"controller/{n}.java", "IN", "GAP", "unannotated Spring params are not a source")
     for n in ("RCE-Runtime", "RCE-ProcessBuilder", "RCE-ScriptEngine", "RCE-Yaml", "RCE-Groovy")]
  + [(n, d, f, "IN", "GAP", "no rule for the class")
     for n, d, f in [("CORS", "CORS misconfiguration", "controller/CORS.java"),
                     ("CRLF", "CRLF injection", "controller/CRLFInjection.java"),
                     ("Deserialize", "deserialization", "controller/Deserialize.java"),
                     ("Fastjson", "Fastjson autotype", "controller/Fastjson.java"),
                     ("RMI", "RMI deserialization", "RMI/Server.java"),
                     ("JSONP", "JSONP", "controller/Jsonp.java"),
                     ("ooxmlXXE", "XXE (ooxml)", "controller/othervulns/ooxmlXXE.java"),
                     ("xlsxXXE", "XXE (xlsx streamer)", "controller/othervulns/xlsxStreamerXXE.java"),
                     ("XXE", "XXE", "controller/XXE.java"),
                     ("XStream", "XStream RCE", "controller/XStreamRce.java"),
                     ("QLExpress", "expression injection", "controller/QLExpress.java"),
                     ("SpEL", "SpEL injection", "controller/SpEL.java"),
                     ("SSTI", "template injection", "controller/SSTI.java")]]
  + [(n, n, "", "OUT:" + w, "n/a", "") for n, w in [
      ("Actuators-to-RCE", "configuration"), ("CSRF", "configuration"), ("CVE-2022-22978", "SCA"),
      ("GetRequestURI", "authorization bypass logic"), ("IP-Forge", "logic"), ("Log4j", "SCA"),
      ("Shiro", "configuration/SCA"), ("Swagger", "configuration"), ("JWT", "authentication")]])
GT["javavulnerablelab"] = ("java", "README OWASP 2025 inventory (+ in-page comments)", [
    ("sqli-authbypass", "SQLi login bypass", "controller/LoginValidator.java:52", "IN", "DET", "aegis-java-sql-injection"),
    ("sqli-blind", "blind SQLi (username/email check)", "controller/UsernameCheck.java:48", "IN", "DET", "aegis-java-sql-injection (location inferred)"),
    ("sqli-error", "error-based SQLi", "webapp/vulnerability/sqli/download_id.jsp", "IN", "CEIL", "JSP is not parsed"),
    ("sqli-union", "union SQLi", "webapp/vulnerability/sqli/download_id_union.jsp", "IN", "CEIL", "JSP"),
    ("cmdi", "OS command injection", "webapp/vulnerability/Injection/ping.jsp", "IN", "CEIL", "JSP"),
    ("xpath", "XPath injection", "controller/XPathQuery.java:51", "IN", "GAP", "no XPath rule"),
    ("xslt", "XSLT injection", "webapp/vulnerability/Injection/xslt.jsp", "IN", "CEIL", "JSP"),
    ("orm", "ORM injection", "webapp/vulnerability/Injection/orm.jsp", "IN", "CEIL", "JSP"),
    ("xss-reflected", "reflected XSS", "webapp/vulnerability/xss/search.jsp", "IN", "CEIL", "JSP"),
    ("xss-stored", "stored XSS", "webapp/vulnerability/xss/*.jsp", "IN", "CEIL", "JSP"),
    ("xss-flash", "Flash XSS", "webapp/vulnerability/xss/flash", "IN", "CEIL", "JSP/SWF"),
    ("path-download", "path traversal in download", "webapp/vulnerability/sqli/download.jsp", "IN", "CEIL", "JSP"),
    ("ssrf", "SSRF", "webapp/vulnerability/ssrf/URLPreview.jsp", "IN", "CEIL", "JSP"),
    ("open-redirect", "open redirect", "controller/Open.java:39", "IN", "GAP", "no Java redirect rule"),
    ("open-forward", "open forward", "controller/ForwardMe.java:42", "IN", "GAP", "no forward rule"),
    ("debug", "debug mode in production", "webapp/vulnerability/debugmode", "IN", "CEIL", "JSP"),
    ("xxe", "XXE", "controller/xxe.java", "IN", "GAP", "no Java XXE rule"),
    ("plaintext-pw", "plaintext passwords", "controller/Register.java", "IN", "GAP", "no cleartext-storage rule"),
    ("creds-cookie", "credentials written to a cookie", "controller/LoginValidator.java:66", "IN", "GAP", "cookie names username/password not session-shaped"),
    ("md5", "MD5 password hashing", "model/HashMe.java", "IN", "GAP", "Java weak-hash rule staged"),
    ("upload", "unrestricted upload -> web shell", "controller/AvatarUpload.java:40", "IN", "GAP", "no upload rule"),
    ("deserialize", "view-state deserialization", "webapp/vulnerability/deserialize/preferences.jsp", "IN", "CEIL", "JSP"),
    ("log-injection", "log injection", "webapp/vulnerability/loginjection/activity.jsp", "IN", "CEIL", "JSP"),
] + [(n, n, "", "OUT:" + w, "n/a", "") for n, w in [
    ("idor", "authorization"), ("function-level-ac", "authorization"), ("jwt-privesc", "authentication"),
    ("cookie-privesc", "authorization"), ("csrf-get", "missing control"), ("csrf-post", "missing control"),
    ("setup-page", "deployment"), ("default-creds", "deployment"), ("dir-listing", "server configuration"),
    ("log4shell", "SCA"), ("cleartext-card", "transport"), ("security-question", "logic"),
    ("otp-client", "logic"), ("no-rate-limit", "logic"), ("username-enum", "logic"),
    ("pw-change-no-reauth", "logic"), ("session-fixation", "session logic"), ("api-keys-in-js", "secrets pillar"),
    ("no-sri", "client-side"), ("stack-trace", "runtime"), ("fail-open", "logic"), ("no-rollback", "logic")]])
GT["dvja"] = ("java", "docs/solution/*.md", [
    ("sqli", "SQLi (UserService JPQL)", "services/UserService.java:75", "IN", "CEIL", "Struts action -> service; JPA createQuery not a sink"),
    ("cmdi", "command injection (PingAction)", "controllers/PingAction.java:46", "IN", "GAP", "Struts2 action properties are not a source"),
    ("reset-key", "reset key = md5(username)", "UserService", "IN", "GAP", "predictable token"),
    ("cred-storage", "weak password hashing", "services/UserService.java", "IN", "GAP", "Java weak-hash rule staged"),
    ("xss-reflected", "reflected XSS", "ProductList.jsp", "IN", "CEIL", "JSP"),
    ("xss-stored", "stored XSS", "ProductList.jsp", "IN", "CEIL", "JSP"),
    ("log-password", "password logged", "services/UserService.java", "IN", "GAP", "no sensitive-logging rule"),
    ("redirect", "unvalidated redirect", "controllers/RedirectAction.java", "IN", "GAP", "no Java redirect rule"),
] + [(n, n, "", "OUT:" + w, "n/a", "") for n, w in [
    ("idor", "authorization"), ("misconfig-null", "logic"), ("function-level-ac", "authorization"),
    ("csrf", "missing control"), ("components", "SCA")]])
GT["javulna"] = ("java", "README exercises (endpoint per exercise)", [
    ("ex1-sqli", "SQLi (/rest/movie)", "services/MovieService.java", "IN", "CEIL", "controller -> service; JPA query"),
    ("ex5-files", "file read via upload/download", "services/*File*", "IN", "CEIL", "service layer"),
    ("ex6-serialization", "serialized cookie", "services/*", "IN", "GAP", "no Java deserialization rule"),
    ("ex7-xxe", "XXE (/rest/moviexml)", "services/MovieService.java:94", "IN", "CEIL", "service layer; no XXE rule"),
    ("ex8-ldap", "LDAP injection", "services/LdapService.java", "IN", "CEIL", "service layer"),
    ("ex9-xss", "XSS", "client", "IN", "CEIL", "client rendering"),
    ("ex2-login", "log in", "", "OUT:authentication", "n/a", ""),
    ("ex3-password", "change another user's password", "", "OUT:authorization", "n/a", ""),
    ("ex4-cheaper", "buy cheaper", "", "OUT:logic", "n/a", ""),
])
_sq = [("SqlInjection1", "DET"), ("SqlInjection3", "DET"), ("SqlInjection4", "DET"), ("SqlInjection5", "DET"),
       ("SqlInjection6", "DET"), ("SqlInjection7", "DET"), ("SqlInjectionEmail", "DET"),
       ("SqlInjectionEscaping", "DET"), ("SqlInjectionStoredProcedure", "DET"), ("SqlInjectionLesson", "CEIL")]
_xs = ["XssChallengeOne", "XssChallengeTwo", "XssChallengeThree", "XssChallengeFour", "XssChallengeFive",
       "XssChallengeSix", "XssLesson"]
GT["securityshepherd"] = ("java", "module table (coreSchema.sql) -> servlets/module/{challenge,lesson}", [
    (n, "SQL injection", f"servlets/module/*/{n}.java", "IN", s,
     "aegis-java-sql-injection" if s == "DET" else "query in a helper") for n, s in _sq]
  + [(n, "XSS", f"servlets/module/*/{n}.java", "IN", "DET", "aegis-java-xss") for n in _xs]
  + [("NoSqlInjection1", "NoSQL injection", "challenge/NoSqlInjection1.java", "IN", "GAP", "no Java Mongo-$where rule"),
     ("XxeChallenge1", "XXE", "challenge/XxeChallenge1.java", "IN", "GAP", "no Java XXE rule"),
     ("XxeLesson", "XXE", "lesson/XxeLesson.java", "IN", "GAP", "no Java XXE rule"),
     ("BrokenCrypto3", "broken crypto", "challenge/BrokenCrypto3.java", "IN", "GAP", "home-made / encoding 'crypto'"),
     ("BrokenCrypto4", "broken crypto", "challenge/BrokenCrypto4.java", "IN", "GAP", "home-made crypto"),
     ("BrokenCryptoHomeMade", "broken crypto", "challenge/BrokenCryptoHomeMade.java", "IN", "GAP", "home-made crypto"),
     ("Redirect", "unvalidated redirect", "lesson/Redirect*.java", "IN", "GAP", "no Java redirect rule"),
     ("UnvalidatedForwardsLesson", "unvalidated forward", "lesson/UnvalidatedForwardsLesson.java", "IN", "GAP", "no forward rule")]
  + [(n, n, "", "OUT:" + w, "n/a", "") for n, w in [
      ("CSRF (7 challenges + lesson)", "missing control"), ("DirectObject (2 + bank + lesson)", "authorization"),
      ("UrlAccess (3)", "authorization"), ("SessionManagement (8 + lesson)", "session logic"),
      ("PoorValidation (2 + lesson)", "logic"), ("SecurityMisconfig (challenge + lesson)", "configuration")]])

# VulnerableApp: generated from its own @AttackVector annotations (vulnapp_items.json)
VA_SCOPE = {  # type -> (scope, miss class when not detected, reason)
    **{t: ("IN", "GAP", "Spring JdbcTemplate.query is not a modelled sink") for t in
       ("BLIND_SQL_INJECTION", "UNION_BASED_SQL_INJECTION", "ERROR_BASED_SQL_INJECTION")},
    "COMMAND_INJECTION": ("IN", "CEIL", "sink in getResponseFromPingCommand helper"),
    "HEADER_INJECTION": ("IN", "GAP", "no header-injection rule"),
    "LDAP_INJECTION": ("IN", "CEIL", "searchUsers helper"),
    "PATH_TRAVERSAL": ("IN", "CEIL", "readFile helper"),
    "PERSISTENT_XSS": ("IN", "CEIL", "getCommentsPayload helper"),
    "REFLECTED_XSS": ("IN", "GAP", "ResponseEntity<String> body is not a modelled sink"),
    "OPEN_REDIRECT_3XX_STATUS_CODE": ("IN", "CEIL", "getURLRedirectionResponseEntity helper; no redirect rule"),
    "SIMPLE_SSRF": ("IN", "CEIL", "-"),
    "REMOTE_CODE_EXECUTION": ("IN", "GAP", "no Java deserialization rule"),
    "XXE": ("IN", "GAP", "no Java XXE rule (JAXB unmarshal)"),
    "INSECURE_DESERIALIZATION": ("IN", "GAP", "no Java deserialization rule"),
    "UNRESTRICTED_FILE_UPLOAD": ("IN", "CEIL", "genericFileUploadUtility helper"),
    "INSECURE_CRYPTOGRAPHIC_STORAGE": ("IN", "CEIL", "seeded vault data"),
    "USE_OF_BROKEN_CRYPTOGRAPHIC_ALGORITHM": ("IN", "CEIL", "EncryptionUtils / seeded vault"),
    "WEAK_CRYPTOGRAPHIC_HASH": ("IN", "CEIL", "seeded vault data"),
    "WEAK_PASSWORD_HASHING": ("IN", "CEIL", "PasswordHashingUtils / seeder"),
    "PLAINTEXT_PASSWORD_STORAGE": ("IN", "GAP", "no cleartext-storage rule"),
    "WEAK_RANDOM_NUMBER_GENERATION": ("IN", "CEIL", "-"),
    "PREDICTABLE_SESSION_ID": ("IN", "GAP", "predictable id; weak-random naming"),
    "OBSCURED_PREDICTABLE_SESSION_ID": ("IN", "GAP", "encoded predictable id"),
    "PREDICTABLE_PASSWORD_RESET_TOKEN": ("IN", "GAP", "predictable token"),
    "CLICKJACKING": ("IN", "GAP", "no frame-options rule"),
    **{t: ("OUT:" + w, "n/a", "") for t, w in [
        ("IMPROPER_AUTHORIZATION", "authorization"), ("INSECURE_DIRECT_OBJECT_REFERENCE", "authorization"),
        ("NO_LOGIN_RATE_LIMITING", "logic"), ("MISSING_LOGOUT_INVALIDATION", "session logic"),
        ("SESSION_FIXATION", "session logic"), ("USERNAME_ENUMERATION", "logic"),
        ("REUSABLE_PASSWORD_RESET_TOKEN", "logic"), ("PASSWORD_RESET_TOKEN_WITHOUT_EXPIRY", "logic"),
        ("PASSWORD_RESET_TOKEN_EXPOSED_VIA_REFERRER", "logic"), ("INSECURE_PASSWORD_RESET_LINK", "logic"),
        ("CLIENT_SIDE_VULNERABLE_JWT", "client-side"), ("SERVER_SIDE_VULNERABLE_JWT", "authentication"),
        ("INSECURE_CONFIGURATION_JWT", "authentication"), ("WEB_CACHE_POISONING", "logic"),
        ("DENIAL_OF_SERVICE", "resource consumption"), ("UNCONTROLLED_RESOURCE_CONSUMPTION", "resource consumption")]},
}
# Detections that live in a helper the level calls (one hop), established by reading the code.
VA_HELPER_DET = {
    ("SIMPLE_SSRF", "getVulnerablePayloadLevel1"): "aegis-java-ssrf (helper, SSRFVulnerability.java:67)",
    ("SIMPLE_SSRF", "getVulnerablePayloadLevel2"): "aegis-java-ssrf (helper, SSRFVulnerability.java:67)",
    ("WEAK_RANDOM_NUMBER_GENERATION", "level1RequestOTP"): "aegis-java-weak-random-secret (OTPService:119)",
    ("WEAK_RANDOM_NUMBER_GENERATION", "level2RequestOTP"): "aegis-java-weak-random-secret (OTPService:150)",
}
VA_SEEDER_DET = {  # two hops: the vault the level reads is built by the seeder we flagged
    ("WEAK_CRYPTOGRAPHIC_HASH", 452): "aegis-java-weak-cipher (LM hash DES, PasswordHashingUtils:150)",
    ("USE_OF_BROKEN_CRYPTOGRAPHIC_ALGORITHM", 568): "aegis-java-weak-cipher (AES/ECB, EncryptionUtils:88)",
}
va = []
for it in json.load(open("E:/n4work/vulnapp_items.json")):
    if it["secure"]:
        continue
    for t in it["types"]:
        scope, miss, why = VA_SCOPE[t]
        rid = f"{t}@{it['method']}:{it['start']}"
        if it["hits"] and scope == "IN" and any(
                k in t for k in ("SQL", "SSRF")):
            va.append((rid, t, f"{it['file']}:{it['start']}", scope, "DET", ",".join(it["hits"])))
        elif (t, it["method"]) in VA_HELPER_DET:
            va.append((rid, t, f"{it['file']}:{it['start']}", scope, "DET", VA_HELPER_DET[(t, it["method"])]))
        elif (t, it["start"]) in VA_SEEDER_DET:
            va.append((rid, t, f"{it['file']}:{it['start']}", scope, "DET", VA_SEEDER_DET[(t, it["start"])]))
        else:
            va.append((rid, t, f"{it['file']}:{it['start']}", scope, miss if scope == "IN" else "n/a", why))
GT["vulnerableapp"] = ("java", "@AttackVector annotations on level methods (vulnerable levels only)", va)

if __name__ == "__main__":
    out = {}
    for corpus, (lang, source, items) in GT.items():
        out[corpus] = {"language": lang, "documented_list": source,
                       "items": [dict(zip(("id", "item", "location", "scope", "status", "rule_or_reason"), x))
                                 for x in items]}
    json.dump(out, open("E:/n4work/gt_n4.json", "w"), indent=1)
    import collections
    per_lang = collections.defaultdict(lambda: [0, 0, 0, 0, 0])  # det, in, strict_in, gap, ceil
    print(f"{'corpus':24s} {'lang':7s} {'docs':>4s} {'in':>4s} {'det':>4s} {'recall':>7s} {'gap':>4s} {'ceil':>4s} {'strict':>9s}")
    for c, v in out.items():
        it = v["items"]
        ins = [x for x in it if x["scope"] == "IN"]
        const = [x for x in it if x["scope"] == "CONST"]
        det = [x for x in ins if x["status"] == "DET"]
        gap = [x for x in ins + const if x["status"] == "GAP"]
        ceil = [x for x in ins if x["status"] == "CEIL"]
        strict = len(ins) + len(const)
        print(f"{c:24s} {v['language']:7s} {len(it):4d} {len(ins):4d} {len(det):4d} {len(det)/max(1,len(ins)):7.0%} "
              f"{len(gap):4d} {len(ceil):4d} {len(det):3d}/{strict:<4d}")
        pl = per_lang[v["language"]]
        pl[0] += len(det); pl[1] += len(ins); pl[2] += strict; pl[3] += len(gap); pl[4] += len(ceil)
    print()
    for l, (d, i, s, g, ce) in per_lang.items():
        corp = [c for c, v in out.items() if v["language"] == l and any(x["status"] == "DET" and x["scope"] == "IN" for x in v["items"])]
        print(f"{l:7s} in-scope recall {d}/{i} = {d/i:.0%} (strict {d}/{s} = {d/s:.0%}); misses: rule gap {g}, engine ceiling {ce}; "
              f"corpora with a documented detection: {len(corp)} {corp}")
