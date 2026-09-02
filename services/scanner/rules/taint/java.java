// Test fixtures for rules/taint/java.yaml — consumed by `semgrep --test`.
// Positive cases fire the rule; sanitized negatives must not. Never scanned in
// production (real scans target the cloned repo; --config only loads *.yaml).
import java.io.File;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.reactive.function.server.ServerRequest;

class TaintFixtures {

    static String validateUrl(String u) { return u; }

    interface LoginForm { String getUser(); }

    // ── SQL injection ────────────────────────────────────────────────────────
    void sqliBad(Statement stmt, HttpServletRequest req) throws Exception {
        String id = req.getParameter("id");
        // ruleid: aegis-java-sql-injection
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    void sqliOk(Connection conn, HttpServletRequest req) throws Exception {
        String id = req.getParameter("id");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        // ok: aegis-java-sql-injection
        ps.setString(1, id);
        ps.executeQuery();
    }

    // ── Cross-site scripting ─────────────────────────────────────────────────
    void xssBad(HttpServletResponse resp, HttpServletRequest req) throws Exception {
        String name = req.getParameter("name");
        PrintWriter out = resp.getWriter();
        // ruleid: aegis-java-xss
        out.println("<h1>Hello " + name + "</h1>");
    }

    void xssOk(HttpServletResponse resp, HttpServletRequest req) throws Exception {
        String name = req.getParameter("name");
        PrintWriter out = resp.getWriter();
        // ok: aegis-java-xss
        out.println("<h1>Hello " + Encode.forHtml(name) + "</h1>");
    }

    // P2 FP guard: writing user data to stdout/stderr is not XSS (no HTTP response,
    // no browser). The bare $OUT.print/println matched System.out — the eladmin
    // AliPayController FP.
    void xssStdoutOk(HttpServletRequest req) {
        String tradeNo = req.getParameter("trade_no");
        // ok: aegis-java-xss
        System.out.println("received trade_no " + tradeNo);
    }

    // T3 FP guard: a PrintWriter over a FILE is not an HTTP response (WebGoat
    // Ping.java logs the User-Agent to disk). Only writers from resp.getWriter()
    // are XSS sinks.
    void xssFileWriterOk(@RequestHeader("User-Agent") String userAgent) throws Exception {
        String logLine = "GET " + userAgent;
        try (PrintWriter pw = new PrintWriter(new File("/tmp/log.txt"))) {
            // ok: aegis-java-xss
            pw.println(logLine);
        }
    }

    // ── OS command injection ─────────────────────────────────────────────────
    void cmdBad(HttpServletRequest req) throws Exception {
        String host = req.getParameter("host");
        // ruleid: aegis-java-command-injection
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    void cmdOk(HttpServletRequest req) throws Exception {
        String host = req.getParameter("host");
        // ok: aegis-java-command-injection
        new ProcessBuilder("ping", "-c", "1", host).start();
    }

    // ── SSRF ─────────────────────────────────────────────────────────────────
    void ssrfBad(HttpServletRequest req) throws Exception {
        String u = req.getParameter("url");
        // ruleid: aegis-java-ssrf
        new URL(u).openStream();
    }

    void ssrfOk(HttpServletRequest req) throws Exception {
        String u = req.getParameter("url");
        // ok: aegis-java-ssrf
        new URL(validateUrl(u)).openStream();
    }

    // T3 FP guard: URI.create for a redirect Location header is an open-redirect
    // concern, not SSRF — the server does not fetch it (booklore OidcAuthController).
    org.springframework.http.ResponseEntity ssrfRedirectOk(@RequestParam String redirectUrl) {
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        // ok: aegis-java-ssrf
        headers.setLocation(java.net.URI.create(redirectUrl));
        return new org.springframework.http.ResponseEntity<>(headers, org.springframework.http.HttpStatus.FOUND);
    }

    // ── Path traversal ───────────────────────────────────────────────────────
    void pathBad(HttpServletRequest req) throws Exception {
        String name = req.getParameter("file");
        // ruleid: aegis-java-path-traversal
        new File(name).delete();
    }

    void pathOk(HttpServletRequest req) throws Exception {
        String name = req.getParameter("file");
        // ok: aegis-java-path-traversal
        new File(FilenameUtils.getName(name)).delete();
    }

    // T3 FP guard: a filename verifier that strips ".." neutralises traversal
    // (eladmin DatabaseController / DeployController via FileUtil.verifyFilename).
    void pathVerifyFilenameOk(@RequestBody org.springframework.web.multipart.MultipartFile file) throws Exception {
        String fileName = FileUtil.verifyFilename(file.getOriginalFilename());
        // ok: aegis-java-path-traversal
        new FileInputStream(new File("/uploads", fileName));
    }

    // ── NoSQL injection ──────────────────────────────────────────────────────
    void nosqlBad(com.mongodb.client.MongoCollection collection, HttpServletRequest req) {
        String body = req.getParameter("query");
        // ruleid: aegis-java-nosql-injection
        collection.find(Document.parse(body));
    }

    void nosqlOk(com.mongodb.client.MongoCollection collection, HttpServletRequest req) {
        String id = req.getParameter("id");
        // ok: aegis-java-nosql-injection
        collection.find(new Document("_id", new ObjectId(id)));
    }

    // T3 FP guard: a JPA/service/enum method named find(id) is NOT a MongoDB query
    // (eladmin genConfigService.find(tableName) / CodeBiEnum.find(codeBi)). Only a
    // Mongo query document counts as the sink.
    Object nosqlServiceFindOk(GenConfigService svc, @PathVariable String tableName) {
        // ok: aegis-java-nosql-injection
        return svc.find(tableName);
    }
    interface GenConfigService { Object find(String t); }

    // ── LDAP injection ───────────────────────────────────────────────────────
    void ldapBad(javax.naming.directory.DirContext ctx, HttpServletRequest req) throws Exception {
        String user = req.getParameter("user");
        Object[] controls = null;
        // ruleid: aegis-java-ldap-injection
        ctx.search("ou=users", "(uid=" + user + ")", controls);
    }

    void ldapOk(javax.naming.directory.DirContext ctx, HttpServletRequest req) throws Exception {
        String user = req.getParameter("user");
        Object[] controls = null;
        // ok: aegis-java-ldap-injection
        ctx.search("ou=users", "(uid=" + Encode.forLdap(user) + ")", controls);
    }

    // ══ Spring MVC / WebFlux sources (T3) ════════════════════════════════════════
    // Input arrives via annotated controller parameters, not getParameter(). Taint
    // is intraprocedural, so each source and its sink share one method.

    // @RequestParam (bare) -> SQL.
    @PostMapping("/sp/sql")
    public ResultSet springRequestParamSqli(@RequestParam String userid, Statement stmt) throws Exception {
        // ruleid: aegis-java-sql-injection
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + userid);
    }

    // @RequestParam("name") (parenthesised) must bind too.
    @PostMapping("/sp/sql2")
    public ResultSet springRequestParamNamed(@RequestParam("uid") String userid, Statement stmt) throws Exception {
        // ruleid: aegis-java-sql-injection
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + userid);
    }

    // Multi-arg prepareStatement sink (WebGoat SqlInjectionLesson5b shape).
    @PostMapping("/sp/prep")
    public void springPrepareStmtMultiArg(@RequestParam String accountName, Connection conn) throws Exception {
        String q = "SELECT * FROM user_data WHERE userid = " + accountName;
        // ruleid: aegis-java-sql-injection
        conn.prepareStatement(q, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
    }

    // @PathVariable -> 2-arg File constructor (WebGoat ProfileUploadRetrieval shape).
    @GetMapping("/sp/pic/{id}")
    public void springPathVariableTraversal(@PathVariable String id) throws Exception {
        File base = new File("/pics");
        // ruleid: aegis-java-path-traversal
        new FileInputStream(new File(base, id + ".jpg"));
    }

    // @RequestHeader -> SSRF.
    @GetMapping("/sp/fetch")
    public void springRequestHeaderSsrf(@RequestHeader("X-Target") String target) throws Exception {
        // ruleid: aegis-java-ssrf
        new URL(target).openStream();
    }

    // @CookieValue -> command injection.
    @GetMapping("/sp/run")
    public void springCookieCmdi(@CookieValue("host") String host) throws Exception {
        // ruleid: aegis-java-command-injection
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    // @RequestBody -> SQL.
    @PostMapping("/sp/search")
    public ResultSet springRequestBodySqli(@RequestBody String term, Statement stmt) throws Exception {
        // ruleid: aegis-java-sql-injection
        return stmt.executeQuery("SELECT * FROM p WHERE name = '" + term + "'");
    }

    // @ModelAttribute object -> LDAP (taint flows through a getter on the bound bean).
    @PostMapping("/sp/login")
    public void springModelAttrLdap(@ModelAttribute LoginForm form, javax.naming.directory.DirContext ctx) throws Exception {
        Object[] controls = null;
        // ruleid: aegis-java-ldap-injection
        ctx.search("ou=users", "(uid=" + form.getUser() + ")", controls);
    }

    // Spring WebFlux accessor source -> SQL.
    public ResultSet webfluxQueryParamSqli(ServerRequest request, Statement stmt) throws Exception {
        String u = request.pathVariable("u");
        // ruleid: aegis-java-sql-injection
        return stmt.executeQuery("SELECT * FROM t WHERE u = " + u);
    }

    // Sanitized Spring source: numeric coercion neutralises SQLi.
    @PostMapping("/sp/sqlok")
    public ResultSet springSqliOk(@RequestParam String id, Statement stmt) throws Exception {
        int safe = Integer.parseInt(id);
        // ok: aegis-java-sql-injection
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + safe);
    }

    // Sanitized 2-arg File: reduce to a bare filename first.
    @GetMapping("/sp/picok/{id}")
    public void springPathOk(@PathVariable String id) throws Exception {
        File base = new File("/pics");
        // ok: aegis-java-path-traversal
        new FileInputStream(new File(base, FilenameUtils.getName(id)));
    }
}
