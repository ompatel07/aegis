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
import javax.xml.xpath.XPath;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;
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

    // N5: a value of numeric type cannot carry markup (taint_assume_safe_numbers).
    void xssNumberOk(HttpServletResponse resp, HttpServletRequest req) throws Exception {
        int qty = Integer.parseInt(req.getParameter("qty"));
        int total = qty * 3;
        PrintWriter out = resp.getWriter();
        // ok: aegis-java-xss
        out.println("<p>Total: " + total + "</p>");
    }

    void xssParsedInlineOk(HttpServletResponse resp, HttpServletRequest req) throws Exception {
        PrintWriter out = resp.getWriter();
        // ok: aegis-java-xss
        out.println("<p>" + Long.parseLong(req.getParameter("n")) + "</p>");
    }

    // N5: a ResultSet holds database rows, not the request. Binding a request value
    // into the statement does not make the rows attacker data (stored XSS is a
    // second-order flow this rule does not model).
    void xssResultSetOk(Connection conn, HttpServletResponse resp, HttpServletRequest req) throws Exception {
        String code = req.getParameter("code");
        PreparedStatement ps = conn.prepareStatement("SELECT name FROM items WHERE code = ?");
        ps.setString(1, code);
        ResultSet rows = ps.executeQuery();
        PrintWriter out = resp.getWriter();
        while (rows.next()) {
            // ok: aegis-java-xss
            out.println("<li>" + rows.getString(1) + "</li>");
        }
    }

    void xssXPathResultOk(HttpServletResponse resp, HttpServletRequest req, org.w3c.dom.Document doc) throws Exception {
        String user = req.getParameter("user");
        javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
        XPath xpath = xp;
        // the XPath INJECTION is real, but the printed value is a node of the document
        String name = xpath.compile("/users/user[name='" + user + "']/display").evaluate(doc);
        PrintWriter out = resp.getWriter();
        // ok: aegis-java-xss
        out.println(name);
    }

    // N5: Spring writes a String response body as-is, and a browser's Accept header
    // negotiates it to text/html, so a request value in it is reflected XSS.
    ResponseEntity<String> xssResponseEntityBad(@RequestParam("q") String q) {
        // ruleid: aegis-java-xss
        return new ResponseEntity<String>("<p>" + q + "</p>", HttpStatus.OK);
    }

    ResponseEntity<String> xssResponseEntityOkBuilderBad(@RequestParam("q") String q) {
        // ruleid: aegis-java-xss
        return ResponseEntity.ok("<p>" + q + "</p>");
    }

    ResponseEntity<String> xssResponseEntityBodyBad(@RequestParam("q") String q) {
        // ruleid: aegis-java-xss
        return ResponseEntity.status(HttpStatus.OK).body("<p>" + q + "</p>");
    }

    ResponseEntity<String> xssResponseEntityEncodedOk(@RequestParam("q") String q) {
        // ok: aegis-java-xss
        return ResponseEntity.ok("<p>" + Encode.forHtml(q) + "</p>");
    }

    ResponseEntity<String> xssResponseEntitySpringEscapedOk(@RequestParam("q") String q) {
        String page = String.format("<img src=\"%s\"/>", HtmlUtils.htmlEscapeHex(q));
        // ok: aegis-java-xss
        return new ResponseEntity<>(page, HttpStatus.OK);
    }

    // A non-String body is serialized by a message converter (JSON), not written as markup.
    ResponseEntity<LoginForm> xssResponseEntityObjectOk(@RequestParam("q") String q) {
        LoginForm form = () -> q;
        // ok: aegis-java-xss
        return new ResponseEntity<LoginForm>(form, HttpStatus.OK);
    }

    @GetMapping("/greet")
    @ResponseBody
    String xssResponseBodyBad(@RequestParam("name") String name) {
        // ruleid: aegis-java-xss
        return "<h1>Hello " + name + "</h1>";
    }

    @GetMapping(value = "/greet.json", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    String xssResponseBodyJsonOk(@RequestParam("name") String name) {
        // ok: aegis-java-xss
        return "{\"name\": \"" + name + "\"}";
    }

    // ── Spring JdbcTemplate (N5) ─────────────────────────────────────────────
    private JdbcTemplate jdbcTemplate;
    private NamedParameterJdbcTemplate namedJdbc;

    void jdbcTemplateBad(@RequestParam("id") String id) {
        // ruleid: aegis-java-sql-injection
        jdbcTemplate.queryForList("SELECT * FROM items WHERE id = " + id);
    }

    void jdbcTemplateUpdateBad(@RequestParam("name") String name) {
        // ruleid: aegis-java-sql-injection
        jdbcTemplate.update("UPDATE items SET name = '" + name + "'");
    }

    void namedJdbcBad(@RequestParam("id") String id) {
        // ruleid: aegis-java-sql-injection
        namedJdbc.queryForList("SELECT * FROM items WHERE id = " + id, new java.util.HashMap<String, Object>());
    }

    // A PreparedStatementCreator lambda as the first argument: the SQL text is inside
    // it, and the inner prepareStatement() is the sink that must still report.
    void jdbcTemplateCreatorBad(@RequestParam("id") String id) {
        jdbcTemplate.query(
                (conn) ->
                        // ruleid: aegis-java-sql-injection
                        conn.prepareStatement("SELECT * FROM items WHERE id = '" + id + "'"),
                (ps) -> {},
                (rs) -> { return null; });
    }

    void jdbcTemplateBoundOk(@RequestParam("id") String id) {
        // ok: aegis-java-sql-injection
        jdbcTemplate.queryForList("SELECT * FROM items WHERE id = ?", id);
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
