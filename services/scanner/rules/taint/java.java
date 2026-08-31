// Test fixtures for rules/taint/java.yaml — consumed by `semgrep --test`.
// Positive cases fire the rule; sanitized negatives must not. Never scanned in
// production (real scans target the cloned repo; --config only loads *.yaml).
import java.io.File;
import java.io.PrintWriter;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class TaintFixtures {

    static String validateUrl(String u) { return u; }

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
}
