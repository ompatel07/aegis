// Fixtures for rules_staging/java_weakness.yaml (Pass N3, staged).
package fixtures;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.web.bind.annotation.RequestParam;

public class JavaWeakness {
    private static final String CHARS = "abcdefghijklmnopqrstuvwxyz0123456789";
    private final Random rnd = new Random();
    private final SecureRandom secure = new SecureRandom();
    private String apiKey;

    // ── weak random ─────────────────────────────────────────────────────────
    void weakRandomBad(User user, HttpServletResponse response, HttpSession session) {
        String resetToken = Long.toHexString(rnd.nextLong());
        long seedless = new Random().nextLong();
        user.setPasswordSalt(Long.toString(seedless));
        this.apiKey = String.valueOf(Math.random()).substring(2);
        Cookie c = new Cookie("remember-me", Integer.toString(ThreadLocalRandom.current().nextInt()));
        session.setAttribute("csrfToken", Double.toString(Math.random()));
    }

    String generateCsrfToken() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            sb.append(CHARS.charAt(rnd.nextInt(CHARS.length())));
        }
        return sb.toString();
    }

    void weakRandomOk(java.util.List<String> items, TokenService tokens) {
        // simulation, shuffling and jitter are not secrets
        long backoffMs = 1000 + rnd.nextInt(500);
        int sampleIndex = rnd.nextInt(items.size());
        // the secret word is not the head noun
        long tokenExpiry = System.currentTimeMillis() + rnd.nextInt(60000);
        // a random value handed to a service does not make its answer weak
        String accessToken = tokens.issue(rnd.nextInt());
        // the fix
        String sessionToken = Long.toHexString(secure.nextLong());
        // a race / correlation "token" is not a secret
        String fetchToken = Long.toHexString(rnd.nextLong());
        // SecureRandom output mixed in
        String resetToken = Long.toHexString(secure.nextLong()) + rnd.nextInt();
    }

    // ── weak hash: by what is hashed, or what the method is for ──────────────
    byte[] weakHashBad(String password, String apiSecret) throws Exception {
        // ruleid: aegis-java-weak-hash-credential
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes("UTF-8"));
        // a non-password secret is not password storage (an HMAC key, CRAM-MD5)
        // ok: aegis-java-weak-hash-credential
        String s = DigestUtils.sha1Hex(apiSecret);
        return md.digest();
    }

    String hashPassword(String raw) throws Exception {
        // ruleid: aegis-java-weak-hash-credential
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return new String(md.digest(raw.getBytes()));
    }

    Object encoderBad() {
        // ruleid: aegis-java-weak-hash-credential
        return new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("MD5");
    }

    byte[] weakHashOk(byte[] fileBytes, String password) throws Exception {
        // a checksum of file content is not a credential problem
        MessageDigest md = MessageDigest.getInstance("MD5");
        // ok: aegis-java-weak-hash-credential
        md.update(fileBytes);
        // ok: aegis-java-weak-hash-credential
        String etag = DigestUtils.md5Hex(fileBytes);
        // a strong digest over a password is not this rule's concern
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        // ok: aegis-java-weak-hash-credential
        sha.update(password.getBytes());
        return md.digest();
    }

    // ── weak cipher / key size: no context needed ───────────────────────────
    void ciphers(byte[] key) throws Exception {
        Cipher a = Cipher.getInstance("DES/CBC/PKCS5Padding");
        Cipher b = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        Cipher c = Cipher.getInstance("AES");
        Cipher d = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher e = Cipher.getInstance("RC4");
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        Cipher f = Cipher.getInstance("AES/GCM/NoPadding");
        // RSA's "ECB" is a placeholder, not a mode
        Cipher g = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        // "AES" in a key spec names the key type, not a mode
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
    }

    void keys() throws Exception {
        KeyPairGenerator weak = KeyPairGenerator.getInstance("RSA");
        weak.initialize(1024);
        KeyPairGenerator ok = KeyPairGenerator.getInstance("RSA");
        ok.initialize(3072);
    }

    // ── session cookie ──────────────────────────────────────────────────────
    void cookies(HttpServletResponse response, String token, String theme) {
        Cookie a = new Cookie("JSESSIONID", token);
        a.setSecure(true);
        response.addCookie(a);

        Cookie b = new Cookie("auth_token", token);
        b.setHttpOnly(true);
        b.setSecure(false);
        response.addCookie(b);

        Cookie c = new Cookie("auth_token", token);
        c.setHttpOnly(true);
        c.setSecure(true);
        response.addCookie(c);

        Cookie d = new Cookie("theme", theme);
        response.addCookie(d);

        Cookie e = new Cookie("XSRF-TOKEN", token);
        e.setSecure(true);
        response.addCookie(e);

        Cookie gone = new Cookie("session", "");
        gone.setMaxAge(0);
        response.addCookie(gone);

        // clearing a cookie with an empty value (WebGoat JWTVotesEndpoint)
        Cookie cleared = new Cookie("access_token", "");
        response.addCookie(cleared);
    }

    // ── trust boundary ──────────────────────────────────────────────────────
    void trust(HttpServletRequest request, HttpSession session) {
        String name = request.getParameter("name");
        // ruleid: aegis-java-session-trust-boundary
        request.getSession().setAttribute(name, "visited");
        // ruleid: aegis-java-session-trust-boundary
        session.setAttribute("role", request.getParameter("role"));
        // a preference from the request is not a trust decision
        // ok: aegis-java-session-trust-boundary
        session.setAttribute("locale", request.getParameter("lang"));
        // ok: aegis-java-session-trust-boundary
        session.setAttribute("role", lookupRole(session.getId()));
    }

    String springTrust(@RequestParam("admin") String admin, HttpSession session) {
        // ruleid: aegis-java-session-trust-boundary
        session.setAttribute("isAdmin", admin);
        return "ok";
    }

    String lookupRole(String id) { return "user"; }
    interface User { void setPasswordSalt(String s); }
    interface TokenService { String issue(int seed); }
}
