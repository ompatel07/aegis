// Fixtures for rules/taint/java_weakness.yaml (Pass N3).
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
        // ruleid: aegis-java-weak-random-secret
        String resetToken = Long.toHexString(rnd.nextLong());
        long seedless = new Random().nextLong();
        // ruleid: aegis-java-weak-random-secret
        user.setPasswordSalt(Long.toString(seedless));
        // ruleid: aegis-java-weak-random-secret
        this.apiKey = String.valueOf(Math.random()).substring(2);
        // ruleid: aegis-java-weak-random-secret
        Cookie c = new Cookie("remember-me", Integer.toString(ThreadLocalRandom.current().nextInt()));
        // ruleid: aegis-java-weak-random-secret
        session.setAttribute("csrfToken", Double.toString(Math.random()));
    }

    String generateCsrfToken() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            sb.append(CHARS.charAt(rnd.nextInt(CHARS.length())));
        }
        // ruleid: aegis-java-weak-random-secret
        return sb.toString();
    }

    void weakRandomOk(java.util.List<String> items, TokenService tokens) {
        // simulation, shuffling and jitter are not secrets
        // ok: aegis-java-weak-random-secret
        long backoffMs = 1000 + rnd.nextInt(500);
        // ok: aegis-java-weak-random-secret
        int sampleIndex = rnd.nextInt(items.size());
        // the secret word is not the head noun
        // ok: aegis-java-weak-random-secret
        long tokenExpiry = System.currentTimeMillis() + rnd.nextInt(60000);
        // a random value handed to a service does not make its answer weak
        // ok: aegis-java-weak-random-secret
        String accessToken = tokens.issue(rnd.nextInt());
        // the fix
        // ok: aegis-java-weak-random-secret
        String sessionToken = Long.toHexString(secure.nextLong());
        // a race / correlation "token" is not a secret
        // ok: aegis-java-weak-random-secret
        String fetchToken = Long.toHexString(rnd.nextLong());
        // SecureRandom output mixed in
        // ok: aegis-java-weak-random-secret
        String resetToken = Long.toHexString(secure.nextLong()) + rnd.nextInt();
    }

    // ── weak hash: by what is hashed, or what the method is for ──────────────
    byte[] weakHashBad(String password, String apiSecret) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes("UTF-8"));
        // a non-password secret is not password storage (an HMAC key, CRAM-MD5)
        String s = DigestUtils.sha1Hex(apiSecret);
        return md.digest();
    }

    String hashPassword(String raw) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return new String(md.digest(raw.getBytes()));
    }

    Object encoderBad() {
        return new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("MD5");
    }

    byte[] weakHashOk(byte[] fileBytes, String password) throws Exception {
        // a checksum of file content is not a credential problem
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(fileBytes);
        String etag = DigestUtils.md5Hex(fileBytes);
        // a strong digest over a password is not this rule's concern
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(password.getBytes());
        return md.digest();
    }

    // ── weak cipher / key size: no context needed ───────────────────────────
    void ciphers(byte[] key) throws Exception {
        // ruleid: aegis-java-weak-cipher
        Cipher a = Cipher.getInstance("DES/CBC/PKCS5Padding");
        // ruleid: aegis-java-weak-cipher
        Cipher b = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        // ruleid: aegis-java-weak-cipher
        Cipher c = Cipher.getInstance("AES");
        // ruleid: aegis-java-weak-cipher
        Cipher d = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ruleid: aegis-java-weak-cipher
        Cipher e = Cipher.getInstance("RC4");
        // ruleid: aegis-java-weak-cipher
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        // ok: aegis-java-weak-cipher
        Cipher f = Cipher.getInstance("AES/GCM/NoPadding");
        // RSA's "ECB" is a placeholder, not a mode
        // ok: aegis-java-weak-cipher
        Cipher g = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        // "AES" in a key spec names the key type, not a mode
        // ok: aegis-java-weak-cipher
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
    }

    void keys() throws Exception {
        // ruleid: aegis-java-weak-key-size
        KeyPairGenerator weak = KeyPairGenerator.getInstance("RSA");
        weak.initialize(1024);
        KeyPairGenerator ok = KeyPairGenerator.getInstance("RSA");
        // ok: aegis-java-weak-key-size
        ok.initialize(3072);
    }

    // ── session cookie ──────────────────────────────────────────────────────
    void cookies(HttpServletResponse response, String token, String theme) {
        Cookie a = new Cookie("JSESSIONID", token);
        a.setSecure(true);
        // ruleid: aegis-java-insecure-session-cookie
        response.addCookie(a);

        Cookie b = new Cookie("auth_token", token);
        b.setHttpOnly(true);
        // ruleid: aegis-java-insecure-session-cookie
        b.setSecure(false);
        response.addCookie(b);

        Cookie c = new Cookie("auth_token", token);
        c.setHttpOnly(true);
        c.setSecure(true);
        // ok: aegis-java-insecure-session-cookie
        response.addCookie(c);

        Cookie d = new Cookie("theme", theme);
        // ok: aegis-java-insecure-session-cookie
        response.addCookie(d);

        Cookie e = new Cookie("XSRF-TOKEN", token);
        e.setSecure(true);
        // ok: aegis-java-insecure-session-cookie
        response.addCookie(e);

        // a bare "token" cookie used as the CSRF double-submit token
        Cookie csrf = new Cookie("token", token);
        // ok: aegis-java-insecure-session-cookie
        response.addCookie(csrf);

        Cookie gone = new Cookie("session", "");
        gone.setMaxAge(0);
        // ok: aegis-java-insecure-session-cookie
        response.addCookie(gone);

        // clearing a cookie with an empty value (WebGoat JWTVotesEndpoint)
        Cookie cleared = new Cookie("access_token", "");
        // ok: aegis-java-insecure-session-cookie
        response.addCookie(cleared);
    }

    // ── trust boundary ──────────────────────────────────────────────────────
    void trust(HttpServletRequest request, HttpSession session) {
        String name = request.getParameter("name");
        request.getSession().setAttribute(name, "visited");
        session.setAttribute("role", request.getParameter("role"));
        // a preference from the request is not a trust decision
        session.setAttribute("locale", request.getParameter("lang"));
        session.setAttribute("role", lookupRole(session.getId()));
    }

    String springTrust(@RequestParam("admin") String admin, HttpSession session) {
        session.setAttribute("isAdmin", admin);
        return "ok";
    }

    String lookupRole(String id) { return "user"; }
    interface User { void setPasswordSalt(String s); }
    interface TokenService { String issue(int seed); }
}
