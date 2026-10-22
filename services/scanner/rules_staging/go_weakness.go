// Fixtures for rules_staging/go_weakness.yaml (Pass N3, staged).
package fixtures

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"

	"github.com/gorilla/sessions"
)

const letters = "abcdefghijklmnopqrstuvwxyz0123456789"

// ── weak random ─────────────────────────────────────────────────────────────
func weakRandomBad(u *User) {
	// ruleid: aegis-go-weak-random-secret
	resetToken := strconv.FormatInt(rand.Int63(), 36)
	n := rand.Intn(1000000)
	// ruleid: aegis-go-weak-random-secret
	u.OTPCode = fmt.Sprintf("%06d", n)
	buf := make([]byte, 16)
	rand.Read(buf)
	// ruleid: aegis-go-weak-random-secret
	apiKey := hex.EncodeToString(buf)
	// ruleid: aegis-go-weak-random-secret
	s := Session{AuthToken: strconv.Itoa(rand.Int())}
	// a correlation id named like a session is not a secret
	// ok: aegis-go-weak-random-secret
	c := Session{SessionID: strconv.Itoa(rand.Int())}
	_ = c
	_, _, _ = resetToken, apiKey, s
}

func generateSalt() string {
	// ruleid: aegis-go-weak-random-secret
	return strconv.FormatUint(rand.Uint64(), 16)
}

func weakRandomOk(items []string, tokens TokenService) {
	// ok: aegis-go-weak-random-secret
	backoff := 100 + rand.Intn(50)
	// ok: aegis-go-weak-random-secret
	pick := items[rand.Intn(len(items))]
	// the secret word is not the head noun
	// ok: aegis-go-weak-random-secret
	tokenTTL := 3600 + rand.Intn(60)
	// a random value handed to a service does not make its answer weak
	// ok: aegis-go-weak-random-secret
	sessionToken := tokens.Issue(rand.Int())
	_, _, _, _ = backoff, pick, tokenTTL, sessionToken
}

// ── weak hash ───────────────────────────────────────────────────────────────
func weakHashBad(password string, apiSecret []byte) {
	// ruleid: aegis-go-weak-hash-credential
	a := md5.Sum([]byte(password))
	// ruleid: aegis-go-weak-hash-credential
	h := sha1.New()
	io.WriteString(h, password)
	// a non-password secret is not password storage (an HMAC key)
	// ok: aegis-go-weak-hash-credential
	k := sha1.Sum(apiSecret)
	_ = k
	_ = a
}

func hashPassword(raw string) string {
	// ruleid: aegis-go-weak-hash-credential
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func weakHashOk(body []byte) string {
	// a checksum / ETag is not a credential problem
	// ok: aegis-go-weak-hash-credential
	sum := md5.Sum(body)
	return hex.EncodeToString(sum[:])
}

// ── weak cipher / key size: no context needed ───────────────────────────────
func ciphers(key []byte) {
	a, _ := des.NewCipher(key)
	b, _ := des.NewTripleDESCipher(key)
	c, _ := rc4.NewCipher(key)
	_, _, _ = a, b, c
}

func keys(r io.Reader) {
	// ruleid: aegis-go-weak-key-size
	weak, _ := rsa.GenerateKey(r, 1024)
	// ok: aegis-go-weak-key-size
	ok, _ := rsa.GenerateKey(r, 3072)
	_, _ = weak, ok
}

// ── session cookie ──────────────────────────────────────────────────────────
func cookies(w http.ResponseWriter, token string) {
	// ruleid: aegis-go-insecure-session-cookie
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: token, Path: "/"})
	// ruleid: aegis-go-insecure-session-cookie
	http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: token, HttpOnly: true, Secure: false})
	// ok: aegis-go-insecure-session-cookie
	http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: token, HttpOnly: true, Secure: true})
	// ok: aegis-go-insecure-session-cookie
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: token, Secure: true})
	// ok: aegis-go-insecure-session-cookie
	http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark"})
	// deleting a cookie carries no secret
	// ok: aegis-go-insecure-session-cookie
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "", MaxAge: -1})
	// flags set on the variable afterwards
	// ok: aegis-go-insecure-session-cookie
	c := &http.Cookie{Name: "session_id", Value: token}
	c.HttpOnly = true
	c.Secure = true
	http.SetCookie(w, c)
}

func ginCookies(ctx GinContext, token string) {
	// ruleid: aegis-go-insecure-session-cookie
	ctx.SetCookie("session", token, 3600, "/", "", false, true)
	// ok: aegis-go-insecure-session-cookie
	ctx.SetCookie("session", token, 3600, "/", "", true, true)
}

// ── trust boundary ──────────────────────────────────────────────────────────
func trust(w http.ResponseWriter, r *http.Request, store *sessions.CookieStore) {
	sess, _ := store.Get(r, "app")
	// ruleid: aegis-go-session-trust-boundary
	sess.Values[r.FormValue("key")] = "x"
	// ruleid: aegis-go-session-trust-boundary
	sess.Values["role"] = r.FormValue("role")
	// ok: aegis-go-session-trust-boundary
	sess.Values["locale"] = r.FormValue("lang")
	// ok: aegis-go-session-trust-boundary
	sess.Values["role"] = lookupRole(sess.ID)
	sess.Save(r, w)
}

type User struct{ OTPCode string }
type Session struct{ SessionID, AuthToken string }
type TokenService interface{ Issue(int) string }
type GinContext interface {
	SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool)
}

func lookupRole(id string) string { return "user" }
