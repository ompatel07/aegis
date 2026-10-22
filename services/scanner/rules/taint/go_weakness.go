// Fixtures for rules/taint/go_weakness.yaml (Pass N3).
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
	resetToken := strconv.FormatInt(rand.Int63(), 36)
	n := rand.Intn(1000000)
	u.OTPCode = fmt.Sprintf("%06d", n)
	buf := make([]byte, 16)
	rand.Read(buf)
	apiKey := hex.EncodeToString(buf)
	s := Session{AuthToken: strconv.Itoa(rand.Int())}
	// a correlation id named like a session is not a secret
	c := Session{SessionID: strconv.Itoa(rand.Int())}
	_ = c
	_, _, _ = resetToken, apiKey, s
}

func generateSalt() string {
	return strconv.FormatUint(rand.Uint64(), 16)
}

func weakRandomOk(items []string, tokens TokenService) {
	backoff := 100 + rand.Intn(50)
	pick := items[rand.Intn(len(items))]
	// the secret word is not the head noun
	tokenTTL := 3600 + rand.Intn(60)
	// a random value handed to a service does not make its answer weak
	sessionToken := tokens.Issue(rand.Int())
	_, _, _, _ = backoff, pick, tokenTTL, sessionToken
}

// ── weak hash ───────────────────────────────────────────────────────────────
func weakHashBad(password string, apiSecret []byte) {
	a := md5.Sum([]byte(password))
	h := sha1.New()
	io.WriteString(h, password)
	// a non-password secret is not password storage (an HMAC key)
	k := sha1.Sum(apiSecret)
	_ = k
	_ = a
}

func hashPassword(raw string) string {
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func weakHashOk(body []byte) string {
	// a checksum / ETag is not a credential problem
	sum := md5.Sum(body)
	return hex.EncodeToString(sum[:])
}

// ── weak cipher / key size: no context needed ───────────────────────────────
func ciphers(key []byte) {
	// ruleid: aegis-go-weak-cipher
	a, _ := des.NewCipher(key)
	// ruleid: aegis-go-weak-cipher
	b, _ := des.NewTripleDESCipher(key)
	// ruleid: aegis-go-weak-cipher
	c, _ := rc4.NewCipher(key)
	_, _, _ = a, b, c
}

func keys(r io.Reader) {
	weak, _ := rsa.GenerateKey(r, 1024)
	ok, _ := rsa.GenerateKey(r, 3072)
	_, _ = weak, ok
}

// ── session cookie ──────────────────────────────────────────────────────────
func cookies(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: token, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: token, HttpOnly: true, Secure: false})
	http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: token, HttpOnly: true, Secure: true})
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: token, Secure: true})
	http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark"})
	// deleting a cookie carries no secret
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "", MaxAge: -1})
	// flags set on the variable afterwards
	c := &http.Cookie{Name: "session_id", Value: token}
	c.HttpOnly = true
	c.Secure = true
	http.SetCookie(w, c)
}

func ginCookies(ctx GinContext, token string) {
	ctx.SetCookie("session", token, 3600, "/", "", false, true)
	ctx.SetCookie("session", token, 3600, "/", "", true, true)
}

// ── trust boundary ──────────────────────────────────────────────────────────
func trust(w http.ResponseWriter, r *http.Request, store *sessions.CookieStore) {
	sess, _ := store.Get(r, "app")
	sess.Values[r.FormValue("key")] = "x"
	sess.Values["role"] = r.FormValue("role")
	sess.Values["locale"] = r.FormValue("lang")
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
