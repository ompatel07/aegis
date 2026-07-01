// Test fixtures for rules/taint/go.yaml — consumed by `semgrep --test`.
// Positive cases fire the rule; sanitized negatives must not. Never scanned in
// production (real scans target the cloned repo; --config only loads *.yaml).
package fixtures

import (
	"context"
	"database/sql"
	"html"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/go-ldap/ldap/v3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func validateURL(u string) string { return u }

// ── SQL injection ────────────────────────────────────────────────────────────
func sqliBad(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	// ruleid: aegis-go-sql-injection
	db.Query("SELECT * FROM users WHERE id = " + id)
}

func sqliOk(db *sql.DB, r *http.Request) {
	id := r.URL.Query().Get("id")
	// ok: aegis-go-sql-injection
	db.Query("SELECT * FROM users WHERE id = $1", id)
}

// ── Cross-site scripting ─────────────────────────────────────────────────────
func xssBad(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: aegis-go-xss
	w.Write([]byte("<h1>" + name + "</h1>"))
}

func xssOk(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ok: aegis-go-xss
	w.Write([]byte("<h1>" + html.EscapeString(name) + "</h1>"))
}

// ── OS command injection ─────────────────────────────────────────────────────
func cmdBad(r *http.Request) {
	host := r.URL.Query().Get("host")
	// ruleid: aegis-go-command-injection
	exec.Command("sh", "-c", "ping -c 1 "+host)
}

func cmdOk(r *http.Request) {
	host := r.URL.Query().Get("host")
	// ok: aegis-go-command-injection
	exec.Command("ping", "-c", "1", host)
}

// ── SSRF ─────────────────────────────────────────────────────────────────────
func ssrfBad(r *http.Request) {
	u := r.URL.Query().Get("url")
	// ruleid: aegis-go-ssrf
	http.Get(u)
}

func ssrfOk(r *http.Request) {
	u := r.URL.Query().Get("url")
	safe := validateURL(u)
	// ok: aegis-go-ssrf
	http.Get(safe)
}

// ── Path traversal ───────────────────────────────────────────────────────────
func pathBad(r *http.Request) {
	name := r.URL.Query().Get("file")
	// ruleid: aegis-go-path-traversal
	os.Open("/var/data/" + name)
}

func pathOk(r *http.Request) {
	name := r.URL.Query().Get("file")
	// ok: aegis-go-path-traversal
	os.Open(filepath.Join("/var/data", filepath.Base(name)))
}

// ── NoSQL injection ──────────────────────────────────────────────────────────
func nosqlBad(coll *mongo.Collection, ctx context.Context, r *http.Request) {
	name := r.URL.Query().Get("user")
	// ruleid: aegis-go-nosql-injection
	coll.FindOne(ctx, bson.M{"user": name})
}

func nosqlOk(coll *mongo.Collection, ctx context.Context, r *http.Request) {
	id := r.URL.Query().Get("id")
	oid, _ := primitive.ObjectIDFromHex(id)
	// ok: aegis-go-nosql-injection
	coll.FindOne(ctx, bson.M{"_id": oid})
}

// ── LDAP injection ───────────────────────────────────────────────────────────
func ldapBad(r *http.Request) {
	user := r.URL.Query().Get("user")
	filter := "(uid=" + user + ")"
	// ruleid: aegis-go-ldap-injection
	ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, nil, nil)
}

func ldapOk(r *http.Request) {
	user := r.URL.Query().Get("user")
	filter := "(uid=" + ldap.EscapeFilter(user) + ")"
	// ok: aegis-go-ldap-injection
	ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, nil, nil)
}
