package middleware

import "net/http"

// SecureHeaders adds defense-in-depth response headers to every API response.
//
// The API only ever returns JSON, so the CSP is maximally strict (`default-src
// 'none'`) and framing is denied outright. HSTS is emitted unconditionally; it
// is inert over plain HTTP (browsers only honor it on HTTPS) and takes effect
// the moment the API is served over TLS in production.
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		// The legacy XSS auditor is deprecated and can introduce vulnerabilities;
		// modern guidance is to disable it explicitly.
		h.Set("X-XSS-Protection", "0")
		next.ServeHTTP(w, r)
	})
}
