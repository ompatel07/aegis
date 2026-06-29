package middleware

import (
	"net/http"
	"runtime/debug"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
)

// Recoverer converts a panic into a clean 500 JSON envelope and logs the stack,
// so a single bad handler never crashes the server.
func Recoverer(log zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					// http.ErrAbortHandler is used intentionally; re-panic it.
					if rec == http.ErrAbortHandler {
						panic(rec)
					}
					log.Error().
						Interface("panic", rec).
						Str("request_id", chimw.GetReqID(r.Context())).
						Bytes("stack", debug.Stack()).
						Msg("recovered from panic")
					httpx.WriteError(w, httpx.ErrInternal())
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
