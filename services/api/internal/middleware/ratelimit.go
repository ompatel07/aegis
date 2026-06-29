package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/httpx"
)

// RateLimiter is a Redis-backed fixed-window limiter keyed by client IP. Using
// Redis means the limit is shared across API replicas.
type RateLimiter struct {
	rdb    *redis.Client
	rpm    int
	window time.Duration
	log    zerolog.Logger
}

func NewRateLimiter(rdb *redis.Client, rpm int, log zerolog.Logger) *RateLimiter {
	return &RateLimiter{rdb: rdb, rpm: rpm, window: time.Minute, log: log}
}

// Handler is the middleware entrypoint.
func (rl *RateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		// Bucket key changes each window, so counters expire naturally.
		bucket := time.Now().Unix() / int64(rl.window.Seconds())
		key := "aegis:ratelimit:" + ip + ":" + strconv.FormatInt(bucket, 10)

		count, err := rl.rdb.Incr(r.Context(), key).Result()
		if err != nil {
			// Fail open: a Redis blip must not take the API down.
			rl.log.Warn().Err(err).Msg("rate limiter unavailable, allowing request")
			next.ServeHTTP(w, r)
			return
		}
		if count == 1 {
			// First hit in this window — set the expiry.
			rl.rdb.Expire(r.Context(), key, rl.window+time.Second)
		}

		remaining := rl.rpm - int(count)
		if remaining < 0 {
			remaining = 0
		}
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.rpm))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))

		if int(count) > rl.rpm {
			w.Header().Set("Retry-After", strconv.Itoa(int(rl.window.Seconds())))
			httpx.WriteError(w, httpx.NewError(http.StatusTooManyRequests, httpx.CodeRateLimited, "rate limit exceeded"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
