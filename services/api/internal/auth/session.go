package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// SessionStore tracks valid refresh tokens in Redis by their jti. This makes
// refresh-token revocation (logout) and rotation possible despite stateless JWTs.
//
// Alongside the per-jti record it maintains a per-user index (a Redis set of
// that user's active jtis) so we can revoke every session at once — required on
// password change / "log out everywhere" — and enforce concurrent-session limits.
type SessionStore struct {
	rdb *redis.Client
}

func NewSessionStore(rdb *redis.Client) *SessionStore {
	return &SessionStore{rdb: rdb}
}

func key(jti string) string      { return "aegis:session:" + jti }
func userKey(userID string) string { return "aegis:user_sessions:" + userID }

// Save records a refresh session (jti → userID) with a TTL equal to the token's,
// and indexes the jti under the user so it can be revoked en masse.
func (s *SessionStore) Save(ctx context.Context, jti, userID string, ttl time.Duration) error {
	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, key(jti), userID, ttl)
	pipe.SAdd(ctx, userKey(userID), jti)
	// Keep the index from growing unbounded: expire it a hair past the longest
	// possible session. Re-set on each Save so an active user's index survives.
	pipe.Expire(ctx, userKey(userID), ttl+time.Hour)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

// Valid reports whether a refresh session exists and belongs to userID.
func (s *SessionStore) Valid(ctx context.Context, jti, userID string) (bool, error) {
	got, err := s.rdb.Get(ctx, key(jti)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read session: %w", err)
	}
	return got == userID, nil
}

// Revoke deletes a single refresh session (logout / rotation) and de-indexes it.
func (s *SessionStore) Revoke(ctx context.Context, jti string) error {
	// Read the owner first so we can remove the jti from that user's index.
	userID, err := s.rdb.Get(ctx, key(jti)).Result()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	pipe := s.rdb.TxPipeline()
	pipe.Del(ctx, key(jti))
	if err != redis.Nil {
		pipe.SRem(ctx, userKey(userID), jti)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeAllForUser invalidates every refresh session a user holds. Call this on
// password change/reset and account suspension so stolen or stale sessions die
// immediately.
func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID string) error {
	jtis, err := s.rdb.SMembers(ctx, userKey(userID)).Result()
	if err != nil {
		return fmt.Errorf("list user sessions: %w", err)
	}
	pipe := s.rdb.TxPipeline()
	for _, jti := range jtis {
		pipe.Del(ctx, key(jti))
	}
	pipe.Del(ctx, userKey(userID))
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("revoke all sessions: %w", err)
	}
	return nil
}

// CountForUser returns the number of active refresh sessions for a user, so
// callers can enforce a concurrent-session cap.
func (s *SessionStore) CountForUser(ctx context.Context, userID string) (int64, error) {
	n, err := s.rdb.SCard(ctx, userKey(userID)).Result()
	if err != nil {
		return 0, fmt.Errorf("count user sessions: %w", err)
	}
	return n, nil
}
