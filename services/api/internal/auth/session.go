package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// SessionStore tracks valid refresh tokens in Redis by their jti. This makes
// refresh-token revocation (logout) and rotation possible despite stateless JWTs.
type SessionStore struct {
	rdb *redis.Client
}

func NewSessionStore(rdb *redis.Client) *SessionStore {
	return &SessionStore{rdb: rdb}
}

func key(jti string) string { return "aegis:session:" + jti }

// Save records a refresh session (jti → userID) with a TTL equal to the token's.
func (s *SessionStore) Save(ctx context.Context, jti, userID string, ttl time.Duration) error {
	if err := s.rdb.Set(ctx, key(jti), userID, ttl).Err(); err != nil {
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

// Revoke deletes a refresh session (logout / rotation).
func (s *SessionStore) Revoke(ctx context.Context, jti string) error {
	if err := s.rdb.Del(ctx, key(jti)).Err(); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}
