package auth

import (
	"testing"
	"time"
)

func newTM() *TokenManager {
	return NewTokenManager("access-secret-access-secret-1234", "refresh-secret-refresh-secret-12", time.Hour, 24*time.Hour)
}

func TestGenerateAccessTokenRoundTrips(t *testing.T) {
	tm := newTM()
	tok, expiresIn, err := tm.GenerateAccessToken("user-123", "u@example.com", "user", 30*time.Minute)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if expiresIn != int((30 * time.Minute).Seconds()) {
		t.Fatalf("expiresIn = %d, want 1800", expiresIn)
	}
	claims, err := tm.ParseAccess(tok)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.Subject != "user-123" || claims.Email != "u@example.com" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
}

func TestImpersonationTokenCappedToOneHour(t *testing.T) {
	tm := newTM()
	// A request for a 5-hour token must be capped to 1 hour (impersonation limit).
	_, expiresIn, err := tm.GenerateAccessToken("u", "e", "user", 5*time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if expiresIn != int(time.Hour.Seconds()) {
		t.Fatalf("expiresIn = %d, want 3600 (capped)", expiresIn)
	}
}

func TestImpersonationTokenExpires(t *testing.T) {
	tm := newTM()
	// A token issued with a 1ms TTL must be rejected once it has elapsed.
	tok, _, err := tm.GenerateAccessToken("u", "e", "user", time.Millisecond)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	time.Sleep(1200 * time.Millisecond) // past the exp + jwt's leeway
	if _, err := tm.ParseAccess(tok); err == nil {
		t.Fatalf("expected expired token to be rejected")
	}
}

func TestRandomTokenIsUniqueHex(t *testing.T) {
	a, b := RandomToken(), RandomToken()
	if a == b || len(a) != 48 {
		t.Fatalf("expected distinct 48-char tokens, got %q / %q", a, b)
	}
}
