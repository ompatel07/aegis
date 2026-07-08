package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// RandomToken returns a 48-hex-char cryptographically-random token (for beta
// invitations and similar opaque secrets).
func RandomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Token types embedded in the JWT "typ" claim to prevent cross-use.
const (
	tokenTypeAccess  = "access"
	tokenTypeRefresh = "refresh"
)

// ErrInvalidToken is returned for any malformed/expired/wrong-type token.
var ErrInvalidToken = errors.New("invalid or expired token")

// Claims is the JWT payload for both access and refresh tokens.
type Claims struct {
	Email     string `json:"email,omitempty"`
	Role      string `json:"role,omitempty"`
	TokenType string `json:"typ"`
	jwt.RegisteredClaims
}

// TokenManager issues and verifies JWTs using separate access/refresh secrets.
type TokenManager struct {
	accessSecret  []byte
	refreshSecret []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
}

func NewTokenManager(accessSecret, refreshSecret string, accessTTL, refreshTTL time.Duration) *TokenManager {
	return &TokenManager{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
	}
}

// TokenPair bundles a freshly issued access + refresh token.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // access token lifetime in seconds
	TokenType    string `json:"token_type"` // always "Bearer"
	// RefreshID is the refresh token's jti, used to manage the server session.
	RefreshID string `json:"-"`
}

// GeneratePair issues an access token and a refresh token for the user.
func (m *TokenManager) GeneratePair(userID, email, role string) (*TokenPair, error) {
	now := time.Now()

	access, err := m.sign(m.accessSecret, &Claims{
		Email:     email,
		Role:      role,
		TokenType: tokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessTTL)),
		},
	})
	if err != nil {
		return nil, err
	}

	jti := uuid.NewString()
	refresh, err := m.sign(m.refreshSecret, &Claims{
		TokenType: tokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.refreshTTL)),
		},
	})
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    int(m.accessTTL.Seconds()),
		TokenType:    "Bearer",
		RefreshID:    jti,
	}, nil
}

// GenerateAccessToken issues a standalone access token for a user with an
// explicit TTL (capped by the manager's default). Used for admin impersonation,
// which must be short-lived. Returns the token + its lifetime in seconds.
func (m *TokenManager) GenerateAccessToken(userID, email, role string, ttl time.Duration) (string, int, error) {
	if ttl <= 0 || ttl > time.Hour {
		ttl = time.Hour
	}
	now := time.Now()
	tok, err := m.sign(m.accessSecret, &Claims{
		Email:     email,
		Role:      role,
		TokenType: tokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	})
	if err != nil {
		return "", 0, err
	}
	return tok, int(ttl.Seconds()), nil
}

// ParseAccess validates an access token and returns its claims.
func (m *TokenManager) ParseAccess(tokenStr string) (*Claims, error) {
	return m.parse(tokenStr, m.accessSecret, tokenTypeAccess)
}

// ParseRefresh validates a refresh token and returns its claims.
func (m *TokenManager) ParseRefresh(tokenStr string) (*Claims, error) {
	return m.parse(tokenStr, m.refreshSecret, tokenTypeRefresh)
}

// RefreshTTL exposes the configured refresh lifetime (for session TTLs).
func (m *TokenManager) RefreshTTL() time.Duration { return m.refreshTTL }

func (m *TokenManager) sign(secret []byte, claims *Claims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func (m *TokenManager) parse(tokenStr string, secret []byte, wantType string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return secret, nil
	})
	if err != nil || !token.Valid || claims.TokenType != wantType {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
