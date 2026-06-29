// Package auth provides password hashing, JWT issuance/verification, refresh
// session management, and symmetric encryption for integration secrets.
package auth

import "golang.org/x/crypto/bcrypt"

// bcryptCost balances security and latency. 12 is a sane production default.
const bcryptCost = 12

// HashPassword returns a bcrypt hash of the plaintext password.
func HashPassword(plaintext string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword reports whether plaintext matches the stored bcrypt hash.
func CheckPassword(hash, plaintext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}
