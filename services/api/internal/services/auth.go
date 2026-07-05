package services

import (
	"context"
	"errors"
	"strings"

	"github.com/aegis-platform/api/internal/auth"
	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
)

// AuthService implements registration, login, refresh, and logout.
type AuthService struct {
	users    *repository.UserRepository
	orgs     *repository.OrganizationRepository
	tokens   *auth.TokenManager
	sessions *auth.SessionStore
}

func NewAuthService(users *repository.UserRepository, orgs *repository.OrganizationRepository, tokens *auth.TokenManager, sessions *auth.SessionStore) *AuthService {
	return &AuthService{users: users, orgs: orgs, tokens: tokens, sessions: sessions}
}

// RegisterInput is the validated registration payload.
type RegisterInput struct {
	Email    string
	Password string
	Name     string
}

// Register creates a user and issues an initial token pair.
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (*models.User, *auth.TokenPair, error) {
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		return nil, nil, err
	}

	user := &models.User{
		Email:        in.Email,
		PasswordHash: hash,
		Name:         in.Name,
		Role:         models.RoleUser,
		Plan:         models.PlanFree,
	}
	if err := s.users.Create(ctx, user); err != nil {
		if errors.Is(err, repository.ErrConflict) {
			return nil, nil, ErrEmailTaken
		}
		return nil, nil, err
	}

	// Every user gets a personal organization (they own it) so projects always
	// have an org home (Phase 2C TASK 5).
	orgName := user.Name
	if orgName == "" {
		orgName = "Personal"
	}
	personal := &models.Organization{
		Name:       orgName + "'s workspace",
		Slug:       "ws-" + strings.ReplaceAll(user.ID, "-", ""),
		Plan:       models.PlanFree,
		IsPersonal: true,
	}
	if user.Email != "" {
		personal.BillingEmail = &user.Email
	}
	if err := s.orgs.Create(ctx, personal, user.ID); err != nil {
		return nil, nil, err
	}

	pair, err := s.issue(ctx, user)
	if err != nil {
		return nil, nil, err
	}
	return user, pair, nil
}

// Login verifies credentials and issues a token pair.
func (s *AuthService) Login(ctx context.Context, email, password string) (*models.User, *auth.TokenPair, error) {
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// Avoid leaking which accounts exist — same error as a bad password.
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, err
	}
	if !auth.CheckPassword(user.PasswordHash, password) {
		return nil, nil, ErrInvalidCredentials
	}

	pair, err := s.issue(ctx, user)
	if err != nil {
		return nil, nil, err
	}
	return user, pair, nil
}

// Refresh rotates a refresh token: the old session is revoked and a new pair
// issued. Reusing a revoked/expired refresh token fails.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*auth.TokenPair, error) {
	claims, err := s.tokens.ParseRefresh(refreshToken)
	if err != nil {
		return nil, ErrInvalidRefresh
	}

	ok, err := s.sessions.Valid(ctx, claims.ID, claims.Subject)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalidRefresh
	}

	user, err := s.users.GetByID(ctx, claims.Subject)
	if err != nil {
		return nil, ErrInvalidRefresh
	}

	// Rotate: revoke the presented token's session, then issue a fresh pair.
	if err := s.sessions.Revoke(ctx, claims.ID); err != nil {
		return nil, err
	}
	return s.issue(ctx, user)
}

// Logout revokes the refresh session so it can no longer be used.
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	claims, err := s.tokens.ParseRefresh(refreshToken)
	if err != nil {
		// Nothing to revoke for an invalid token; treat logout as idempotent.
		return nil
	}
	return s.sessions.Revoke(ctx, claims.ID)
}

// issue creates a token pair and records the refresh session in Redis.
func (s *AuthService) issue(ctx context.Context, user *models.User) (*auth.TokenPair, error) {
	pair, err := s.tokens.GeneratePair(user.ID, user.Email, user.Role)
	if err != nil {
		return nil, err
	}
	if err := s.sessions.Save(ctx, pair.RefreshID, user.ID, s.tokens.RefreshTTL()); err != nil {
		return nil, err
	}
	return pair, nil
}
