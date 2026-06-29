package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
)

// UserRepository handles persistence for users.
type UserRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create inserts a new user and populates generated columns on the struct.
func (r *UserRepository) Create(ctx context.Context, u *models.User) error {
	const q = `
		INSERT INTO users (email, password_hash, name, role, plan)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at`
	err := r.db.QueryRowxContext(ctx, q,
		u.Email, u.PasswordHash, u.Name, u.Role, u.Plan,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		// Unique violation on email → conflict.
		if strings.Contains(err.Error(), "users_email_key") ||
			strings.Contains(strings.ToLower(err.Error()), "duplicate key") {
			return ErrConflict
		}
		return err
	}
	return nil
}

// GetByEmail loads a user by email (used for login).
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	const q = `SELECT * FROM users WHERE email = $1`
	var u models.User
	if err := r.db.GetContext(ctx, &u, q, email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

// GetByID loads a user by id.
func (r *UserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	const q = `SELECT * FROM users WHERE id = $1`
	var u models.User
	if err := r.db.GetContext(ctx, &u, q, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}
