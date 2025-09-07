package repository

import (
	"database/sql"
	"time"

	"github.com/Flack74/go-auth-system/internal/models"
	"github.com/google/uuid"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *models.User) error {
	query := `
        INSERT INTO users (id, email, password, email_verify_token, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
    `
	_, err := r.db.Exec(query,
		user.ID,
		user.Email,
		user.Password,
		user.EmailVerifyToken,
		user.CreatedAt,
		user.UpdatedAt,
	)
	return err
}

func (r *UserRepository) GetByEmail(email string) (*models.User, error) {
	user := &models.User{}
	query := `
        SELECT id, email, password, email_verified, email_verify_token,
               password_reset_token, password_reset_expiry, failed_login_attempts,
               locked_until, created_at, updated_at
        FROM users
        WHERE email = $1
    `
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.EmailVerified,
		&user.EmailVerifyToken,
		&user.PasswordResetToken,
		&user.PasswordResetExpiry,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) GetByID(id uuid.UUID) (*models.User, error) {
	user := &models.User{}
	query := `
        SELECT id, email, password, email_verified, created_at, updated_at
        FROM users
        WHERE id = $1
    `
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) Update(user *models.User) error {
	query := `
        UPDATE users
        SET email = $2, password = $3, email_verified = $4, email_verify_token = $5,
            password_reset_token = $6, password_reset_expiry = $7,
            failed_login_attempts = $8, locked_until = $9, updated_at = $10
        WHERE id = $1
    `
	_, err := r.db.Exec(query,
		user.ID,
		user.Email,
		user.Password,
		user.EmailVerified,
		user.EmailVerifyToken,
		user.PasswordResetToken,
		user.PasswordResetExpiry,
		user.FailedLoginAttempts,
		user.LockedUntil,
		time.Now(),
	)
	return err
}

func (r *UserRepository) VerifyEmail(token string) error {
	query := `
        UPDATE users
        SET email_verified = true, email_verify_token = NULL, updated_at = $2
        WHERE email_verify_token = $1 AND email_verified = false
    `
	result, err := r.db.Exec(query, token, time.Now())
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (r *UserRepository) IncrementFailedLoginAttempts(email string) error {
	query := `
        UPDATE users
        SET failed_login_attempts = failed_login_attempts + 1,
            locked_until = CASE
                WHEN failed_login_attempts >= 4 THEN $2
                ELSE locked_until
            END,
            updated_at = $3
        WHERE email = $1
    `
	_, err := r.db.Exec(query, email, time.Now().Add(30*time.Minute), time.Now())
	return err
}

func (r *UserRepository) ResetFailedLoginAttempts(email string) error {
	query := `
        UPDATE users
        SET failed_login_attempts = 0, locked_until = NULL, updated_at = $2
        WHERE email = $1
    `
	_, err := r.db.Exec(query, email, time.Now())
	return err
}

func (r *UserRepository) GetByPasswordResetToken(token string) (*models.User, error) {
	user := &models.User{}
	query := `
        SELECT id, email, password, email_verified, email_verify_token,
               password_reset_token, password_reset_expiry, failed_login_attempts,
               locked_until, created_at, updated_at
        FROM users
        WHERE password_reset_token = $1
    `
	err := r.db.QueryRow(query, token).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.EmailVerified,
		&user.EmailVerifyToken,
		&user.PasswordResetToken,
		&user.PasswordResetExpiry,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}
