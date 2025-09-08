package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/Flack74/go-auth-system/internal/db"
	"github.com/Flack74/go-auth-system/internal/models"
	"github.com/google/uuid"
)

type SqlcUserRepository struct {
	queries *db.Queries
}

func NewSqlcUserRepository(dbConn *sql.DB) *SqlcUserRepository {
	return &SqlcUserRepository{
		queries: db.New(dbConn),
	}
}

func (r *SqlcUserRepository) Create(user *models.User) error {
	ctx := context.Background()
	
	_, err := r.queries.CreateUser(ctx, db.CreateUserParams{
		ID:               user.ID,
		Email:            user.Email,
		Password:         user.Password,
		EmailVerifyToken: user.EmailVerifyToken,
		CreatedAt:        sql.NullTime{Time: user.CreatedAt, Valid: true},
		UpdatedAt:        sql.NullTime{Time: user.UpdatedAt, Valid: true},
	})
	
	return err
}

func (r *SqlcUserRepository) GetByEmail(email string) (*models.User, error) {
	ctx := context.Background()
	
	dbUser, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	
	return &models.User{
		ID:                  dbUser.ID,
		Email:               dbUser.Email,
		Password:            dbUser.Password,
		EmailVerified:       dbUser.EmailVerified.Bool,
		EmailVerifyToken:    dbUser.EmailVerifyToken,
		PasswordResetToken:  dbUser.PasswordResetToken,
		PasswordResetExpiry: dbUser.PasswordResetExpiry,
		FailedLoginAttempts: int(dbUser.FailedLoginAttempts.Int32),
		LockedUntil:         dbUser.LockedUntil,
		CreatedAt:           dbUser.CreatedAt.Time,
		UpdatedAt:           dbUser.UpdatedAt.Time,
	}, nil
}

func (r *SqlcUserRepository) GetByID(id string) (*models.User, error) {
	ctx := context.Background()
	
	userID, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}
	
	dbUser, err := r.queries.GetUserByID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	
	return &models.User{
		ID:                  dbUser.ID,
		Email:               dbUser.Email,
		Password:            dbUser.Password,
		EmailVerified:       dbUser.EmailVerified.Bool,
		EmailVerifyToken:    dbUser.EmailVerifyToken,
		PasswordResetToken:  dbUser.PasswordResetToken,
		PasswordResetExpiry: dbUser.PasswordResetExpiry,
		FailedLoginAttempts: int(dbUser.FailedLoginAttempts.Int32),
		LockedUntil:         dbUser.LockedUntil,
		CreatedAt:           dbUser.CreatedAt.Time,
		UpdatedAt:           dbUser.UpdatedAt.Time,
	}, nil
}

func (r *SqlcUserRepository) Update(user *models.User) error {
	ctx := context.Background()
	
	return r.queries.UpdateUser(ctx, db.UpdateUserParams{
		ID:                  user.ID,
		Email:               user.Email,
		Password:            user.Password,
		EmailVerified:       sql.NullBool{Bool: user.EmailVerified, Valid: true},
		EmailVerifyToken:    user.EmailVerifyToken,
		PasswordResetToken:  user.PasswordResetToken,
		PasswordResetExpiry: user.PasswordResetExpiry,
		FailedLoginAttempts: sql.NullInt32{Int32: int32(user.FailedLoginAttempts), Valid: true},
		LockedUntil:         user.LockedUntil,
		UpdatedAt:           sql.NullTime{Time: time.Now(), Valid: true},
	})
}

func (r *SqlcUserRepository) VerifyEmail(token string) error {
	ctx := context.Background()
	return r.queries.VerifyEmail(ctx, db.VerifyEmailParams{
		EmailVerifyToken: sql.NullString{String: token, Valid: true},
		UpdatedAt:        sql.NullTime{Time: time.Now(), Valid: true},
	})
}

func (r *SqlcUserRepository) IncrementFailedLoginAttempts(email string) error {
	ctx := context.Background()
	return r.queries.IncrementFailedLoginAttempts(ctx, db.IncrementFailedLoginAttemptsParams{
		Email:       email,
		LockedUntil: sql.NullTime{Time: time.Now().Add(30 * time.Minute), Valid: true},
		UpdatedAt:   sql.NullTime{Time: time.Now(), Valid: true},
	})
}

func (r *SqlcUserRepository) ResetFailedLoginAttempts(email string) error {
	ctx := context.Background()
	return r.queries.ResetFailedLoginAttempts(ctx, db.ResetFailedLoginAttemptsParams{
		Email:     email,
		UpdatedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
}

func (r *SqlcUserRepository) GetByPasswordResetToken(token string) (*models.User, error) {
	ctx := context.Background()
	
	dbUser, err := r.queries.GetUserByPasswordResetToken(ctx, sql.NullString{String: token, Valid: true})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	
	return &models.User{
		ID:                  dbUser.ID,
		Email:               dbUser.Email,
		Password:            dbUser.Password,
		EmailVerified:       dbUser.EmailVerified.Bool,
		EmailVerifyToken:    dbUser.EmailVerifyToken,
		PasswordResetToken:  dbUser.PasswordResetToken,
		PasswordResetExpiry: dbUser.PasswordResetExpiry,
		FailedLoginAttempts: int(dbUser.FailedLoginAttempts.Int32),
		LockedUntil:         dbUser.LockedUntil,
		CreatedAt:           dbUser.CreatedAt.Time,
		UpdatedAt:           dbUser.UpdatedAt.Time,
	}, nil
}