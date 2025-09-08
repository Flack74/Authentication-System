package repository

import (
	"github.com/Flack74/go-auth-system/internal/models"
)

// UserRepositoryInterface defines the contract for user repository
type UserRepositoryInterface interface {
	Create(user *models.User) error
	GetByEmail(email string) (*models.User, error)
	GetByID(id string) (*models.User, error)
	Update(user *models.User) error
	VerifyEmail(token string) error
	IncrementFailedLoginAttempts(email string) error
	ResetFailedLoginAttempts(email string) error
	GetByPasswordResetToken(token string) (*models.User, error)
}