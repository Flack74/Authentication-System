package repository

import (
	"errors"
	"time"

	"github.com/Flack74/go-auth-system/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type GormUserRepository struct {
	db *gorm.DB
}

func NewGormUserRepository(db *gorm.DB) *GormUserRepository {
	return &GormUserRepository{db: db}
}

func (r *GormUserRepository) Create(user *models.User) error {
	gormUser := &models.GormUser{}
	gormUser.FromUser(user)
	
	result := r.db.Create(gormUser)
	if result.Error != nil {
		return result.Error
	}
	
	// Update the original user with generated ID
	*user = *gormUser.ToUser()
	return nil
}

func (r *GormUserRepository) GetByEmail(email string) (*models.User, error) {
	var gormUser models.GormUser
	
	result := r.db.Where("email = ?", email).First(&gormUser)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	
	return gormUser.ToUser(), nil
}

func (r *GormUserRepository) GetByID(id string) (*models.User, error) {
	userID, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}
	
	var gormUser models.GormUser
	
	result := r.db.Where("id = ?", userID).First(&gormUser)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	
	return gormUser.ToUser(), nil
}

func (r *GormUserRepository) Update(user *models.User) error {
	gormUser := &models.GormUser{}
	gormUser.FromUser(user)
	
	result := r.db.Save(gormUser)
	return result.Error
}

func (r *GormUserRepository) VerifyEmail(token string) error {
	result := r.db.Model(&models.GormUser{}).
		Where("email_verify_token = ?", token).
		Updates(map[string]interface{}{
			"email_verified":      true,
			"email_verify_token": nil,
		})
	
	if result.Error != nil {
		return result.Error
	}
	
	if result.RowsAffected == 0 {
		return errors.New("invalid verification token")
	}
	
	return nil
}

func (r *GormUserRepository) IncrementFailedLoginAttempts(email string) error {
	result := r.db.Model(&models.GormUser{}).
		Where("email = ?", email).
		Update("failed_login_attempts", gorm.Expr("failed_login_attempts + 1"))
	
	return result.Error
}

func (r *GormUserRepository) LockAccount(email string, lockDuration time.Duration) error {
	lockUntil := time.Now().Add(lockDuration)
	
	result := r.db.Model(&models.GormUser{}).
		Where("email = ?", email).
		Update("locked_until", lockUntil)
	
	return result.Error
}

func (r *GormUserRepository) ResetFailedAttempts(email string) error {
	result := r.db.Model(&models.GormUser{}).
		Where("email = ?", email).
		Updates(map[string]interface{}{
			"failed_login_attempts": 0,
			"locked_until":          nil,
		})
	
	return result.Error
}

func (r *GormUserRepository) GetByPasswordResetToken(token string) (*models.User, error) {
	var gormUser models.GormUser
	
	result := r.db.Where("password_reset_token = ? AND password_reset_expiry > ?", 
		token, time.Now()).First(&gormUser)
	
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	
	return gormUser.ToUser(), nil
}

func (r *GormUserRepository) ResetFailedLoginAttempts(email string) error {
	result := r.db.Model(&models.GormUser{}).
		Where("email = ?", email).
		Updates(map[string]interface{}{
			"failed_login_attempts": 0,
			"locked_until":          nil,
		})
	
	return result.Error
}