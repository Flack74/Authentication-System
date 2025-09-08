package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GormUser represents the GORM version of User model
type GormUser struct {
	ID                  uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Email               string         `gorm:"unique;not null" json:"email"`
	Password            string         `gorm:"not null" json:"-"`
	EmailVerified       bool           `gorm:"default:false" json:"email_verified"`
	EmailVerifyToken    *string        `gorm:"index" json:"-"`
	PasswordResetToken  *string        `gorm:"index" json:"-"`
	PasswordResetExpiry *time.Time     `json:"-"`
	FailedLoginAttempts int            `gorm:"default:0" json:"-"`
	LockedUntil         *time.Time     `gorm:"index" json:"-"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
	DeletedAt           gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName specifies the table name for GORM
func (GormUser) TableName() string {
	return "users"
}

// BeforeCreate hook to generate UUID
func (u *GormUser) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// ToUser converts GormUser to User model
func (u *GormUser) ToUser() *User {
	user := &User{
		ID:                  u.ID,
		Email:               u.Email,
		Password:            u.Password,
		EmailVerified:       u.EmailVerified,
		FailedLoginAttempts: u.FailedLoginAttempts,
		CreatedAt:           u.CreatedAt,
		UpdatedAt:           u.UpdatedAt,
	}

	if u.EmailVerifyToken != nil {
		user.EmailVerifyToken.String = *u.EmailVerifyToken
		user.EmailVerifyToken.Valid = true
	}

	if u.PasswordResetToken != nil {
		user.PasswordResetToken.String = *u.PasswordResetToken
		user.PasswordResetToken.Valid = true
	}

	if u.PasswordResetExpiry != nil {
		user.PasswordResetExpiry.Time = *u.PasswordResetExpiry
		user.PasswordResetExpiry.Valid = true
	}

	if u.LockedUntil != nil {
		user.LockedUntil.Time = *u.LockedUntil
		user.LockedUntil.Valid = true
	}

	return user
}

// FromUser converts User to GormUser model
func (u *GormUser) FromUser(user *User) {
	u.ID = user.ID
	u.Email = user.Email
	u.Password = user.Password
	u.EmailVerified = user.EmailVerified
	u.FailedLoginAttempts = user.FailedLoginAttempts
	u.CreatedAt = user.CreatedAt
	u.UpdatedAt = user.UpdatedAt

	if user.EmailVerifyToken.Valid {
		u.EmailVerifyToken = &user.EmailVerifyToken.String
	}

	if user.PasswordResetToken.Valid {
		u.PasswordResetToken = &user.PasswordResetToken.String
	}

	if user.PasswordResetExpiry.Valid {
		u.PasswordResetExpiry = &user.PasswordResetExpiry.Time
	}

	if user.LockedUntil.Valid {
		u.LockedUntil = &user.LockedUntil.Time
	}
}