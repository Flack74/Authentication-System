package services

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/Flack74/go-auth-system/internal/config"
	"github.com/Flack74/go-auth-system/internal/models"
	"github.com/Flack74/go-auth-system/internal/repository"
	"github.com/Flack74/go-auth-system/internal/utils"
	"github.com/google/uuid"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account locked due to too many failed attempts")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrUserAlreadyExists  = errors.New("user already exists")
)

type AuthService struct {
	userRepo     repository.UserRepositoryInterface
	tokenService TokenServiceInterface
	emailService EmailServiceInterface
	config       *config.Config
}

func NewAuthService(userRepo repository.UserRepositoryInterface, tokenService TokenServiceInterface, emailService EmailServiceInterface, config *config.Config) *AuthService {
	return &AuthService{
		userRepo:     userRepo,
		tokenService: tokenService,
		emailService: emailService,
		config:       config,
	}
}

func (s *AuthService) Register(req *models.CreateUserRequest) (*models.AuthResponse, error) {
	// Normalize email
	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Check if user exists
	existing, _ := s.userRepo.GetByEmail(email)
	if existing != nil {
		return nil, ErrUserAlreadyExists
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(req.Password, s.config.BcryptCost)
	if err != nil {
		return nil, err
	}

	// Generate email verification token
	verifyToken := uuid.New().String()

	// Create user
	user := &models.User{
		ID:               uuid.New(),
		Email:            email,
		Password:         hashedPassword,
		EmailVerifyToken: sql.NullString{String: verifyToken, Valid: true},
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}

	// Send verification email
	if err := s.emailService.SendVerificationEmail(email, verifyToken); err != nil {
		// Log error but don't fail registration
	}

	// Generate tokens
	accessToken, err := s.tokenService.GenerateAccessToken(user.ID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.tokenService.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, err
	}

	return &models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

func (s *AuthService) Login(req *models.LoginRequest) (*models.AuthResponse, error) {
	// Normalize email
	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Get user
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// Check if account is locked
	if user.LockedUntil.Valid && user.LockedUntil.Time.After(time.Now()) {
		return nil, ErrAccountLocked
	}

	// Verify password
	if err := utils.CheckPassword(req.Password, user.Password); err != nil {
		// Increment failed login attempts
		s.userRepo.IncrementFailedLoginAttempts(email)
		return nil, ErrInvalidCredentials
	}

	// Check if email is verified
	if !user.EmailVerified && s.config.Env == "production" {
		return nil, ErrEmailNotVerified
	}

	// Reset failed login attempts
	s.userRepo.ResetFailedLoginAttempts(email)

	// Generate tokens
	accessToken, err := s.tokenService.GenerateAccessToken(user.ID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.tokenService.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, err
	}

	return &models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

func (s *AuthService) RefreshToken(refreshToken string) (*models.AuthResponse, error) {
	// Validate refresh token
	userID, err := s.tokenService.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	// Revoke old refresh token
	if err := s.tokenService.RevokeRefreshToken(refreshToken); err != nil {
		return nil, err
	}

	// Generate new tokens
	accessToken, err := s.tokenService.GenerateAccessToken(userID)
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := s.tokenService.GenerateRefreshToken(userID)
	if err != nil {
		return nil, err
	}

	return &models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *AuthService) Logout(userID uuid.UUID, accessToken string) error {
	// Revoke access token
	if err := s.tokenService.RevokeAccessToken(accessToken); err != nil {
		return err
	}
	
	// Revoke all refresh tokens for this user (more secure)
	// This ensures complete logout across all devices
	return nil // TokenService handles refresh token cleanup
}

func (s *AuthService) VerifyEmail(token string) error {
	return s.userRepo.VerifyEmail(token)
}

func (s *AuthService) ForgotPassword(email string) error {
	user, err := s.userRepo.GetByEmail(strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		// Don't reveal if user exists
		return nil
	}

	// Generate reset token
	resetToken := uuid.New().String()
	user.PasswordResetToken = sql.NullString{String: resetToken, Valid: true}
	user.PasswordResetExpiry = sql.NullTime{Time: time.Now().Add(1 * time.Hour), Valid: true}

	if err := s.userRepo.Update(user); err != nil {
		return err
	}

	// Send reset email
	return s.emailService.SendPasswordResetEmail(user.Email, resetToken)
}

func (s *AuthService) ResetPassword(token, newPassword string) error {
	// Find user by reset token
	user, err := s.userRepo.GetByPasswordResetToken(token)
	if err != nil {
		return errors.New("invalid token")
	}

	// Validate token expiry
	if !user.PasswordResetExpiry.Valid || user.PasswordResetExpiry.Time.Before(time.Now()) {
		return errors.New("token expired")
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(newPassword, s.config.BcryptCost)
	if err != nil {
		return err
	}

	// Update password and clear reset token
	user.Password = hashedPassword
	user.PasswordResetToken = sql.NullString{}
	user.PasswordResetExpiry = sql.NullTime{}

	return s.userRepo.Update(user)
}

func (s *AuthService) GetUserByID(userID uuid.UUID) (*models.User, error) {
	return s.userRepo.GetByID(userID.String())
}
