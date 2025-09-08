package services

import (
	"errors"
	"testing"
	"time"

	"github.com/Flack74/go-auth-system/internal/config"
	"github.com/Flack74/go-auth-system/internal/models"
	"github.com/Flack74/go-auth-system/internal/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock interfaces
type MockUserRepo struct {
	mock.Mock
}

func (m *MockUserRepo) Create(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepo) GetByEmail(email string) (*models.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepo) GetByID(id string) (*models.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepo) LockAccount(email string, lockDuration time.Duration) error {
	args := m.Called(email, lockDuration)
	return args.Error(0)
}

func (m *MockUserRepo) Update(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepo) VerifyEmail(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockUserRepo) IncrementFailedLoginAttempts(email string) error {
	args := m.Called(email)
	return args.Error(0)
}

func (m *MockUserRepo) ResetFailedLoginAttempts(email string) error {
	args := m.Called(email)
	return args.Error(0)
}

func (m *MockUserRepo) GetByPasswordResetToken(token string) (*models.User, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

type MockTokenSvc struct {
	mock.Mock
}

func (m *MockTokenSvc) GenerateAccessToken(userID uuid.UUID) (string, error) {
	args := m.Called(userID)
	return args.String(0), args.Error(1)
}

func (m *MockTokenSvc) GenerateRefreshToken(userID uuid.UUID) (string, error) {
	args := m.Called(userID)
	return args.String(0), args.Error(1)
}

func (m *MockTokenSvc) ValidateAccessToken(token string) (uuid.UUID, error) {
	args := m.Called(token)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockTokenSvc) ValidateRefreshToken(token string) (uuid.UUID, error) {
	args := m.Called(token)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockTokenSvc) RevokeToken(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockTokenSvc) RevokeRefreshToken(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockTokenSvc) RevokeAccessToken(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

type MockEmailSvc struct {
	mock.Mock
}

func (m *MockEmailSvc) SendVerificationEmail(email, token string) error {
	args := m.Called(email, token)
	return args.Error(0)
}

func (m *MockEmailSvc) SendPasswordResetEmail(email, token string) error {
	args := m.Called(email, token)
	return args.Error(0)
}

// Unit Tests
func TestAuthService_Register_Success(t *testing.T) {
	mockRepo := new(MockUserRepo)
	mockToken := new(MockTokenSvc)
	mockEmail := new(MockEmailSvc)
	
	cfg := &config.Config{BcryptCost: 4}
	service := &AuthService{
		userRepo:     mockRepo,
		tokenService: mockToken,
		emailService: mockEmail,
		config:       cfg,
	}

	req := &models.CreateUserRequest{
		Email:    "test@example.com",
		Password: "TestPass123!",
	}

	// Mock expectations
	mockRepo.On("GetByEmail", "test@example.com").Return(nil, errors.New("not found"))
	mockRepo.On("Create", mock.AnythingOfType("*models.User")).Return(nil)
	mockToken.On("GenerateAccessToken", mock.AnythingOfType("uuid.UUID")).Return("access_token", nil)
	mockToken.On("GenerateRefreshToken", mock.AnythingOfType("uuid.UUID")).Return("refresh_token", nil)
	mockEmail.On("SendVerificationEmail", "test@example.com", mock.AnythingOfType("string")).Return(nil)

	// Execute
	response, err := service.Register(req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "access_token", response.AccessToken)
	assert.Equal(t, "refresh_token", response.RefreshToken)
	mockRepo.AssertExpectations(t)
	mockToken.AssertExpectations(t)
	mockEmail.AssertExpectations(t)
}

func TestAuthService_Register_UserExists(t *testing.T) {
	mockRepo := new(MockUserRepo)
	mockToken := new(MockTokenSvc)
	mockEmail := new(MockEmailSvc)
	
	cfg := &config.Config{BcryptCost: 4}
	service := &AuthService{
		userRepo:     mockRepo,
		tokenService: mockToken,
		emailService: mockEmail,
		config:       cfg,
	}

	req := &models.CreateUserRequest{
		Email:    "existing@example.com",
		Password: "TestPass123!",
	}

	existingUser := &models.User{
		ID:    uuid.New(),
		Email: "existing@example.com",
	}

	// Mock expectations
	mockRepo.On("GetByEmail", "existing@example.com").Return(existingUser, nil)

	// Execute
	response, err := service.Register(req)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, ErrUserAlreadyExists, err)
	assert.Nil(t, response)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_Success(t *testing.T) {
	mockRepo := new(MockUserRepo)
	mockToken := new(MockTokenSvc)
	mockEmail := new(MockEmailSvc)
	
	cfg := &config.Config{}
	service := &AuthService{
		userRepo:     mockRepo,
		tokenService: mockToken,
		emailService: mockEmail,
		config:       cfg,
	}

	req := &models.LoginRequest{
		Email:    "test@example.com",
		Password: "TestPass123!",
	}

	hashedPassword, _ := utils.HashPassword("TestPass123!", 4)
	user := &models.User{
		ID:            uuid.New(),
		Email:         "test@example.com",
		Password:      hashedPassword,
		EmailVerified: true,
	}

	// Mock expectations
	mockRepo.On("GetByEmail", "test@example.com").Return(user, nil)
	mockRepo.On("ResetFailedLoginAttempts", "test@example.com").Return(nil)
	mockToken.On("GenerateAccessToken", user.ID).Return("access_token", nil)
	mockToken.On("GenerateRefreshToken", user.ID).Return("refresh_token", nil)

	// Execute
	response, err := service.Login(req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "access_token", response.AccessToken)
	mockRepo.AssertExpectations(t)
	mockToken.AssertExpectations(t)
}

func TestAuthService_Login_WrongPassword(t *testing.T) {
	mockRepo := new(MockUserRepo)
	mockToken := new(MockTokenSvc)
	mockEmail := new(MockEmailSvc)
	
	cfg := &config.Config{}
	service := &AuthService{
		userRepo:     mockRepo,
		tokenService: mockToken,
		emailService: mockEmail,
		config:       cfg,
	}

	req := &models.LoginRequest{
		Email:    "test@example.com",
		Password: "WrongPassword",
	}

	hashedPassword, _ := utils.HashPassword("CorrectPassword", 4)
	user := &models.User{
		ID:            uuid.New(),
		Email:         "test@example.com",
		Password:      hashedPassword,
		EmailVerified: true,
	}

	// Mock expectations
	mockRepo.On("GetByEmail", "test@example.com").Return(user, nil)
	mockRepo.On("IncrementFailedLoginAttempts", "test@example.com").Return(nil)

	// Execute
	response, err := service.Login(req)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Nil(t, response)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_AccountLocked(t *testing.T) {
	mockRepo := new(MockUserRepo)
	mockToken := new(MockTokenSvc)
	mockEmail := new(MockEmailSvc)
	
	cfg := &config.Config{}
	service := &AuthService{
		userRepo:     mockRepo,
		tokenService: mockToken,
		emailService: mockEmail,
		config:       cfg,
	}

	req := &models.LoginRequest{
		Email:    "locked@example.com",
		Password: "TestPass123!",
	}

	user := &models.User{
		ID:            uuid.New(),
		Email:         "locked@example.com",
		EmailVerified: true,
	}
	user.LockedUntil.Time = time.Now().Add(10 * time.Minute)
	user.LockedUntil.Valid = true

	// Mock expectations
	mockRepo.On("GetByEmail", "locked@example.com").Return(user, nil)

	// Execute
	response, err := service.Login(req)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, ErrAccountLocked, err)
	assert.Nil(t, response)
	mockRepo.AssertExpectations(t)
}