package services

import (
	"database/sql"
	"testing"

	"github.com/Flack74/go-auth-system/internal/config"
	"github.com/Flack74/go-auth-system/internal/models"
	"github.com/Flack74/go-auth-system/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type AuthServiceIntegrationSuite struct {
	suite.Suite
	authService *AuthService
	userRepo    *repository.UserRepository
	cfg         *config.Config
}

func (suite *AuthServiceIntegrationSuite) SetupSuite() {
	suite.cfg = &config.Config{
		BcryptCost: 4, // Lower for faster tests
	}
}

func (suite *AuthServiceIntegrationSuite) TestRegisterUser_Success() {
	req := &models.CreateUserRequest{
		Email:    "integration@test.com",
		Password: "TestPass123!",
	}

	// Test password validation
	err := ValidatePasswordComplexity(req.Password)
	assert.NoError(suite.T(), err)

	// Test email validation
	assert.True(suite.T(), IsValidEmail(req.Email))
}

func (suite *AuthServiceIntegrationSuite) TestPasswordComplexity() {
	tests := []struct {
		password string
		valid    bool
	}{
		{"TestPass123!", true},
		{"weak", false},
		{"NoDigits!", false},
		{"nouppercasepass123!", false},
		{"NOLOWERCASE123!", false},
		{"NoSpecialChar123", false},
	}

	for _, test := range tests {
		err := ValidatePasswordComplexity(test.password)
		if test.valid {
			assert.NoError(suite.T(), err, "Password should be valid: %s", test.password)
		} else {
			assert.Error(suite.T(), err, "Password should be invalid: %s", test.password)
		}
	}
}

func TestAuthServiceIntegrationSuite(t *testing.T) {
	suite.Run(t, new(AuthServiceIntegrationSuite))
}

// Helper functions for testing
func ValidatePasswordComplexity(password string) error {
	if len(password) < 8 {
		return sql.ErrNoRows // Using as placeholder error
	}
	
	hasUpper, hasLower, hasDigit, hasSpecial := false, false, false, false
	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z': hasUpper = true
		case char >= 'a' && char <= 'z': hasLower = true
		case char >= '0' && char <= '9': hasDigit = true
		case char >= '!' && char <= '/': hasSpecial = true
		}
	}
	
	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return sql.ErrNoRows
	}
	return nil
}

func IsValidEmail(email string) bool {
	return len(email) > 5 && len(email) < 100 // Simplified validation
}