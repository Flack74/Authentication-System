package services

import "github.com/google/uuid"

type TokenServiceInterface interface {
	GenerateAccessToken(userID uuid.UUID) (string, error)
	GenerateRefreshToken(userID uuid.UUID) (string, error)
	ValidateAccessToken(token string) (uuid.UUID, error)
	ValidateRefreshToken(token string) (uuid.UUID, error)
	RevokeAccessToken(token string) error
	RevokeRefreshToken(token string) error
}

type EmailServiceInterface interface {
	SendVerificationEmail(email, token string) error
	SendPasswordResetEmail(email, token string) error
}