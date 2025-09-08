package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/Flack74/go-auth-system/internal/config"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type SessionService struct {
	redisClient *redis.Client
	config      *config.Config
}

func NewSessionService(redisClient *redis.Client, config *config.Config) *SessionService {
	return &SessionService{
		redisClient: redisClient,
		config:      config,
	}
}

// GenerateSessionID creates a secure random session ID
func (s *SessionService) GenerateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateSession stores user session in Redis
func (s *SessionService) CreateSession(userID uuid.UUID) (string, error) {
	ctx := context.Background()
	
	sessionID, err := s.GenerateSessionID()
	if err != nil {
		return "", err
	}
	
	key := fmt.Sprintf("session:%s", sessionID)
	err = s.redisClient.Set(ctx, key, userID.String(), s.config.SessionTimeout).Err()
	if err != nil {
		return "", err
	}
	
	return sessionID, nil
}

// ValidateSession checks if session exists and returns user ID
func (s *SessionService) ValidateSession(sessionID string) (uuid.UUID, error) {
	ctx := context.Background()
	
	key := fmt.Sprintf("session:%s", sessionID)
	userIDStr, err := s.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return uuid.Nil, fmt.Errorf("session not found")
		}
		return uuid.Nil, err
	}
	
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, err
	}
	
	// Extend session expiry on access
	s.redisClient.Expire(ctx, key, s.config.SessionTimeout)
	
	return userID, nil
}

// RevokeSession deletes session from Redis
func (s *SessionService) RevokeSession(sessionID string) error {
	ctx := context.Background()
	key := fmt.Sprintf("session:%s", sessionID)
	return s.redisClient.Del(ctx, key).Err()
}

// RevokeAllUserSessions revokes all sessions for a user
func (s *SessionService) RevokeAllUserSessions(userID uuid.UUID) error {
	ctx := context.Background()
	
	pattern := "session:*"
	keys, err := s.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}
	
	for _, key := range keys {
		storedUserID, err := s.redisClient.Get(ctx, key).Result()
		if err != nil {
			continue
		}
		
		if storedUserID == userID.String() {
			s.redisClient.Del(ctx, key)
		}
	}
	
	return nil
}