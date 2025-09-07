package services

import (
    "context"
    "errors"
    "fmt"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"
    "github.com/Flack74/go-auth-system/internal/config"
)

type TokenService struct {
    config      *config.Config
    redisClient *redis.Client
}

type TokenClaims struct {
    UserID uuid.UUID `json:"user_id"`
    Type   string    `json:"type"`
    jwt.RegisteredClaims
}

func NewTokenService(config *config.Config, redisClient *redis.Client) *TokenService {
    return &TokenService{
        config:      config,
        redisClient: redisClient,
    }
}

func (s *TokenService) GenerateAccessToken(userID uuid.UUID) (string, error) {
    claims := TokenClaims{
        UserID: userID,
        Type:   "access",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.JWTAccessExpiry)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            ID:        uuid.New().String(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(s.config.JWTSecret))
}

func (s *TokenService) GenerateRefreshToken(userID uuid.UUID) (string, error) {
    tokenID := uuid.New().String()
    claims := TokenClaims{
        UserID: userID,
        Type:   "refresh",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.JWTRefreshExpiry)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            ID:        tokenID,
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString([]byte(s.config.JWTSecret))
    if err != nil {
        return "", err
    }

    // Store in Redis for revocation checking
    ctx := context.Background()
    key := fmt.Sprintf("refresh_token:%s", tokenID)
    err = s.redisClient.Set(ctx, key, userID.String(), s.config.JWTRefreshExpiry).Err()
    if err != nil {
        return "", err
    }

    return tokenString, nil
}

func (s *TokenService) ValidateAccessToken(tokenString string) (uuid.UUID, error) {
    token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
        return []byte(s.config.JWTSecret), nil
    })

    if err != nil {
        return uuid.Nil, err
    }

    claims, ok := token.Claims.(*TokenClaims)
    if !ok || !token.Valid || claims.Type != "access" {
        return uuid.Nil, errors.New("invalid token")
    }

    // Check if token is blacklisted
    ctx := context.Background()
    key := fmt.Sprintf("blacklist:access:%s", claims.ID)
    exists, err := s.redisClient.Exists(ctx, key).Result()
    if err != nil {
        return uuid.Nil, err
    }
    if exists > 0 {
        return uuid.Nil, errors.New("token revoked")
    }

    return claims.UserID, nil
}

func (s *TokenService) ValidateRefreshToken(tokenString string) (uuid.UUID, error) {
    token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
        return []byte(s.config.JWTSecret), nil
    })

    if err != nil {
        return uuid.Nil, err
    }

    claims, ok := token.Claims.(*TokenClaims)
    if !ok || !token.Valid || claims.Type != "refresh" {
        return uuid.Nil, errors.New("invalid refresh token")
    }

    // Check if token exists in Redis
    ctx := context.Background()
    key := fmt.Sprintf("refresh_token:%s", claims.ID)
    exists, err := s.redisClient.Exists(ctx, key).Result()
    if err != nil {
        return uuid.Nil, err
    }
    if exists == 0 {
        return uuid.Nil, errors.New("refresh token not found or expired")
    }

    return claims.UserID, nil
}

func (s *TokenService) RevokeAccessToken(tokenString string) error {
    token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
        return []byte(s.config.JWTSecret), nil
    })

    if err != nil {
        return err
    }

    claims, ok := token.Claims.(*TokenClaims)
    if !ok {
        return errors.New("invalid token")
    }

    // Add to blacklist
    ctx := context.Background()
    key := fmt.Sprintf("blacklist:access:%s", claims.ID)
    ttl := time.Until(claims.ExpiresAt.Time)
    if ttl > 0 {
        return s.redisClient.Set(ctx, key, "revoked", ttl).Err()
    }
    return nil
}

func (s *TokenService) RevokeRefreshToken(tokenString string) error {
    token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
        return []byte(s.config.JWTSecret), nil
    })

    if err != nil {
        return err
    }

    claims, ok := token.Claims.(*TokenClaims)
    if !ok {
        return errors.New("invalid token")
    }

    // Remove from Redis
    ctx := context.Background()
    key := fmt.Sprintf("refresh_token:%s", claims.ID)
    return s.redisClient.Del(ctx, key).Err()
}
