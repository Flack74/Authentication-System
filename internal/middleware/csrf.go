package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func CSRF(redisClient *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		token := c.GetHeader("X-CSRF-Token")
		if token == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token required"})
			c.Abort()
			return
		}

		// Validate CSRF token in Redis
		ctx := c.Request.Context()
		key := "csrf:" + token
		exists, err := redisClient.Exists(ctx, key).Result()
		if err != nil || exists == 0 {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid CSRF token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func GenerateCSRFToken(redisClient *redis.Client) (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	
	token := hex.EncodeToString(bytes)
	ctx := context.Background()
	key := "csrf:" + token
	
	// Store token for 1 hour
	err := redisClient.Set(ctx, key, "valid", time.Hour).Err()
	return token, err
}