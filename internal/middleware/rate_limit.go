package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func RateLimit(redisClient *redis.Client, requests int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.Background()
		clientIP := c.ClientIP()
		key := fmt.Sprintf("rate_limit:ip:%s", clientIP)

		// Check IP-based rate limit
		if !checkRateLimit(ctx, redisClient, key, requests, window) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded for IP",
				"retry_after": window.Seconds(),
			})
			c.Abort()
			return
		}

		// Check user-based rate limit if authenticated
		if userID, exists := c.Get("userID"); exists {
			userKey := fmt.Sprintf("rate_limit:user:%v", userID)
			if !checkRateLimit(ctx, redisClient, userKey, requests*2, window) {
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error": "Rate limit exceeded for user",
					"retry_after": window.Seconds(),
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

func checkRateLimit(ctx context.Context, redisClient *redis.Client, key string, limit int, window time.Duration) bool {
	current, err := redisClient.Get(ctx, key).Int()
	if err != nil && err != redis.Nil {
		return false
	}

	if current >= limit {
		return false
	}

	// Increment counter with sliding window
	pipe := redisClient.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	_, err = pipe.Exec(ctx)
	return err == nil
}

func RequestSizeLimit(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Request body too large",
				"max_size": maxSize,
			})
			c.Abort()
			return
		}
		c.Next()
	}
}