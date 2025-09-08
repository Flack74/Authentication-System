package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type CacheService struct {
	redisClient *redis.Client
}

func NewCacheService(redisClient *redis.Client) *CacheService {
	return &CacheService{
		redisClient: redisClient,
	}
}

// Set stores data in cache with TTL
func (c *CacheService) Set(key string, value interface{}, ttl time.Duration) error {
	ctx := context.Background()
	
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	
	return c.redisClient.Set(ctx, fmt.Sprintf("cache:%s", key), data, ttl).Err()
}

// Get retrieves data from cache
func (c *CacheService) Get(key string, dest interface{}) error {
	ctx := context.Background()
	
	data, err := c.redisClient.Get(ctx, fmt.Sprintf("cache:%s", key)).Result()
	if err != nil {
		return err
	}
	
	return json.Unmarshal([]byte(data), dest)
}

// Delete removes data from cache
func (c *CacheService) Delete(key string) error {
	ctx := context.Background()
	return c.redisClient.Del(ctx, fmt.Sprintf("cache:%s", key)).Err()
}

// CacheUserProfile caches expensive user profile lookup
func (c *CacheService) CacheUserProfile(userID string, profile interface{}) error {
	return c.Set(fmt.Sprintf("user_profile:%s", userID), profile, 5*time.Minute)
}

// GetCachedUserProfile retrieves cached user profile
func (c *CacheService) GetCachedUserProfile(userID string, dest interface{}) error {
	return c.Get(fmt.Sprintf("user_profile:%s", userID), dest)
}