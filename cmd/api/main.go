package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Flack74/go-auth-system/internal/config"
	"github.com/Flack74/go-auth-system/internal/databases"
	"github.com/Flack74/go-auth-system/internal/handlers"
	"github.com/Flack74/go-auth-system/internal/middleware"
	"github.com/Flack74/go-auth-system/internal/repository"
	"github.com/Flack74/go-auth-system/internal/services"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found")
	}

	// Load configuration
	cfg := config.Load()

	// Initialize database
	db, err := databases.NewPostgresDB(cfg)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Initialize Redis
	redisClient := databases.NewRedisClient(cfg)
	defer redisClient.Close()

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)

	// Initialize services
	tokenService := services.NewTokenService(cfg, redisClient)
	emailService := services.NewEmailService(cfg)
	authService := services.NewAuthService(userRepo, tokenService, emailService, cfg)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService)

	// Setup routes
	router := setupRouter(cfg, authHandler, tokenService, redisClient)

	// Start server
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	log.Printf("Server started on port %s", cfg.Port)

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited")
}

func setupRouter(cfg *config.Config, authHandler *handlers.AuthHandler, tokenService *services.TokenService, redisClient *redis.Client) *gin.Engine {
	router := gin.Default()

	// Global middleware
	router.Use(middleware.CORS())
	router.Use(middleware.SecureHeaders())
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// Auth routes
	auth := router.Group("/auth")
	{
		// Apply rate limiting to auth endpoints
		auth.Use(middleware.RateLimit(redisClient, cfg.RateLimitRequests, cfg.RateLimitWindow))

		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/refresh", authHandler.Refresh)
		auth.POST("/logout", middleware.Auth(tokenService), authHandler.Logout)
		auth.GET("/verify", authHandler.VerifyEmail)
		auth.POST("/password/forgot", authHandler.ForgotPassword)
		auth.POST("/password/reset", authHandler.ResetPassword)
	}

	// Protected routes example
	protected := router.Group("/api")
	protected.Use(middleware.Auth(tokenService))
	{
		protected.GET("/profile", authHandler.GetProfile)
	}

	return router
}
