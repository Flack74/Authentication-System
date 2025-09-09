# 🚀 Development Guide & Code Walkthrough

## Table of Contents
1. [Getting Started](#getting-started)
2. [Code Structure Deep Dive](#code-structure-deep-dive)
3. [Key Implementation Patterns](#key-implementation-patterns)
4. [Security Implementation Details](#security-implementation-details)
5. [Testing Strategy](#testing-strategy)
6. [Common Development Tasks](#common-development-tasks)
7. [Debugging & Troubleshooting](#debugging--troubleshooting)

---

## Getting Started

### Prerequisites Understanding
```bash
# Why these specific versions?
Go 1.21+     # Generics support, improved performance
PostgreSQL 15+ # JSON improvements, performance enhancements  
Redis 7+     # ACL improvements, better memory efficiency
Docker       # Consistent development environment
```

### Development Environment Setup
```bash
# 1. Clone and setup
git clone <repository-url>
cd Authentication_System

# 2. Environment configuration
cp .env.example .env
# Edit .env with your local settings

# 3. Start dependencies
docker-compose up -d postgres redis

# 4. Run migrations
migrate -path migrations -database "postgres://authuser:authpassword@localhost:5432/authdb?sslmode=disable" up

# 5. Start development server
go run cmd/api/main.go
```

---

## Code Structure Deep Dive

### Entry Point Analysis (`cmd/api/main.go`)

```go
func main() {
    // 1. Configuration Loading
    cfg := config.Load()
    
    // 2. Database Connections
    db, err := databases.NewPostgresDB(cfg)
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    defer db.Close()
    
    redisClient := databases.NewRedisClient(cfg)
    defer redisClient.Close()
    
    // 3. Repository Layer Initialization
    userRepo := repository.NewUserRepository(db)
    
    // 4. Service Layer Initialization  
    tokenService := services.NewTokenService(cfg, redisClient)
    emailService := services.NewEmailService(cfg)
    authService := services.NewAuthService(userRepo, tokenService, emailService, cfg)
    
    // 5. Handler Layer Initialization
    authHandler := handlers.NewAuthHandler(authService)
    healthHandler := handlers.NewHealthHandler(db, redisClient)
    
    // 6. Router Setup with Middleware
    router := setupRouter(authHandler, healthHandler, redisClient, cfg)
    
    // 7. Server Configuration
    server := &http.Server{
        Addr:         ":" + cfg.Port,
        Handler:      router,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }
    
    // 8. Graceful Shutdown
    gracefulShutdown(server, db, redisClient)
}
```

**Key Insights:**
- **Dependency Injection**: All dependencies are explicitly wired
- **Error Handling**: Fatal errors stop application startup
- **Resource Management**: Proper cleanup with defer statements
- **Server Configuration**: Production-ready timeouts

### Configuration Deep Dive (`internal/config/config.go`)

```go
type Config struct {
    // Server Configuration
    Port string `env:"PORT" envDefault:"8080"`
    Env  string `env:"ENV" envDefault:"development"`
    
    // Database Configuration
    DBHost     string `env:"DB_HOST" envDefault:"localhost"`
    DBPort     string `env:"DB_PORT" envDefault:"5432"`
    DBUser     string `env:"DB_USER" envDefault:"authuser"`
    DBPassword string `env:"DB_PASSWORD" envDefault:"authpassword"`
    DBName     string `env:"DB_NAME" envDefault:"authdb"`
    DBSSLMode  string `env:"DB_SSLMODE" envDefault:"disable"`
    
    // Redis Configuration
    RedisHost     string `env:"REDIS_HOST" envDefault:"localhost"`
    RedisPort     string `env:"REDIS_PORT" envDefault:"6379"`
    RedisPassword string `env:"REDIS_PASSWORD" envDefault:""`
    RedisDB       int    `env:"REDIS_DB" envDefault:"0"`
    
    // JWT Configuration
    JWTSecret        string        `env:"JWT_SECRET" envDefault:"dev-secret-change-in-production"`
    JWTAccessExpiry  time.Duration `env:"JWT_ACCESS_EXPIRY" envDefault:"15m"`
    JWTRefreshExpiry time.Duration `env:"JWT_REFRESH_EXPIRY" envDefault:"7d"`
    
    // Security Configuration
    BcryptCost              int           `env:"BCRYPT_COST" envDefault:"12"`
    RateLimitRequests       int           `env:"RATE_LIMIT_REQUESTS" envDefault:"10"`
    RateLimitWindow         time.Duration `env:"RATE_LIMIT_WINDOW" envDefault:"1m"`
    AccountLockoutDuration  time.Duration `env:"ACCOUNT_LOCKOUT_DURATION" envDefault:"30m"`
    MaxFailedAttempts       int           `env:"MAX_FAILED_ATTEMPTS" envDefault:"5"`
    PasswordComplexity      bool          `env:"PASSWORD_COMPLEXITY" envDefault:"true"`
    CSRFProtection          bool          `env:"CSRF_PROTECTION" envDefault:"false"`
    RequestTimeout          time.Duration `env:"REQUEST_TIMEOUT" envDefault:"30s"`
}

func Load() *Config {
    cfg := &Config{}
    
    // Parse environment variables with defaults
    if err := env.Parse(cfg); err != nil {
        log.Fatal("Failed to parse configuration:", err)
    }
    
    // Validate critical production settings
    if cfg.Env == "production" {
        validateProductionConfig(cfg)
    }
    
    return cfg
}

func validateProductionConfig(cfg *Config) {
    if cfg.JWTSecret == "dev-secret-change-in-production" {
        log.Fatal("JWT_SECRET must be changed in production")
    }
    
    if cfg.BcryptCost < 12 {
        log.Fatal("BCRYPT_COST must be at least 12 in production")
    }
    
    if !cfg.PasswordComplexity {
        log.Warn("Password complexity is disabled in production")
    }
}
```

**Design Decisions:**
- **Environment Variables**: 12-factor app compliance
- **Sensible Defaults**: Development-friendly defaults
- **Type Safety**: Duration and integer parsing with validation
- **Production Validation**: Prevents common security misconfigurations

### Database Layer Implementation (`internal/databases/`)

#### PostgreSQL Connection with Optimization

```go
func NewPostgresDB(cfg *config.Config) (*sql.DB, error) {
    // Build connection string
    dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
        cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBSSLMode)
    
    // Open connection
    db, err := sql.Open("postgres", dsn)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }
    
    // Connection pool configuration for production
    db.SetMaxOpenConns(25)                 // Maximum connections
    db.SetMaxIdleConns(5)                  // Idle connections to keep
    db.SetConnMaxLifetime(5 * time.Minute) // Connection lifetime
    db.SetConnMaxIdleTime(1 * time.Minute) // Idle connection timeout
    
    // Test connection
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    if err := db.PingContext(ctx); err != nil {
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }
    
    return db, nil
}
```

#### Redis Connection with Configuration

```go
func NewRedisClient(cfg *config.Config) *redis.Client {
    client := redis.NewClient(&redis.Options{
        Addr:         fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort),
        Password:     cfg.RedisPassword,
        DB:           cfg.RedisDB,
        PoolSize:     10,                    // Connection pool size
        MinIdleConns: 2,                     // Minimum idle connections
        MaxRetries:   3,                     // Retry failed commands
        DialTimeout:  5 * time.Second,       // Connection timeout
        ReadTimeout:  3 * time.Second,       // Read timeout
        WriteTimeout: 3 * time.Second,       // Write timeout
    })
    
    // Test connection
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    if err := client.Ping(ctx).Err(); err != nil {
        log.Fatal("Failed to connect to Redis:", err)
    }
    
    return client
}
```

**Performance Optimizations:**
- **Connection Pooling**: Reuse database connections
- **Timeouts**: Prevent hanging connections
- **Health Checks**: Verify connectivity at startup

---

## Key Implementation Patterns

### 1. Repository Pattern Implementation

```go
// Interface definition (in services package)
type UserRepositoryInterface interface {
    Create(user *models.User) error
    GetByID(id uuid.UUID) (*models.User, error)
    GetByEmail(email string) (*models.User, error)
    Update(user *models.User) error
    UpdateFailedLoginAttempts(user *models.User) error
    VerifyEmail(token string) error
    GetByPasswordResetToken(token string) (*models.User, error)
}

// Concrete implementation
type UserRepository struct {
    db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepositoryInterface {
    return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *models.User) error {
    query := `
        INSERT INTO users (id, email, password, email_verify_token, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)`
    
    _, err := r.db.Exec(query, 
        user.ID, user.Email, user.Password, 
        user.EmailVerifyToken, user.CreatedAt, user.UpdatedAt)
    
    if err != nil {
        // Handle specific database errors
        if strings.Contains(err.Error(), "duplicate key") {
            return ErrUserAlreadyExists
        }
        return fmt.Errorf("failed to create user: %w", err)
    }
    
    return nil
}

func (r *UserRepository) GetByEmail(email string) (*models.User, error) {
    query := `
        SELECT id, email, password, email_verified, email_verify_token,
               password_reset_token, password_reset_expiry, failed_login_attempts,
               locked_until, created_at, updated_at
        FROM users WHERE email = $1`
    
    user := &models.User{}
    err := r.db.QueryRow(query, email).Scan(
        &user.ID, &user.Email, &user.Password, &user.EmailVerified,
        &user.EmailVerifyToken, &user.PasswordResetToken, &user.PasswordResetExpiry,
        &user.FailedLoginAttempts, &user.LockedUntil, &user.CreatedAt, &user.UpdatedAt)
    
    if err == sql.ErrNoRows {
        return nil, nil // Not found, not an error
    }
    
    if err != nil {
        return nil, fmt.Errorf("failed to get user by email: %w", err)
    }
    
    return user, nil
}
```

**Pattern Benefits:**
- **Testability**: Easy to mock for unit tests
- **Abstraction**: Business logic doesn't know about SQL
- **Error Handling**: Database errors are translated to domain errors

### 2. Service Layer Pattern

```go
type AuthService struct {
    userRepo     UserRepositoryInterface
    tokenService TokenServiceInterface
    emailService EmailServiceInterface
    config       *config.Config
    logger       *slog.Logger
}

func NewAuthService(
    userRepo UserRepositoryInterface,
    tokenService TokenServiceInterface,
    emailService EmailServiceInterface,
    config *config.Config,
) AuthServiceInterface {
    return &AuthService{
        userRepo:     userRepo,
        tokenService: tokenService,
        emailService: emailService,
        config:       config,
        logger:       slog.Default(),
    }
}

func (s *AuthService) Register(req *models.CreateUserRequest) (*models.AuthResponse, error) {
    // 1. Input validation and normalization
    email := strings.ToLower(strings.TrimSpace(req.Email))
    if !utils.IsValidEmail(email) {
        return nil, ErrInvalidEmail
    }
    
    if s.config.PasswordComplexity {
        if err := utils.ValidatePassword(req.Password); err != nil {
            return nil, err
        }
    }
    
    // 2. Business rule validation
    existingUser, err := s.userRepo.GetByEmail(email)
    if err != nil {
        return nil, fmt.Errorf("failed to check existing user: %w", err)
    }
    if existingUser != nil {
        return nil, ErrUserAlreadyExists
    }
    
    // 3. Password hashing
    hashedPassword, err := utils.HashPassword(req.Password, s.config.BcryptCost)
    if err != nil {
        return nil, fmt.Errorf("failed to hash password: %w", err)
    }
    
    // 4. Create user entity
    user := &models.User{
        ID:               uuid.New(),
        Email:            email,
        Password:         hashedPassword,
        EmailVerified:    false,
        EmailVerifyToken: sql.NullString{String: uuid.New().String(), Valid: true},
        CreatedAt:        time.Now(),
        UpdatedAt:        time.Now(),
    }
    
    // 5. Persist user
    if err := s.userRepo.Create(user); err != nil {
        return nil, err
    }
    
    // 6. Send verification email (async to not block response)
    go func() {
        if err := s.emailService.SendVerificationEmail(user.Email, user.EmailVerifyToken.String); err != nil {
            s.logger.Error("Failed to send verification email",
                "user_id", user.ID,
                "email", user.Email,
                "error", err)
        }
    }()
    
    // 7. Generate tokens
    tokens, err := s.tokenService.GenerateTokenPair(user.ID)
    if err != nil {
        return nil, fmt.Errorf("failed to generate tokens: %w", err)
    }
    
    // 8. Log successful registration
    s.logger.Info("User registered successfully",
        "user_id", user.ID,
        "email", user.Email)
    
    return &models.AuthResponse{
        AccessToken:  tokens.AccessToken,
        RefreshToken: tokens.RefreshToken,
        User:         user.ToPublic(),
    }, nil
}
```

**Service Layer Responsibilities:**
- **Business Logic Orchestration**: Coordinates between repositories
- **Transaction Boundaries**: Defines what constitutes a business operation
- **Error Handling**: Translates technical errors to business errors
- **Logging**: Records business events for monitoring

### 3. Middleware Pattern Implementation

```go
// Correlation ID middleware for request tracing
func CorrelationID() gin.HandlerFunc {
    return func(c *gin.Context) {
        correlationID := c.GetHeader("X-Correlation-ID")
        if correlationID == "" {
            correlationID = uuid.New().String()
        }
        
        c.Set("correlation_id", correlationID)
        c.Header("X-Correlation-ID", correlationID)
        c.Next()
    }
}

// Structured logging middleware
func StructuredLogging() gin.HandlerFunc {
    return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
        logEntry := map[string]interface{}{
            "timestamp":      param.TimeStamp.Format(time.RFC3339),
            "status":         param.StatusCode,
            "latency":        param.Latency.String(),
            "client_ip":      param.ClientIP,
            "method":         param.Method,
            "path":           param.Path,
            "user_agent":     param.Request.UserAgent(),
            "correlation_id": param.Keys["correlation_id"],
        }
        
        if param.ErrorMessage != "" {
            logEntry["error"] = param.ErrorMessage
        }
        
        logJSON, _ := json.Marshal(logEntry)
        return string(logJSON) + "\n"
    })
}

// Rate limiting with Redis
func RateLimit(redisClient *redis.Client, requests int, window time.Duration) gin.HandlerFunc {
    return func(c *gin.Context) {
        ctx := context.Background()
        clientIP := c.ClientIP()
        
        // Sliding window rate limiting
        key := fmt.Sprintf("rate_limit:ip:%s", clientIP)
        
        // Use Redis sorted sets for sliding window
        now := time.Now().Unix()
        windowStart := now - int64(window.Seconds())
        
        pipe := redisClient.Pipeline()
        
        // Remove old entries
        pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart))
        
        // Count current requests
        pipe.ZCard(ctx, key)
        
        // Add current request
        pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: now})
        
        // Set expiration
        pipe.Expire(ctx, key, window)
        
        results, err := pipe.Exec(ctx)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Rate limiting error"})
            c.Abort()
            return
        }
        
        // Check if rate limit exceeded
        currentRequests := results[1].(*redis.IntCmd).Val()
        if currentRequests >= int64(requests) {
            c.JSON(http.StatusTooManyRequests, gin.H{
                "error":       "Rate limit exceeded",
                "retry_after": int(window.Seconds()),
            })
            c.Abort()
            return
        }
        
        c.Next()
    }
}
```

**Middleware Design Principles:**
- **Single Responsibility**: Each middleware has one job
- **Order Matters**: Security middleware runs before business logic
- **Context Passing**: Information flows through gin.Context
- **Error Handling**: Middleware can abort request processing

---

## Security Implementation Details

### 1. Password Security Deep Dive

```go
// Password hashing with bcrypt
func HashPassword(password string, cost int) (string, error) {
    // bcrypt automatically handles salt generation
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
    return string(bytes), err
}

func CheckPassword(password, hash string) error {
    return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// Password complexity validation
func ValidatePassword(password string) error {
    if len(password) < 8 {
        return ErrPasswordTooShort
    }
    
    var hasUpper, hasLower, hasDigit, hasSpecial bool
    
    for _, char := range password {
        switch {
        case unicode.IsUpper(char):
            hasUpper = true
        case unicode.IsLower(char):
            hasLower = true
        case unicode.IsDigit(char):
            hasDigit = true
        case unicode.IsPunct(char) || unicode.IsSymbol(char):
            hasSpecial = true
        }
    }
    
    if !hasUpper {
        return ErrPasswordNoUpper
    }
    if !hasLower {
        return ErrPasswordNoLower
    }
    if !hasDigit {
        return ErrPasswordNoDigit
    }
    if !hasSpecial {
        return ErrPasswordNoSpecial
    }
    
    return nil
}
```

**Security Considerations:**
- **bcrypt Cost**: Adjustable work factor (12+ for production)
- **Salt Handling**: bcrypt includes salt in the hash
- **Complexity Rules**: Enforced at application level
- **Timing Attacks**: bcrypt has constant-time comparison

### 2. JWT Token Implementation

```go
type TokenClaims struct {
    UserID uuid.UUID `json:"user_id"`
    Type   string    `json:"type"` // "access" or "refresh"
    jwt.RegisteredClaims
}

type TokenService struct {
    config      *config.Config
    redisClient *redis.Client
}

func (s *TokenService) GenerateAccessToken(userID uuid.UUID) (string, error) {
    claims := TokenClaims{
        UserID: userID,
        Type:   "access",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.JWTAccessExpiry)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            NotBefore: jwt.NewNumericDate(time.Now()),
            ID:        uuid.New().String(), // Unique token ID for revocation
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(s.config.JWTSecret))
}

func (s *TokenService) GenerateRefreshToken(userID uuid.UUID) (string, error) {
    claims := TokenClaims{
        UserID: userID,
        Type:   "refresh",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.JWTRefreshExpiry)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            NotBefore: jwt.NewNumericDate(time.Now()),
            ID:        uuid.New().String(),
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString([]byte(s.config.JWTSecret))
    if err != nil {
        return "", err
    }
    
    // Store refresh token in Redis for revocation capability
    ctx := context.Background()
    key := fmt.Sprintf("refresh_token:%s", claims.ID)
    err = s.redisClient.Set(ctx, key, userID.String(), s.config.JWTRefreshExpiry).Err()
    if err != nil {
        return "", fmt.Errorf("failed to store refresh token: %w", err)
    }
    
    return tokenString, nil
}

func (s *TokenService) ValidateToken(tokenString string) (*TokenClaims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
        // Validate signing method
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(s.config.JWTSecret), nil
    })
    
    if err != nil {
        return nil, err
    }
    
    claims, ok := token.Claims.(*TokenClaims)
    if !ok || !token.Valid {
        return nil, ErrInvalidToken
    }
    
    // Check if token is blacklisted (for logout)
    ctx := context.Background()
    blacklistKey := fmt.Sprintf("blacklist:%s", claims.ID)
    exists, err := s.redisClient.Exists(ctx, blacklistKey).Result()
    if err != nil {
        return nil, fmt.Errorf("failed to check token blacklist: %w", err)
    }
    if exists > 0 {
        return nil, ErrTokenBlacklisted
    }
    
    return claims, nil
}

func (s *TokenService) RevokeToken(tokenID string, expiry time.Duration) error {
    ctx := context.Background()
    blacklistKey := fmt.Sprintf("blacklist:%s", tokenID)
    
    // Add to blacklist with expiration matching token expiry
    return s.redisClient.Set(ctx, blacklistKey, "revoked", expiry).Err()
}
```

**Token Security Features:**
- **Short-lived Access Tokens**: Minimize exposure window
- **Refresh Token Rotation**: New tokens on each refresh
- **Token Revocation**: Blacklist capability via Redis
- **Unique Token IDs**: Enable individual token revocation

### 3. Account Lockout Implementation

```go
func (s *AuthService) Login(req *models.LoginRequest) (*models.AuthResponse, error) {
    // Get user by email
    user, err := s.userRepo.GetByEmail(req.Email)
    if err != nil {
        return nil, err
    }
    if user == nil {
        return nil, ErrInvalidCredentials
    }
    
    // Check if account is locked
    if user.IsAccountLocked() {
        s.logger.Warn("Login attempt on locked account",
            "user_id", user.ID,
            "email", user.Email,
            "locked_until", user.LockedUntil.Time)
        return nil, ErrAccountLocked
    }
    
    // Verify password
    if err := utils.CheckPassword(req.Password, user.Password); err != nil {
        // Handle failed login
        if err := s.handleFailedLogin(user); err != nil {
            s.logger.Error("Failed to update failed login attempts", "error", err)
        }
        return nil, ErrInvalidCredentials
    }
    
    // Reset failed login attempts on successful login
    if user.FailedLoginAttempts > 0 {
        user.FailedLoginAttempts = 0
        user.LockedUntil = sql.NullTime{Valid: false}
        if err := s.userRepo.UpdateFailedLoginAttempts(user); err != nil {
            s.logger.Error("Failed to reset failed login attempts", "error", err)
        }
    }
    
    // Generate tokens and return response
    // ... token generation logic
}

func (s *AuthService) handleFailedLogin(user *models.User) error {
    user.FailedLoginAttempts++
    
    // Lock account after max failed attempts
    if user.FailedLoginAttempts >= s.config.MaxFailedAttempts {
        lockDuration := s.config.AccountLockoutDuration
        user.LockedUntil = sql.NullTime{
            Time:  time.Now().Add(lockDuration),
            Valid: true,
        }
        
        s.logger.Warn("Account locked due to failed login attempts",
            "user_id", user.ID,
            "email", user.Email,
            "attempts", user.FailedLoginAttempts,
            "locked_until", user.LockedUntil.Time)
    }
    
    return s.userRepo.UpdateFailedLoginAttempts(user)
}
```

**Brute Force Protection:**
- **Progressive Lockout**: Account locked after 5 failed attempts
- **Time-based Unlock**: Automatic unlock after 30 minutes
- **Audit Logging**: All security events are logged
- **Reset on Success**: Counter reset on successful login

---

## Testing Strategy

### 1. Unit Testing Example

```go
// services/auth_service_test.go
func TestAuthService_Register(t *testing.T) {
    // Setup
    mockUserRepo := &mocks.MockUserRepository{}
    mockTokenService := &mocks.MockTokenService{}
    mockEmailService := &mocks.MockEmailService{}
    
    cfg := &config.Config{
        BcryptCost:         4, // Lower cost for faster tests
        PasswordComplexity: true,
    }
    
    authService := services.NewAuthService(
        mockUserRepo, mockTokenService, mockEmailService, cfg)
    
    t.Run("successful registration", func(t *testing.T) {
        // Arrange
        req := &models.CreateUserRequest{
            Email:    "test@example.com",
            Password: "SecurePass123!",
        }
        
        mockUserRepo.On("GetByEmail", "test@example.com").Return(nil, nil)
        mockUserRepo.On("Create", mock.AnythingOfType("*models.User")).Return(nil)
        mockTokenService.On("GenerateTokenPair", mock.AnythingOfType("uuid.UUID")).
            Return(&models.TokenPair{
                AccessToken:  "access_token",
                RefreshToken: "refresh_token",
            }, nil)
        mockEmailService.On("SendVerificationEmail", "test@example.com", mock.AnythingOfType("string")).
            Return(nil)
        
        // Act
        response, err := authService.Register(req)
        
        // Assert
        assert.NoError(t, err)
        assert.NotNil(t, response)
        assert.Equal(t, "access_token", response.AccessToken)
        assert.Equal(t, "test@example.com", response.User.Email)
        assert.False(t, response.User.EmailVerified)
        
        mockUserRepo.AssertExpectations(t)
        mockTokenService.AssertExpectations(t)
        mockEmailService.AssertExpectations(t)
    })
    
    t.Run("user already exists", func(t *testing.T) {
        // Arrange
        req := &models.CreateUserRequest{
            Email:    "existing@example.com",
            Password: "SecurePass123!",
        }
        
        existingUser := &models.User{
            ID:    uuid.New(),
            Email: "existing@example.com",
        }
        
        mockUserRepo.On("GetByEmail", "existing@example.com").Return(existingUser, nil)
        
        // Act
        response, err := authService.Register(req)
        
        // Assert
        assert.Error(t, err)
        assert.Nil(t, response)
        assert.Equal(t, services.ErrUserAlreadyExists, err)
        
        mockUserRepo.AssertExpectations(t)
    })
}
```

### 2. Integration Testing Example

```go
// tests/integration/auth_test.go
func TestAuthIntegration(t *testing.T) {
    // Setup test database
    testDB := setupTestDB(t)
    defer testDB.Close()
    
    // Setup test Redis
    testRedis := setupTestRedis(t)
    defer testRedis.Close()
    
    // Setup test server
    server := setupTestServer(testDB, testRedis)
    defer server.Close()
    
    t.Run("complete registration flow", func(t *testing.T) {
        // Register user
        registerReq := map[string]string{
            "email":    "integration@example.com",
            "password": "SecurePass123!",
        }
        
        resp := makeRequest(t, server, "POST", "/auth/register", registerReq)
        assert.Equal(t, http.StatusCreated, resp.StatusCode)
        
        var registerResp models.AuthResponse
        json.NewDecoder(resp.Body).Decode(&registerResp)
        
        assert.NotEmpty(t, registerResp.AccessToken)
        assert.NotEmpty(t, registerResp.RefreshToken)
        assert.Equal(t, "integration@example.com", registerResp.User.Email)
        assert.False(t, registerResp.User.EmailVerified)
        
        // Test login with same credentials
        loginReq := map[string]string{
            "email":    "integration@example.com",
            "password": "SecurePass123!",
        }
        
        loginResp := makeRequest(t, server, "POST", "/auth/login", loginReq)
        assert.Equal(t, http.StatusOK, loginResp.StatusCode)
        
        // Test protected endpoint
        protectedResp := makeAuthenticatedRequest(t, server, "GET", "/api/profile", 
            registerResp.AccessToken, nil)
        assert.Equal(t, http.StatusOK, protectedResp.StatusCode)
    })
}
```

### 3. Load Testing Example

```go
// tests/load/auth_load_test.go
func TestAuthLoad(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping load test in short mode")
    }
    
    server := setupTestServer(setupTestDB(t), setupTestRedis(t))
    defer server.Close()
    
    // Test concurrent registrations
    t.Run("concurrent registrations", func(t *testing.T) {
        concurrency := 100
        requests := 1000
        
        var wg sync.WaitGroup
        errors := make(chan error, requests)
        
        for i := 0; i < concurrency; i++ {
            wg.Add(1)
            go func(workerID int) {
                defer wg.Done()
                
                for j := 0; j < requests/concurrency; j++ {
                    email := fmt.Sprintf("load-test-%d-%d@example.com", workerID, j)
                    req := map[string]string{
                        "email":    email,
                        "password": "SecurePass123!",
                    }
                    
                    resp := makeRequest(t, server, "POST", "/auth/register", req)
                    if resp.StatusCode != http.StatusCreated {
                        errors <- fmt.Errorf("registration failed for %s: %d", email, resp.StatusCode)
                    }
                }
            }(i)
        }
        
        wg.Wait()
        close(errors)
        
        errorCount := 0
        for err := range errors {
            t.Logf("Error: %v", err)
            errorCount++
        }
        
        // Allow for some errors due to rate limiting
        assert.Less(t, errorCount, requests/10, "Too many errors during load test")
    })
}
```

---

## Common Development Tasks

### 1. Adding a New Endpoint

```go
// 1. Add to models (if needed)
type ChangePasswordRequest struct {
    CurrentPassword string `json:"current_password" binding:"required"`
    NewPassword     string `json:"new_password" binding:"required"`
}

// 2. Add to service interface
type AuthServiceInterface interface {
    // ... existing methods
    ChangePassword(userID uuid.UUID, req *ChangePasswordRequest) error
}

// 3. Implement in service
func (s *AuthService) ChangePassword(userID uuid.UUID, req *ChangePasswordRequest) error {
    user, err := s.userRepo.GetByID(userID)
    if err != nil {
        return err
    }
    if user == nil {
        return ErrUserNotFound
    }
    
    // Verify current password
    if err := utils.CheckPassword(req.CurrentPassword, user.Password); err != nil {
        return ErrInvalidCredentials
    }
    
    // Validate new password
    if s.config.PasswordComplexity {
        if err := utils.ValidatePassword(req.NewPassword); err != nil {
            return err
        }
    }
    
    // Hash new password
    hashedPassword, err := utils.HashPassword(req.NewPassword, s.config.BcryptCost)
    if err != nil {
        return err
    }
    
    // Update user
    user.Password = hashedPassword
    user.UpdatedAt = time.Now()
    
    return s.userRepo.Update(user)
}

// 4. Add handler method
func (h *AuthHandler) ChangePassword(c *gin.Context) {
    userID, exists := c.Get("userID")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
        return
    }
    
    var req models.ChangePasswordRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    if err := h.authService.ChangePassword(userID.(uuid.UUID), &req); err != nil {
        handleAuthError(c, err)
        return
    }
    
    c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// 5. Add route
func setupAuthRoutes(router *gin.RouterGroup, authHandler *handlers.AuthHandler, authMiddleware gin.HandlerFunc) {
    auth := router.Group("/auth")
    {
        // ... existing routes
        auth.PUT("/password", authMiddleware, authHandler.ChangePassword)
    }
}
```

### 2. Adding Database Migration

```sql
-- migrations/000003_add_user_preferences.up.sql
CREATE TABLE user_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    theme VARCHAR(20) DEFAULT 'light',
    language VARCHAR(10) DEFAULT 'en',
    notifications_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(user_id)
);

CREATE INDEX idx_user_preferences_user_id ON user_preferences(user_id);
```

```sql
-- migrations/000003_add_user_preferences.down.sql
DROP TABLE IF EXISTS user_preferences;
```

### 3. Adding New Configuration

```go
// 1. Add to Config struct
type Config struct {
    // ... existing fields
    
    // New feature configuration
    EnableTwoFactor     bool          `env:"ENABLE_TWO_FACTOR" envDefault:"false"`
    TwoFactorIssuer     string        `env:"TWO_FACTOR_ISSUER" envDefault:"AuthSystem"`
    SessionTimeout      time.Duration `env:"SESSION_TIMEOUT" envDefault:"24h"`
}

// 2. Add validation if needed
func validateProductionConfig(cfg *Config) {
    // ... existing validations
    
    if cfg.EnableTwoFactor && cfg.TwoFactorIssuer == "" {
        log.Fatal("TWO_FACTOR_ISSUER must be set when two-factor is enabled")
    }
}

// 3. Use in services
func NewAuthService(/* ... */, config *config.Config) AuthServiceInterface {
    service := &AuthService{
        // ... existing fields
        twoFactorEnabled: config.EnableTwoFactor,
    }
    
    return service
}
```

---

## Debugging & Troubleshooting

### 1. Common Issues and Solutions

#### Database Connection Issues
```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Check PostgreSQL logs
docker-compose logs postgres

# Test connection manually
docker-compose exec postgres psql -U authuser -d authdb -c "SELECT 1;"

# Check connection pool stats
# Add to your health check endpoint
func (h *HealthHandler) DatabaseStats() gin.HandlerFunc {
    return func(c *gin.Context) {
        stats := h.db.Stats()
        c.JSON(http.StatusOK, gin.H{
            "max_open_connections": stats.MaxOpenConnections,
            "open_connections":     stats.OpenConnections,
            "in_use":              stats.InUse,
            "idle":                stats.Idle,
        })
    }
}
```

#### Redis Connection Issues
```bash
# Check Redis status
docker-compose ps redis

# Test Redis connection
docker-compose exec redis redis-cli ping

# Check Redis memory usage
docker-compose exec redis redis-cli info memory

# Monitor Redis commands
docker-compose exec redis redis-cli monitor
```

#### JWT Token Issues
```go
// Add token debugging
func (s *TokenService) DebugToken(tokenString string) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return []byte(s.config.JWTSecret), nil
    })
    
    if err != nil {
        log.Printf("Token parse error: %v", err)
        return
    }
    
    if claims, ok := token.Claims.(jwt.MapClaims); ok {
        log.Printf("Token claims: %+v", claims)
        log.Printf("Token valid: %v", token.Valid)
        
        if exp, ok := claims["exp"].(float64); ok {
            expTime := time.Unix(int64(exp), 0)
            log.Printf("Token expires at: %v", expTime)
            log.Printf("Token expired: %v", time.Now().After(expTime))
        }
    }
}
```

### 2. Logging and Monitoring

```go
// Enhanced logging with context
func (s *AuthService) Login(req *models.LoginRequest) (*models.AuthResponse, error) {
    logger := s.logger.With(
        "operation", "login",
        "email", req.Email,
        "ip", req.IPAddress, // Add IP to request model
    )
    
    logger.Info("Login attempt started")
    
    user, err := s.userRepo.GetByEmail(req.Email)
    if err != nil {
        logger.Error("Failed to get user", "error", err)
        return nil, err
    }
    
    if user == nil {
        logger.Warn("Login attempt with non-existent email")
        return nil, ErrInvalidCredentials
    }
    
    if user.IsAccountLocked() {
        logger.Warn("Login attempt on locked account",
            "user_id", user.ID,
            "locked_until", user.LockedUntil.Time)
        return nil, ErrAccountLocked
    }
    
    // ... rest of login logic
    
    logger.Info("Login successful", "user_id", user.ID)
    return response, nil
}
```

### 3. Performance Monitoring

```go
// Add performance metrics
func (s *AuthService) Register(req *models.CreateUserRequest) (*models.AuthResponse, error) {
    start := time.Now()
    defer func() {
        duration := time.Since(start)
        s.logger.Info("Registration completed",
            "duration", duration,
            "email", req.Email)
        
        // Could integrate with metrics system like Prometheus
        // metrics.RecordDuration("auth.register", duration)
    }()
    
    // ... registration logic
}

// Database query performance monitoring
func (r *UserRepository) GetByEmail(email string) (*models.User, error) {
    start := time.Now()
    defer func() {
        duration := time.Since(start)
        if duration > 100*time.Millisecond {
            log.Printf("Slow query detected: GetByEmail took %v", duration)
        }
    }()
    
    // ... query logic
}
```

This development guide provides a comprehensive understanding of the codebase structure, implementation patterns, and development practices. Use it as a reference when working with the authentication system or when building similar systems.