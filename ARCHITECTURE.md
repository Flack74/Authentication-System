# 🏗️ Authentication System Architecture Documentation

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture Philosophy](#architecture-philosophy)
3. [Layer-by-Layer Breakdown](#layer-by-layer-breakdown)
4. [Security Design Decisions](#security-design-decisions)
5. [Data Flow & Request Lifecycle](#data-flow--request-lifecycle)
6. [Technology Choices & Rationale](#technology-choices--rationale)
7. [Scalability Considerations](#scalability-considerations)
8. [Code Organization Principles](#code-organization-principles)

---

## System Overview

This authentication system follows **Clean Architecture** principles with clear separation of concerns, making it maintainable, testable, and scalable. The system is designed as a **stateless microservice** that can handle enterprise-level authentication requirements.

### Core Principles
- **Security First**: Every design decision prioritizes security
- **Separation of Concerns**: Each layer has a single responsibility
- **Dependency Inversion**: High-level modules don't depend on low-level modules
- **Testability**: Each component can be tested in isolation
- **Scalability**: Designed to handle high concurrent loads

---

## Architecture Philosophy

### Why Clean Architecture?

```
┌─────────────────────────────────────────────────────────────┐
│                    External Interfaces                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   HTTP API  │  │   Database  │  │   External Services │ │
│  │  (Gin/REST) │  │ (PostgreSQL)│  │    (SMTP/Redis)     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
           │                │                    │
           ▼                ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                     Interface Layer                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Handlers   │  │ Repository  │  │     Services        │ │
│  │ (HTTP Logic)│  │ (Data Access│  │  (Email, Cache)     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
           │                │                    │
           ▼                ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                    Business Logic Layer                     │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Authentication Service                     │ │
│  │  • User Registration    • Login/Logout                 │ │
│  │  • Token Management     • Password Reset               │ │
│  │  • Email Verification   • Account Security             │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────┐
│                      Domain Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Models    │  │   Entities  │  │   Business Rules    │ │
│  │ (User, JWT) │  │ (Pure Data) │  │  (Validation, etc)  │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Key Benefits:**
- **Independence**: Business logic doesn't depend on frameworks
- **Testability**: Core logic can be tested without external dependencies
- **Flexibility**: Easy to swap databases, frameworks, or external services
- **Maintainability**: Changes in one layer don't affect others

---

## Layer-by-Layer Breakdown

### 1. **Entry Point Layer** (`cmd/api/`)

```go
// main.go - Application bootstrap
func main() {
    // 1. Load configuration
    cfg := config.Load()
    
    // 2. Initialize dependencies
    db := databases.NewPostgresDB(cfg)
    redis := databases.NewRedisClient(cfg)
    
    // 3. Wire up services (Dependency Injection)
    userRepo := repository.NewUserRepository(db)
    authService := services.NewAuthService(userRepo, cfg)
    
    // 4. Setup HTTP server
    router := setupRouter(authService, redis, cfg)
    server := &http.Server{Addr: ":" + cfg.Port, Handler: router}
    
    // 5. Graceful shutdown
    gracefulShutdown(server, db, redis)
}
```

**Intuition**: This is the **composition root** where all dependencies are wired together. It's the only place that knows about concrete implementations.

### 2. **Configuration Layer** (`internal/config/`)

```go
type Config struct {
    // Server settings
    Port string
    Env  string
    
    // Database configuration
    DBHost     string
    DBPort     string
    DBUser     string
    DBPassword string
    DBName     string
    
    // Security settings
    JWTSecret         string
    JWTAccessExpiry   time.Duration
    JWTRefreshExpiry  time.Duration
    BcryptCost        int
    
    // Rate limiting
    RateLimitRequests int
    RateLimitWindow   time.Duration
}
```

**Design Decision**: Centralized configuration with environment variable parsing ensures:
- **12-Factor App Compliance**: Configuration through environment
- **Type Safety**: Parsed once at startup with validation
- **Default Values**: Sensible defaults for development

### 3. **HTTP Handler Layer** (`internal/handlers/`)

```go
type AuthHandler struct {
    authService services.AuthServiceInterface
    logger      *slog.Logger
}

func (h *AuthHandler) Register(c *gin.Context) {
    // 1. Parse and validate input
    var req models.CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    // 2. Delegate to business logic
    response, err := h.authService.Register(&req)
    
    // 3. Handle errors and return response
    if err != nil {
        handleAuthError(c, err)
        return
    }
    
    c.JSON(http.StatusCreated, response)
}
```

**Intuition**: Handlers are **thin adapters** that:
- Convert HTTP requests to domain objects
- Delegate business logic to services
- Convert domain responses back to HTTP
- Handle HTTP-specific concerns (status codes, headers)

### 4. **Middleware Layer** (`internal/middleware/`)

```go
// Middleware stack applied in specific order
func SetupMiddleware(router *gin.Engine, redis *redis.Client, cfg *config.Config) {
    // 1. Request tracing
    router.Use(CorrelationID())
    
    // 2. Logging and monitoring
    router.Use(StructuredLogging())
    
    // 3. Security middleware
    router.Use(CORS(cfg))
    router.Use(SecureHeaders())
    router.Use(RateLimit(redis, cfg.RateLimitRequests, cfg.RateLimitWindow))
    
    // 4. Request processing
    router.Use(RequestTimeout(cfg.RequestTimeout))
    router.Use(InputValidation())
    
    // 5. Error handling
    router.Use(ErrorHandler())
}
```

**Design Philosophy**: Middleware follows the **Chain of Responsibility** pattern:
- Each middleware has a single responsibility
- Order matters (security before business logic)
- Cross-cutting concerns are handled uniformly

### 5. **Service Layer** (`internal/services/`)

```go
type AuthService struct {
    userRepo     repository.UserRepositoryInterface
    tokenService TokenServiceInterface
    emailService EmailServiceInterface
    config       *config.Config
    logger       *slog.Logger
}

func (s *AuthService) Register(req *models.CreateUserRequest) (*models.AuthResponse, error) {
    // 1. Business rule validation
    if err := s.validateRegistrationRequest(req); err != nil {
        return nil, err
    }
    
    // 2. Check business constraints
    existingUser, _ := s.userRepo.GetByEmail(req.Email)
    if existingUser != nil {
        return nil, ErrUserAlreadyExists
    }
    
    // 3. Apply business logic
    hashedPassword, err := utils.HashPassword(req.Password, s.config.BcryptCost)
    if err != nil {
        return nil, err
    }
    
    // 4. Create domain entity
    user := &models.User{
        ID:               uuid.New(),
        Email:            strings.ToLower(req.Email),
        Password:         hashedPassword,
        EmailVerifyToken: sql.NullString{String: uuid.New().String(), Valid: true},
        CreatedAt:        time.Now(),
        UpdatedAt:        time.Now(),
    }
    
    // 5. Persist changes
    if err := s.userRepo.Create(user); err != nil {
        return nil, err
    }
    
    // 6. Handle side effects
    go s.emailService.SendVerificationEmail(user.Email, user.EmailVerifyToken.String)
    
    // 7. Generate response
    tokens, err := s.tokenService.GenerateTokenPair(user.ID)
    if err != nil {
        return nil, err
    }
    
    return &models.AuthResponse{
        AccessToken:  tokens.AccessToken,
        RefreshToken: tokens.RefreshToken,
        User:         user.ToPublic(),
    }, nil
}
```

**Key Insights**:
- **Business Logic Orchestration**: Services coordinate between repositories and external services
- **Transaction Boundaries**: Services define what constitutes a business transaction
- **Error Handling**: Business errors are distinct from technical errors
- **Side Effects**: Async operations (like emails) don't block the main flow

### 6. **Repository Layer** (`internal/repository/`)

```go
type UserRepository struct {
    db *sql.DB
}

func (r *UserRepository) Create(user *models.User) error {
    query := `
        INSERT INTO users (id, email, password, email_verify_token, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)`
    
    _, err := r.db.Exec(query, 
        user.ID, user.Email, user.Password, 
        user.EmailVerifyToken, user.CreatedAt, user.UpdatedAt)
    
    return err
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
        return nil, nil
    }
    
    return user, err
}
```

**Design Principles**:
- **Data Access Abstraction**: Hides database implementation details
- **SQL Injection Prevention**: Uses parameterized queries
- **Error Handling**: Distinguishes between "not found" and actual errors
- **Interface Segregation**: Each repository focuses on one aggregate root

### 7. **Model Layer** (`internal/models/`)

```go
type User struct {
    ID                  uuid.UUID      `json:"id"`
    Email               string         `json:"email"`
    Password            string         `json:"-"`                    // Hidden from JSON
    EmailVerified       bool           `json:"email_verified"`
    EmailVerifyToken    sql.NullString `json:"-"`                    // Hidden from JSON
    PasswordResetToken  sql.NullString `json:"-"`                    // Hidden from JSON
    PasswordResetExpiry sql.NullTime   `json:"-"`                    // Hidden from JSON
    FailedLoginAttempts int            `json:"-"`                    // Hidden from JSON
    LockedUntil         sql.NullTime   `json:"-"`                    // Hidden from JSON
    CreatedAt           time.Time      `json:"created_at"`
    UpdatedAt           time.Time      `json:"updated_at"`
}

// ToPublic returns user data safe for API responses
func (u *User) ToPublic() *PublicUser {
    return &PublicUser{
        ID:            u.ID,
        Email:         u.Email,
        EmailVerified: u.EmailVerified,
        CreatedAt:     u.CreatedAt,
    }
}

// IsAccountLocked checks if account is currently locked
func (u *User) IsAccountLocked() bool {
    return u.LockedUntil.Valid && u.LockedUntil.Time.After(time.Now())
}
```

**Security Considerations**:
- **Data Hiding**: Sensitive fields excluded from JSON serialization
- **Immutability**: Models represent state, not behavior
- **Validation**: Input validation happens at the boundary
- **Type Safety**: Strong typing prevents common errors

---

## Security Design Decisions

### 1. **Password Security**

```go
// Why bcrypt with cost 12+?
func HashPassword(password string, cost int) (string, error) {
    // bcrypt is designed to be slow (adaptive hashing)
    // Cost 12 = ~250ms on modern hardware
    // Protects against rainbow table and brute force attacks
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
    return string(bytes), err
}
```

**Rationale**: 
- **Adaptive Hashing**: Cost can be increased as hardware improves
- **Salt Included**: Each hash has a unique salt
- **Time-Tested**: Industry standard for password hashing

### 2. **JWT Token Strategy**

```go
type TokenClaims struct {
    UserID uuid.UUID `json:"user_id"`
    Type   string    `json:"type"`        // "access" or "refresh"
    jwt.RegisteredClaims
}

// Why dual-token approach?
func (s *TokenService) GenerateTokenPair(userID uuid.UUID) (*TokenPair, error) {
    // Short-lived access token (15 minutes)
    accessToken, err := s.GenerateAccessToken(userID)
    
    // Long-lived refresh token (7 days)
    refreshToken, err := s.GenerateRefreshToken(userID)
    
    // Store refresh token in Redis for revocation
    s.storeRefreshToken(refreshToken, userID)
    
    return &TokenPair{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
    }, nil
}
```

**Security Benefits**:
- **Limited Exposure**: Access tokens expire quickly
- **Revocation**: Refresh tokens can be blacklisted
- **Rotation**: New tokens issued on refresh
- **Stateless**: Access tokens don't require database lookup

### 3. **Rate Limiting Strategy**

```go
func RateLimit(redis *redis.Client, requests int, window time.Duration) gin.HandlerFunc {
    return func(c *gin.Context) {
        clientIP := c.ClientIP()
        
        // IP-based limiting (prevents basic DoS)
        ipKey := fmt.Sprintf("rate_limit:ip:%s", clientIP)
        if !checkRateLimit(ctx, redis, ipKey, requests, window) {
            c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
            c.Abort()
            return
        }
        
        // User-based limiting (prevents account enumeration)
        if userID, exists := c.Get("userID"); exists {
            userKey := fmt.Sprintf("rate_limit:user:%v", userID)
            if !checkRateLimit(ctx, redis, userKey, requests*2, window) {
                c.JSON(http.StatusTooManyRequests, gin.H{"error": "User rate limit exceeded"})
                c.Abort()
                return
            }
        }
        
        c.Next()
    }
}
```

**Multi-Layer Protection**:
- **IP-Level**: Prevents basic DoS attacks
- **User-Level**: Prevents account enumeration
- **Sliding Window**: More accurate than fixed windows
- **Redis-Based**: Distributed rate limiting

### 4. **Account Lockout Mechanism**

```go
func (s *AuthService) handleFailedLogin(user *models.User) error {
    user.FailedLoginAttempts++
    
    // Lock account after 5 failed attempts
    if user.FailedLoginAttempts >= s.config.MaxFailedAttempts {
        lockDuration := s.config.AccountLockoutDuration
        user.LockedUntil = sql.NullTime{
            Time:  time.Now().Add(lockDuration),
            Valid: true,
        }
        
        // Log security event
        s.logger.Warn("Account locked due to failed login attempts",
            "user_id", user.ID,
            "attempts", user.FailedLoginAttempts,
            "locked_until", user.LockedUntil.Time)
    }
    
    return s.userRepo.UpdateFailedLoginAttempts(user)
}
```

**Brute Force Protection**:
- **Progressive Delays**: Could be enhanced with exponential backoff
- **Temporary Lockout**: Balances security with usability
- **Audit Logging**: Security events are logged for monitoring

---

## Data Flow & Request Lifecycle

### Registration Flow

```
1. HTTP Request
   POST /auth/register
   {"email": "user@example.com", "password": "SecurePass123!"}
   
2. Middleware Chain
   CorrelationID() → Logging() → CORS() → RateLimit() → Validation()
   
3. Handler Layer
   AuthHandler.Register()
   ├── Parse JSON request
   ├── Validate input format
   └── Call AuthService.Register()
   
4. Service Layer
   AuthService.Register()
   ├── Validate business rules (email format, password strength)
   ├── Check if user already exists (UserRepository.GetByEmail)
   ├── Hash password with bcrypt
   ├── Create User entity with verification token
   ├── Save to database (UserRepository.Create)
   ├── Send verification email (async)
   ├── Generate JWT token pair
   └── Return AuthResponse
   
5. Response
   HTTP 201 Created
   {
     "access_token": "eyJ...",
     "refresh_token": "eyJ...",
     "user": {
       "id": "uuid",
       "email": "user@example.com",
       "email_verified": false,
       "created_at": "2024-01-01T00:00:00Z"
     }
   }
```

### Login Flow with Security Checks

```
1. HTTP Request
   POST /auth/login
   {"email": "user@example.com", "password": "SecurePass123!"}
   
2. Service Layer Security Checks
   AuthService.Login()
   ├── Get user by email
   ├── Check if account exists
   ├── Check if account is locked (IsAccountLocked())
   ├── Verify password with bcrypt
   ├── Handle failed login (increment counter, potentially lock account)
   ├── Reset failed login attempts on success
   ├── Generate new JWT token pair
   └── Return AuthResponse
   
3. Security Events Logged
   ├── Login attempt (success/failure)
   ├── Account lockout (if applicable)
   ├── Rate limit violations
   └── Correlation ID for tracing
```

---

## Technology Choices & Rationale

### 1. **Go Language**
- **Performance**: Compiled language with excellent concurrency
- **Simplicity**: Easy to read and maintain
- **Standard Library**: Excellent HTTP and crypto support
- **Deployment**: Single binary deployment

### 2. **Gin Framework**
- **Performance**: Fast HTTP router
- **Middleware Support**: Excellent middleware ecosystem
- **JSON Handling**: Built-in JSON binding and validation
- **Community**: Large, active community

### 3. **PostgreSQL**
- **ACID Compliance**: Strong consistency guarantees
- **JSON Support**: Flexible schema when needed
- **Performance**: Excellent query optimization
- **Security**: Row-level security, encryption at rest

### 4. **Redis**
- **Performance**: In-memory operations for caching
- **Data Structures**: Rich data types for rate limiting
- **Persistence**: Optional durability for session data
- **Clustering**: Horizontal scaling capabilities

### 5. **JWT Tokens**
- **Stateless**: No server-side session storage required
- **Scalable**: Works across multiple server instances
- **Standard**: Industry-standard token format
- **Flexible**: Can carry custom claims

### 6. **Docker Containerization**
- **Consistency**: Same environment across dev/staging/prod
- **Isolation**: Process and dependency isolation
- **Scalability**: Easy horizontal scaling
- **Deployment**: Simplified deployment process

---

## Scalability Considerations

### 1. **Horizontal Scaling**

```go
// Stateless design enables horizontal scaling
type AuthService struct {
    // No instance state - all state in database/cache
    userRepo     repository.UserRepositoryInterface
    tokenService TokenServiceInterface
    config       *config.Config
}
```

**Benefits**:
- **Load Balancing**: Multiple instances can handle requests
- **No Session Affinity**: Requests can go to any instance
- **Database Scaling**: Read replicas for query scaling

### 2. **Caching Strategy**

```go
// Redis caching for frequently accessed data
func (r *UserRepository) GetByEmailCached(email string) (*models.User, error) {
    // 1. Check cache first
    cached, err := r.cache.Get(ctx, "user:email:"+email).Result()
    if err == nil {
        var user models.User
        json.Unmarshal([]byte(cached), &user)
        return &user, nil
    }
    
    // 2. Fallback to database
    user, err := r.GetByEmail(email)
    if err != nil {
        return nil, err
    }
    
    // 3. Cache the result
    userJSON, _ := json.Marshal(user)
    r.cache.Set(ctx, "user:email:"+email, userJSON, time.Hour)
    
    return user, nil
}
```

### 3. **Database Optimization**

```sql
-- Strategic indexes for performance
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_users_email_verify_token ON users(email_verify_token);
CREATE INDEX CONCURRENTLY idx_users_password_reset_token ON users(password_reset_token);
CREATE INDEX CONCURRENTLY idx_users_created_at ON users(created_at);
```

### 4. **Monitoring & Observability**

```go
// Structured logging for monitoring
func (h *AuthHandler) Register(c *gin.Context) {
    correlationID := c.GetString("correlation_id")
    
    h.logger.Info("Registration attempt",
        "correlation_id", correlationID,
        "ip", c.ClientIP(),
        "user_agent", c.GetHeader("User-Agent"))
    
    // ... business logic ...
    
    h.logger.Info("Registration successful",
        "correlation_id", correlationID,
        "user_id", response.User.ID,
        "duration", time.Since(start))
}
```

---

## Code Organization Principles

### 1. **Dependency Direction**

```
┌─────────────────┐    ┌─────────────────┐
│    Handlers     │───▶│    Services     │
│  (HTTP Logic)   │    │ (Business Logic)│
└─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   Repository    │
                       │  (Data Access)  │
                       └─────────────────┘
```

**Rule**: Dependencies point inward toward business logic

### 2. **Interface Segregation**

```go
// Small, focused interfaces
type UserRepositoryInterface interface {
    Create(user *models.User) error
    GetByID(id uuid.UUID) (*models.User, error)
    GetByEmail(email string) (*models.User, error)
    Update(user *models.User) error
}

type EmailServiceInterface interface {
    SendVerificationEmail(email, token string) error
    SendPasswordResetEmail(email, token string) error
}
```

### 3. **Error Handling Strategy**

```go
// Domain-specific errors
var (
    ErrUserNotFound      = errors.New("user not found")
    ErrInvalidCredentials = errors.New("invalid credentials")
    ErrAccountLocked     = errors.New("account locked")
    ErrEmailNotVerified  = errors.New("email not verified")
)

// Error handling in handlers
func handleAuthError(c *gin.Context, err error) {
    switch err {
    case services.ErrInvalidCredentials:
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
    case services.ErrAccountLocked:
        c.JSON(http.StatusLocked, gin.H{"error": "Account locked"})
    case services.ErrEmailNotVerified:
        c.JSON(http.StatusForbidden, gin.H{"error": "Email not verified"})
    default:
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
    }
}
```

### 4. **Configuration Management**

```go
// Environment-based configuration
func Load() *Config {
    cfg := &Config{
        Port: getEnv("PORT", "8080"),
        Env:  getEnv("ENV", "development"),
        
        // Database
        DBHost: getEnv("DB_HOST", "localhost"),
        DBPort: getEnv("DB_PORT", "5432"),
        
        // Security
        JWTSecret:        getEnv("JWT_SECRET", "dev-secret-change-in-production"),
        JWTAccessExpiry:  parseDuration("JWT_ACCESS_EXPIRY", "15m"),
        JWTRefreshExpiry: parseDuration("JWT_REFRESH_EXPIRY", "7d"),
        BcryptCost:       parseInt("BCRYPT_COST", 12),
    }
    
    // Validate critical settings
    if cfg.Env == "production" && cfg.JWTSecret == "dev-secret-change-in-production" {
        log.Fatal("JWT_SECRET must be set in production")
    }
    
    return cfg
}
```

---

## Summary

This authentication system demonstrates enterprise-grade software architecture with:

1. **Clean Architecture**: Clear separation of concerns and dependency inversion
2. **Security First**: Multiple layers of security controls
3. **Scalability**: Stateless design enabling horizontal scaling  
4. **Maintainability**: Well-organized code with clear interfaces
5. **Observability**: Comprehensive logging and monitoring
6. **Production Ready**: Docker containerization and deployment automation

The codebase serves as a template for building secure, scalable microservices in Go, with patterns and practices that can be applied to other domains beyond authentication.