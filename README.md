<div align="center">

# 🔐 Go Authentication System

**A production-ready, enterprise-grade authentication system built with Go**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker)](https://www.docker.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-336791?style=for-the-badge&logo=postgresql)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7+-DC382D?style=for-the-badge&logo=redis)](https://redis.io/)
[![JWT](https://img.shields.io/badge/JWT-Tokens-000000?style=for-the-badge&logo=jsonwebtokens)](https://jwt.io/)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-bcrypt%20%7C%20Rate%20Limiting-green?style=for-the-badge&logo=shield)]()
[![API](https://img.shields.io/badge/API-RESTful-blue?style=for-the-badge&logo=api)]()
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success?style=for-the-badge)]()

*Secure • Scalable • Production-Ready*

[Features](#-features) • [Quick Start](#-quick-start) • [API Documentation](#-api-endpoints) • [Security](#-security-implementation) • [Screenshots](#-screenshots)

</div>

---

## 🌟 **Why Choose This Authentication System?**

✨ **Enterprise-Grade Security** - bcrypt hashing, JWT tokens, rate limiting, account lockout  
🚀 **Production Ready** - Docker containerized, health checks, graceful shutdown  
⚡ **High Performance** - Redis caching, connection pooling, optimized queries  
🛡️ **Security First** - CORS, security headers, input validation, SQL injection protection  
📊 **Monitoring Ready** - Structured logging, health endpoints, metrics collection  
🔧 **Developer Friendly** - Clean architecture, comprehensive documentation, easy setup

## 🏗️ Architecture Overview

This authentication system follows clean architecture principles with clear separation of concerns:

```
go-auth-system/
├── cmd/api/                    # Application entry point
├── internal/                   # Private application code
│   ├── config/                 # Configuration management
│   ├── databases/              # Database connections
│   ├── handlers/               # HTTP request handlers
│   ├── middleware/             # HTTP middleware
│   ├── models/                 # Data models and DTOs
│   ├── repository/             # Data access layer
│   ├── services/               # Business logic layer
│   └── utils/                  # Utility functions
├── migrations/                 # Database migrations
├── docker/                     # Docker configuration
├── docker-compose.yml          # Multi-container setup
└── README.md                   # This file
```

## ✨ Features

### Core Authentication
- **User Registration** with email verification
- **Secure Login** with bcrypt password hashing (cost 12+)
- **JWT Tokens** (short-lived access + long-lived refresh)
- **Token Refresh** with automatic rotation
- **Secure Logout** with token revocation
- **Password Reset** via email with time-limited tokens

### Security Features
- **Rate Limiting** per IP using Redis sliding window
- **Account Lockout** after failed login attempts
- **CORS Protection** with configurable origins
- **Security Headers** (HSTS, CSP, XSS Protection)
- **Input Validation** and sanitization
- **SQL Injection Protection** via prepared statements

### Infrastructure
- **PostgreSQL** for persistent data storage
- **Redis** for session management and caching
- **Docker** containerization with health checks
- **Graceful Shutdown** handling
- **Environment-based Configuration**

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Framework** | Gin | HTTP web framework |
| **Database** | PostgreSQL | Primary data store |
| **Cache** | Redis | Session store & rate limiting |
| **Auth** | JWT | Stateless authentication |
| **Password** | bcrypt | Secure password hashing |
| **Email** | SMTP/Gomail | Email notifications |
| **Containerization** | Docker | Deployment & development |

## 📋 Prerequisites

- Go 1.21+
- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+

## 🚀 Quick Start

### 1. Clone and Setup
```bash
git clone <repository-url>
cd go-auth-system
cp .env.example .env
```

### 2. Configure Environment
Edit `.env` file with your settings:
```env
# Server
PORT=8080
ENV=development

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=authuser
DB_PASSWORD=authpassword
DB_NAME=authdb

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# JWT (Change in production!)
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d

# Email (Configure for production)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
```

### 3. Run with Docker
```bash
# Start all services
docker-compose up -d

# Check logs
docker-compose logs -f app

# Stop services
docker-compose down
```

### 4. Run Locally (Development)
```bash
# Install dependencies
go mod download

# Start PostgreSQL and Redis
docker-compose up -d postgres redis

# Run migrations
migrate -path migrations -database "postgres://authuser:authpassword@localhost:5432/authdb?sslmode=disable" up

# Start the application
go run cmd/api/main.go
```

## 📡 API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/auth/register` | Create new user account | ❌ |
| `POST` | `/auth/login` | Authenticate user | ❌ |
| `POST` | `/auth/refresh` | Refresh access token | ❌ |
| `POST` | `/auth/logout` | Revoke tokens | ✅ |
| `GET` | `/auth/verify?token=` | Verify email address | ❌ |
| `POST` | `/auth/password/forgot` | Request password reset | ❌ |
| `POST` | `/auth/password/reset` | Reset password | ❌ |

### Protected Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/profile` | Get user profile | ✅ |
| `GET` | `/health` | Health check | ❌ |

### Request/Response Examples

#### Register User
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "email_verified": false,
    "created_at": "2024-01-01T00:00:00Z"
  }
}
```

#### Login
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

#### Access Protected Endpoint
```bash
curl -X GET http://localhost:8080/api/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

## 🏗️ Code Architecture Deep Dive

### 1. Configuration Management (`internal/config/`)

The configuration system uses environment variables with sensible defaults:

```go
type Config struct {
    Port string
    Env  string
    
    // Database configuration
    DBHost     string
    DBPort     string
    // ... other fields
    
    // Security settings
    BcryptCost        int
    RateLimitRequests int
    JWTAccessExpiry   time.Duration
}
```

**Key Features:**
- Environment variable parsing with defaults
- Type-safe duration and integer parsing
- Centralized configuration management

### 2. Database Layer (`internal/databases/`)

#### PostgreSQL Connection
```go
func NewPostgresDB(cfg *config.Config) (*sql.DB, error) {
    // Connection string building
    dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
        cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBSSLMode)
    
    // Connection pool configuration
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(5)
    db.SetConnMaxLifetime(5 * time.Minute)
}
```

#### Redis Connection
```go
func NewRedisClient(cfg *config.Config) *redis.Client {
    client := redis.NewClient(&redis.Options{
        Addr:     fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort),
        Password: cfg.RedisPassword,
        DB:       cfg.RedisDB,
    })
}
```

### 3. Data Models (`internal/models/`)

The User model includes all necessary fields for authentication:

```go
type User struct {
    ID                  uuid.UUID      `json:"id"`
    Email               string         `json:"email"`
    Password            string         `json:"-"`           // Hidden from JSON
    EmailVerified       bool           `json:"email_verified"`
    EmailVerifyToken    sql.NullString `json:"-"`
    PasswordResetToken  sql.NullString `json:"-"`
    PasswordResetExpiry sql.NullTime   `json:"-"`
    FailedLoginAttempts int            `json:"-"`
    LockedUntil         sql.NullTime   `json:"-"`
    CreatedAt           time.Time      `json:"created_at"`
    UpdatedAt           time.Time      `json:"updated_at"`
}
```

**Security Considerations:**
- Password field excluded from JSON serialization
- Sensitive tokens hidden from API responses
- UUID primary keys for security
- Nullable fields for optional data

### 4. Repository Pattern (`internal/repository/`)

The repository layer abstracts database operations:

```go
type UserRepository struct {
    db *sql.DB
}

func (r *UserRepository) Create(user *models.User) error {
    query := `INSERT INTO users (id, email, password, email_verify_token, created_at, updated_at)
              VALUES ($1, $2, $3, $4, $5, $6)`
    _, err := r.db.Exec(query, user.ID, user.Email, user.Password, 
                       user.EmailVerifyToken, user.CreatedAt, user.UpdatedAt)
    return err
}
```

**Key Methods:**
- `Create()` - Insert new user
- `GetByEmail()` - Find user by email
- `GetByID()` - Find user by UUID
- `Update()` - Update user data
- `VerifyEmail()` - Mark email as verified
- `IncrementFailedLoginAttempts()` - Security feature
- `GetByPasswordResetToken()` - Password reset flow

### 5. Service Layer (`internal/services/`)

#### Authentication Service
Handles business logic for authentication:

```go
func (s *AuthService) Register(req *models.CreateUserRequest) (*models.AuthResponse, error) {
    // 1. Normalize and validate email
    email := strings.ToLower(strings.TrimSpace(req.Email))
    
    // 2. Check if user exists
    existing, _ := s.userRepo.GetByEmail(email)
    if existing != nil {
        return nil, ErrUserAlreadyExists
    }
    
    // 3. Hash password with bcrypt
    hashedPassword, err := utils.HashPassword(req.Password, s.config.BcryptCost)
    
    // 4. Generate verification token
    verifyToken := uuid.New().String()
    
    // 5. Create user record
    // 6. Send verification email
    // 7. Generate JWT tokens
}
```

#### Token Service
Manages JWT token lifecycle:

```go
type TokenClaims struct {
    UserID uuid.UUID `json:"user_id"`
    Type   string    `json:"type"`        // "access" or "refresh"
    jwt.RegisteredClaims
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
```

**Token Security Features:**
- Separate access and refresh tokens
- Refresh tokens stored in Redis for revocation
- Access tokens blacklisted on logout
- Unique JTI (JWT ID) for each token

#### Email Service
Handles email notifications:

```go
func (s *EmailService) SendVerificationEmail(email, token string) error {
    subject := "Verify Your Email Address"
    verifyURL := fmt.Sprintf("http://localhost:%s/auth/verify?token=%s", s.config.Port, token)
    
    body := fmt.Sprintf(`
        <h2>Email Verification</h2>
        <p>Please click the link below to verify your email address:</p>
        <a href="%s">Verify Email</a>
    `, verifyURL)
    
    return s.sendEmail(email, subject, body)
}
```

### 6. Middleware (`internal/middleware/`)

#### Authentication Middleware
```go
func Auth(tokenService *services.TokenService) gin.HandlerFunc {
    return func(c *gin.Context) {
        // 1. Extract Bearer token from Authorization header
        authHeader := c.GetHeader("Authorization")
        tokenParts := strings.Split(authHeader, " ")
        
        // 2. Validate token format
        if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
            c.Abort()
            return
        }
        
        // 3. Validate JWT token
        userID, err := tokenService.ValidateAccessToken(tokenParts[1])
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
            c.Abort()
            return
        }
        
        // 4. Set user context
        c.Set("userID", userID)
        c.Set("token", tokenParts[1])
        c.Next()
    }
}
```

#### Rate Limiting Middleware
```go
func RateLimit(redisClient *redis.Client, requests int, window time.Duration) gin.HandlerFunc {
    return func(c *gin.Context) {
        clientIP := c.ClientIP()
        key := fmt.Sprintf("rate_limit:%s", clientIP)
        
        // Check current request count
        current, err := redisClient.Get(ctx, key).Int()
        
        if current >= requests {
            c.JSON(http.StatusTooManyRequests, gin.H{
                "error": "Rate limit exceeded",
                "retry_after": window.Seconds(),
            })
            c.Abort()
            return
        }
        
        // Increment counter with expiration
        pipe := redisClient.Pipeline()
        pipe.Incr(ctx, key)
        pipe.Expire(ctx, key, window)
        pipe.Exec(ctx)
        
        c.Next()
    }
}
```

### 7. HTTP Handlers (`internal/handlers/`)

Handlers process HTTP requests and coordinate between services:

```go
func (h *AuthHandler) Login(c *gin.Context) {
    var req models.LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    response, err := h.authService.Login(&req)
    if err != nil {
        switch err {
        case services.ErrInvalidCredentials:
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
        case services.ErrAccountLocked:
            c.JSON(http.StatusLocked, gin.H{"error": "Account locked"})
        case services.ErrEmailNotVerified:
            c.JSON(http.StatusForbidden, gin.H{"error": "Email not verified"})
        default:
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Login failed"})
        }
        return
    }
    
    c.JSON(http.StatusOK, response)
}
```

### 8. Utilities (`internal/utils/`)

#### Password Utilities
```go
func HashPassword(password string, cost int) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
    return string(bytes), err
}

func CheckPassword(password, hash string) error {
    return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
```

#### Validation Utilities
```go
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

func IsValidEmail(email string) bool {
    return emailRegex.MatchString(email)
}

func NormalizeEmail(email string) string {
    return strings.ToLower(strings.TrimSpace(email))
}
```

## 🔒 Security Implementation

### Password Security
- **bcrypt hashing** with cost factor 12+ (configurable)
- **Minimum password length** validation
- **Password reset tokens** with 1-hour expiration

### Token Security
- **Short-lived access tokens** (15 minutes default)
- **Long-lived refresh tokens** (7 days default)
- **Token rotation** on refresh
- **Blacklisting** for immediate revocation
- **Unique JTI** for each token

### Account Protection
- **Failed login tracking** with automatic lockout
- **Account lockout** for 30 minutes after 5 failed attempts
- **Rate limiting** (10 requests per minute per IP)
- **Email verification** required in production

### HTTP Security
- **CORS protection** with configurable origins
- **Security headers** (HSTS, CSP, X-Frame-Options)
- **Input validation** and sanitization
- **SQL injection protection** via prepared statements

## 🐳 Docker Deployment

### Development
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f app

# Execute commands in container
docker-compose exec app sh
```

### Production Considerations
1. **Use secrets management** for sensitive environment variables
2. **Configure TLS termination** at load balancer level
3. **Set up monitoring** and health checks
4. **Use production-grade PostgreSQL** and Redis instances
5. **Implement log aggregation**

## 🧪 Testing

### Manual Testing
```bash
# Health check
curl http://localhost:8080/health

# Register user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

### Load Testing
```bash
# Install hey
go install github.com/rakyll/hey@latest

# Test registration endpoint
hey -n 1000 -c 10 -m POST -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  http://localhost:8080/auth/register
```

## 📊 Monitoring & Observability

### Health Checks
- **Application health**: `/health` endpoint
- **Database connectivity**: PostgreSQL ping
- **Cache connectivity**: Redis ping
- **Docker health checks**: Built into containers

### Logging
- **Structured logging** with request IDs
- **Authentication events** logging
- **Error tracking** and alerting
- **Performance metrics**

## 🚀 Production Deployment

### Environment Setup
1. **Generate strong JWT secret**: `openssl rand -base64 32`
2. **Configure SMTP** for email delivery
3. **Set up SSL/TLS** certificates
4. **Configure reverse proxy** (NGINX/Traefik)
5. **Set up monitoring** (Prometheus/Grafana)

### Security Checklist
- [ ] Change default JWT secret
- [ ] Enable HTTPS/TLS
- [ ] Configure CORS for production domains
- [ ] Set up rate limiting
- [ ] Enable email verification
- [ ] Configure secure headers
- [ ] Set up log monitoring
- [ ] Regular security updates

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-feature`
3. Commit changes: `git commit -am 'Add new feature'`
4. Push to branch: `git push origin feature/new-feature`
5. Submit pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Troubleshooting

### Common Issues

#### Database Connection Failed
```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Check logs
docker-compose logs postgres

# Restart database
docker-compose restart postgres
```

#### Redis Connection Failed
```bash
# Check Redis status
docker-compose ps redis

# Test Redis connection
docker-compose exec redis redis-cli ping
```

#### Email Not Sending
1. Check SMTP configuration in `.env`
2. Verify email credentials
3. Check firewall/network settings
4. Review application logs

#### Token Validation Errors
1. Verify JWT secret configuration
2. Check token expiration settings
3. Ensure Redis is accessible
4. Review token format in requests

### Performance Optimization

#### Database
- Add indexes for frequently queried fields
- Use connection pooling
- Monitor query performance
- Consider read replicas for scaling

#### Redis
- Configure appropriate memory limits
- Use Redis clustering for high availability
- Monitor memory usage
- Set up Redis persistence

#### Application
- Enable Gin release mode in production
- Use HTTP/2 where possible
- Implement response caching
- Monitor memory and CPU usage

---

**Built with ❤️ Flack**