package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SecurityTestSuite struct {
	suite.Suite
	router *gin.Engine
}

func (suite *SecurityTestSuite) SetupSuite() {
	gin.SetMode(gin.TestMode)
	suite.router = gin.New()
	
	// Add security middleware
	suite.router.Use(suite.mockInputValidation())
	suite.router.POST("/auth/register", suite.mockRegisterHandler)
	suite.router.POST("/auth/login", suite.mockLoginHandler)
}

func (suite *SecurityTestSuite) TestSQLInjectionPrevention() {
	maliciousInputs := []string{
		"'; DROP TABLE users; --",
		"' OR '1'='1",
		"admin'--",
		"' UNION SELECT * FROM users --",
		"'; INSERT INTO users VALUES ('hacker', 'pass'); --",
	}

	for _, maliciousInput := range maliciousInputs {
		reqBody := map[string]string{
			"email":    maliciousInput,
			"password": "password123",
		}
		
		jsonBody, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)
		
		// Should reject malicious SQL injection attempts
		assert.Equal(suite.T(), http.StatusBadRequest, w.Code, 
			"Should reject SQL injection: %s", maliciousInput)
	}
}

func (suite *SecurityTestSuite) TestXSSPrevention() {
	xssPayloads := []string{
		"<script>alert('xss')</script>",
		"javascript:alert('xss')",
		"<img src=x onerror=alert('xss')>",
		"<svg onload=alert('xss')>",
		"<iframe src=javascript:alert('xss')>",
	}

	for _, payload := range xssPayloads {
		reqBody := map[string]string{
			"email":    payload + "@test.com",
			"password": "password123",
		}
		
		jsonBody, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)
		
		// Should reject XSS attempts
		assert.Equal(suite.T(), http.StatusBadRequest, w.Code,
			"Should reject XSS payload: %s", payload)
	}
}

func (suite *SecurityTestSuite) TestPasswordComplexityValidation() {
	weakPasswords := []struct {
		password string
		reason   string
	}{
		{"weak", "too short"},
		{"password", "no uppercase, digits, or special chars"},
		{"PASSWORD123", "no lowercase or special chars"},
		{"Password", "no digits or special chars"},
		{"Password123", "no special chars"},
		{"password!", "no uppercase or digits"},
	}

	for _, test := range weakPasswords {
		reqBody := map[string]string{
			"email":    "test@example.com",
			"password": test.password,
		}
		
		jsonBody, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)
		
		// Should reject weak passwords
		assert.Equal(suite.T(), http.StatusBadRequest, w.Code,
			"Should reject weak password (%s): %s", test.reason, test.password)
	}
}

func (suite *SecurityTestSuite) TestValidPasswordAccepted() {
	strongPasswords := []string{
		"StrongPass123!",
		"MySecure@Pass1",
		"Complex#Password9",
		"Valid$Password2024",
	}

	for _, password := range strongPasswords {
		reqBody := map[string]string{
			"email":    "test@example.com",
			"password": password,
		}
		
		jsonBody, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)
		
		// Should accept strong passwords
		assert.Equal(suite.T(), http.StatusCreated, w.Code,
			"Should accept strong password: %s", password)
	}
}

func (suite *SecurityTestSuite) TestInputLengthLimits() {
	// Test extremely long input
	longString := strings.Repeat("a", 2000)
	
	reqBody := map[string]string{
		"email":    longString + "@test.com",
		"password": "ValidPass123!",
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)
	
	// Should reject overly long input
	assert.Equal(suite.T(), http.StatusBadRequest, w.Code)
}

func (suite *SecurityTestSuite) TestHeaderInjection() {
	maliciousHeaders := map[string]string{
		"X-Forwarded-For": "'; DROP TABLE users; --",
		"User-Agent":      "<script>alert('xss')</script>",
		"Referer":         "javascript:alert('xss')",
	}

	for header, value := range maliciousHeaders {
		req, _ := http.NewRequest("GET", "/auth/login", nil)
		req.Header.Set(header, value)
		
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)
		
		// Should handle malicious headers gracefully
		assert.NotEqual(suite.T(), http.StatusInternalServerError, w.Code,
			"Should handle malicious header: %s", header)
	}
}

// Mock handlers and middleware
func (suite *SecurityTestSuite) mockInputValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Simulate input validation middleware
		if c.Request.Method == "POST" {
			var body map[string]interface{}
			if err := c.ShouldBindJSON(&body); err == nil {
				for key, value := range body {
					if str, ok := value.(string); ok {
						// Check for SQL injection
						if strings.Contains(strings.ToLower(str), "drop table") ||
						   strings.Contains(strings.ToLower(str), "union select") ||
						   strings.Contains(str, "'; ") {
							c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input detected"})
							c.Abort()
							return
						}
						
						// Check for XSS
						if strings.Contains(str, "<script") ||
						   strings.Contains(str, "javascript:") ||
						   strings.Contains(str, "onerror=") {
							c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input detected"})
							c.Abort()
							return
						}
						
						// Check length
						if len(str) > 1000 {
							c.JSON(http.StatusBadRequest, gin.H{"error": "Input too long"})
							c.Abort()
							return
						}
						
						// Password complexity check
						if key == "password" {
							if len(str) < 8 ||
							   !strings.ContainsAny(str, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") ||
							   !strings.ContainsAny(str, "abcdefghijklmnopqrstuvwxyz") ||
							   !strings.ContainsAny(str, "0123456789") ||
							   !strings.ContainsAny(str, "!@#$%^&*()_+-=[]{}|;:,.<>?") {
								c.JSON(http.StatusBadRequest, gin.H{"error": "Password does not meet complexity requirements"})
								c.Abort()
								return
							}
						}
					}
				}
			}
		}
		c.Next()
	}
}

func (suite *SecurityTestSuite) mockRegisterHandler(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func (suite *SecurityTestSuite) mockLoginHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func TestSecurityTestSuite(t *testing.T) {
	suite.Run(t, new(SecurityTestSuite))
}