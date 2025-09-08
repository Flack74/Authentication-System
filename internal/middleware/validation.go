package middleware

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/Flack74/go-auth-system/internal/utils"
	"github.com/gin-gonic/gin"
)

var (
	sqlInjectionPattern = regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|create|alter|exec|script)`)
	xssPattern         = regexp.MustCompile(`(?i)(<script|javascript:|on\w+\s*=)`)
)

func InputValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Validate query parameters
		for key, values := range c.Request.URL.Query() {
			for _, value := range values {
				if err := validateInput(key, value); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "Invalid input detected",
						"field": key,
					})
					c.Abort()
					return
				}
			}
		}

		// Validate headers for potential attacks
		userAgent := c.GetHeader("User-Agent")
		if userAgent != "" && (sqlInjectionPattern.MatchString(userAgent) || xssPattern.MatchString(userAgent)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user agent"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func validateInput(field, value string) error {
	// Sanitize input
	sanitized := utils.SanitizeInput(value)
	
	// Check for SQL injection patterns
	if sqlInjectionPattern.MatchString(strings.ToLower(sanitized)) {
		return gin.Error{Err: fmt.Errorf("potential SQL injection in field %s", field)}
	}
	
	// Check for XSS patterns
	if xssPattern.MatchString(strings.ToLower(sanitized)) {
		return gin.Error{Err: fmt.Errorf("potential XSS in field %s", field)}
	}
	
	return nil
}

func EmailValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "POST" {
			var body map[string]interface{}
			if err := c.ShouldBindJSON(&body); err == nil {
				if email, exists := body["email"]; exists {
					if emailStr, ok := email.(string); ok {
						if !utils.IsValidEmail(emailStr) {
							c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
							c.Abort()
							return
						}
					}
				}
			}
		}
		c.Next()
	}
}