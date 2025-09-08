package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type ErrorResponse struct {
	Error       string `json:"error"`
	Code        string `json:"code,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
	Timestamp   string `json:"timestamp"`
}

func ErrorHandler() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		correlationID, _ := c.Get("correlation_id")
		
		logrus.WithFields(logrus.Fields{
			"correlation_id": correlationID,
			"panic":          recovered,
			"path":           c.Request.URL.Path,
			"method":         c.Request.Method,
		}).Error("Panic recovered")

		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:     "Internal server error",
			Code:      "INTERNAL_ERROR",
			RequestID: correlationID.(string),
			Timestamp: "2024-01-01T00:00:00Z",
		})
	})
}

func ValidationErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Handle validation errors
		if len(c.Errors) > 0 {
			correlationID, _ := c.Get("correlation_id")
			
			logrus.WithFields(logrus.Fields{
				"correlation_id": correlationID,
				"errors":         c.Errors,
				"path":           c.Request.URL.Path,
			}).Warn("Validation errors")

			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error:     c.Errors[0].Error(),
				Code:      "VALIDATION_ERROR",
				RequestID: correlationID.(string),
				Timestamp: "2024-01-01T00:00:00Z",
			})
		}
	}
}