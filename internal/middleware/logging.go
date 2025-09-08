package middleware

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func StructuredLogging() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		correlationID := param.Keys["correlation_id"]
		if correlationID == nil {
			correlationID = "unknown"
		}

		logrus.WithFields(logrus.Fields{
			"correlation_id": correlationID,
			"timestamp":      param.TimeStamp.Format(time.RFC3339),
			"status":         param.StatusCode,
			"latency":        param.Latency,
			"client_ip":      param.ClientIP,
			"method":         param.Method,
			"path":           param.Path,
			"user_agent":     param.Request.UserAgent(),
		}).Info("HTTP Request")

		return ""
	})
}

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

func RequestTimeout() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}