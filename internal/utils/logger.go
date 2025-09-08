package utils

import (
	"context"

	"github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Logger
}

func NewLogger() *Logger {
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.000Z",
	})
	return &Logger{log}
}

func (l *Logger) WithCorrelationID(ctx context.Context) *logrus.Entry {
	correlationID := ctx.Value("correlation_id")
	if correlationID == nil {
		correlationID = "unknown"
	}
	return l.WithField("correlation_id", correlationID)
}

func (l *Logger) LogAuthEvent(ctx context.Context, event string, email string, success bool) {
	entry := l.WithCorrelationID(ctx).WithFields(logrus.Fields{
		"event":   event,
		"email":   email,
		"success": success,
		"type":    "auth_event",
	})
	
	if success {
		entry.Info("Authentication event")
	} else {
		entry.Warn("Authentication failed")
	}
}

func (l *Logger) LogSecurityEvent(ctx context.Context, event string, details map[string]interface{}) {
	entry := l.WithCorrelationID(ctx).WithFields(logrus.Fields{
		"event": event,
		"type":  "security_event",
	})
	
	for key, value := range details {
		entry = entry.WithField(key, value)
	}
	
	entry.Warn("Security event detected")
}

func (l *Logger) LogBusinessEvent(ctx context.Context, event string, details map[string]interface{}) {
	entry := l.WithCorrelationID(ctx).WithFields(logrus.Fields{
		"event": event,
		"type":  "business_event",
	})
	
	for key, value := range details {
		entry = entry.WithField(key, value)
	}
	
	entry.Info("Business event")
}