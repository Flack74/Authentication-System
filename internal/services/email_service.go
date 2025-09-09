package services

import (
	"fmt"

	"github.com/Flack74/go-auth-system/internal/config"
	"gopkg.in/gomail.v2"
)

type EmailService struct {
	config *config.Config
}

func NewEmailService(config *config.Config) *EmailService {
	return &EmailService{config: config}
}

func (s *EmailService) SendVerificationEmail(email, token string) error {
	subject := "Verify Your Email Address"
	verifyURL := fmt.Sprintf("%s/auth/verify?token=%s", s.config.BaseURL, token)
	
	body := fmt.Sprintf(`
		<h2>Email Verification</h2>
		<p>Please click the link below to verify your email address:</p>
		<a href="%s">Verify Email</a>
		<p>If you didn't create an account, please ignore this email.</p>
	`, verifyURL)

	return s.sendEmail(email, subject, body)
}

func (s *EmailService) SendPasswordResetEmail(email, token string) error {
	subject := "Password Reset Request"
	resetURL := fmt.Sprintf("%s/auth/password/reset?token=%s", s.config.BaseURL, token)
	
	body := fmt.Sprintf(`
		<h2>Password Reset</h2>
		<p>You requested a password reset. Click the link below to reset your password:</p>
		<a href="%s">Reset Password</a>
		<p>This link will expire in 1 hour.</p>
		<p>If you didn't request this, please ignore this email.</p>
	`, resetURL)

	return s.sendEmail(email, subject, body)
}

func (s *EmailService) sendEmail(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.config.EmailFrom)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer(s.config.SMTPHost, s.config.SMTPPort, s.config.SMTPUser, s.config.SMTPPassword)

	return d.DialAndSend(m)
}