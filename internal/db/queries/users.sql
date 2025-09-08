-- name: CreateUser :one
INSERT INTO users (id, email, password, email_verify_token, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: UpdateUser :exec
UPDATE users 
SET email = $2, password = $3, email_verified = $4, email_verify_token = $5,
    password_reset_token = $6, password_reset_expiry = $7,
    failed_login_attempts = $8, locked_until = $9, updated_at = $10
WHERE id = $1;

-- name: VerifyEmail :exec
UPDATE users 
SET email_verified = true, email_verify_token = NULL, updated_at = $2
WHERE email_verify_token = $1 AND email_verified = false;

-- name: IncrementFailedLoginAttempts :exec
UPDATE users
SET failed_login_attempts = failed_login_attempts + 1,
    locked_until = CASE
        WHEN failed_login_attempts >= 4 THEN $2
        ELSE locked_until
    END,
    updated_at = $3
WHERE email = $1;

-- name: ResetFailedLoginAttempts :exec
UPDATE users
SET failed_login_attempts = 0, locked_until = NULL, updated_at = $2
WHERE email = $1;

-- name: GetUserByPasswordResetToken :one
SELECT * FROM users WHERE password_reset_token = $1;