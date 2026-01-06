package security

import (
	"errors"
	"regexp"
	"strings"
)

var (
	ErrPasswordTooShort     = errors.New("password must be at least 8 characters")
	ErrUsernameTooShort     = errors.New("username must be at least 3 characters")
	ErrUsernameTooLong      = errors.New("username must be at most 50 characters")
	ErrUsernameInvalidChars = errors.New("username can only contain letters, numbers, underscore, and hyphen")
)

// ValidatePassword performs minimal password validation
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return ErrPasswordTooShort
	}
	return nil
}

// ValidateUsername validates username format
func ValidateUsername(username string) error {
	if len(username) < 3 {
		return ErrUsernameTooShort
	}

	if len(username) > 50 {
		return ErrUsernameTooLong
	}

	// Only allow alphanumeric, underscore, and hyphen
	validUsername := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validUsername.MatchString(username) {
		return ErrUsernameInvalidChars
	}

	return nil
}

// SanitizeInput removes potentially dangerous characters
func SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Trim whitespace
	input = strings.TrimSpace(input)

	return input
}
