package security

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

var (
	ErrInvalidTOTP       = errors.New("invalid TOTP code")
	Err2FANotEnabled     = errors.New("2FA is not enabled for this user")
	Err2FAAlreadyEnabled = errors.New("2FA is already enabled")
)

// TOTPManager handles TOTP 2FA operations
type TOTPManager struct {
	db *sql.DB
}

// NewTOTPManager creates a new TOTP manager
func NewTOTPManager(db *sql.DB) *TOTPManager {
	return &TOTPManager{db: db}
}

// GenerateSecret creates a new TOTP secret for a user
func (tm *TOTPManager) GenerateSecret(userID uuid.UUID, username string) (string, string, error) {
	// Check if 2FA already enabled
	var exists bool
	err := tm.db.QueryRow(`
		SELECT EXISTS(SELECT 1 FROM user_2fa WHERE user_id = $1 AND enabled = true)
	`, userID).Scan(&exists)

	if err != nil {
		return "", "", err
	}

	if exists {
		return "", "", Err2FAAlreadyEnabled
	}

	// Generate secret
	secret := make([]byte, 20)
	_, err = rand.Read(secret)
	if err != nil {
		return "", "", err
	}

	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	// Generate provisioning URI (for QR code)
	issuer := "SecureMessenger"
	uri := "otpauth://totp/" + issuer + ":" + username + "?secret=" + secretBase32 + "&issuer=" + issuer + "&algorithm=SHA1&digits=6&period=30"

	// Store secret (disabled by default, enabled after first successful validation)
	_, err = tm.db.Exec(`
		INSERT INTO user_2fa (user_id, secret, enabled, created_at)
		VALUES ($1, $2, false, $3)
		ON CONFLICT (user_id) 
		DO UPDATE SET secret = $2, enabled = false, created_at = $3
	`, userID, secretBase32, time.Now())

	if err != nil {
		return "", "", err
	}

	return secretBase32, uri, nil
}

// Enable2FA validates TOTP code and enables 2FA for user
func (tm *TOTPManager) Enable2FA(userID uuid.UUID, code string) error {
	var secret string
	var enabled bool

	err := tm.db.QueryRow(`
		SELECT secret, enabled FROM user_2fa WHERE user_id = $1
	`, userID).Scan(&secret, &enabled)

	if err == sql.ErrNoRows {
		return Err2FANotEnabled
	}
	if err != nil {
		return err
	}

	if enabled {
		return Err2FAAlreadyEnabled
	}

	// Validate TOTP code
	valid := totp.Validate(code, secret)
	if !valid {
		return ErrInvalidTOTP
	}

	// Enable 2FA
	_, err = tm.db.Exec(`
		UPDATE user_2fa SET enabled = true WHERE user_id = $1
	`, userID)

	return err
}

// Disable2FA disables 2FA for user (requires current TOTP code)
func (tm *TOTPManager) Disable2FA(userID uuid.UUID, code string) error {
	var secret string
	var enabled bool

	err := tm.db.QueryRow(`
		SELECT secret, enabled FROM user_2fa WHERE user_id = $1
	`, userID).Scan(&secret, &enabled)

	if err == sql.ErrNoRows {
		return Err2FANotEnabled
	}
	if err != nil {
		return err
	}

	if !enabled {
		return Err2FANotEnabled
	}

	// Validate TOTP code before disabling
	valid := totp.Validate(code, secret)
	if !valid {
		return ErrInvalidTOTP
	}

	// Disable 2FA
	_, err = tm.db.Exec(`
		UPDATE user_2fa SET enabled = false WHERE user_id = $1
	`, userID)

	return err
}

// ValidateTOTP checks if TOTP code is valid for user
func (tm *TOTPManager) ValidateTOTP(userID uuid.UUID, code string) (bool, error) {
	var secret string
	var enabled bool

	err := tm.db.QueryRow(`
		SELECT secret, enabled FROM user_2fa WHERE user_id = $1
	`, userID).Scan(&secret, &enabled)

	if err == sql.ErrNoRows {
		return false, Err2FANotEnabled
	}
	if err != nil {
		return false, err
	}

	if !enabled {
		return false, Err2FANotEnabled
	}

	valid := totp.Validate(code, secret)
	return valid, nil
}

// Is2FAEnabled checks if 2FA is enabled for user
func (tm *TOTPManager) Is2FAEnabled(userID uuid.UUID) (bool, error) {
	var enabled bool
	err := tm.db.QueryRow(`
		SELECT enabled FROM user_2fa WHERE user_id = $1
	`, userID).Scan(&enabled)

	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return enabled, nil
}

// GenerateBackupCodes creates recovery codes for 2FA
func (tm *TOTPManager) GenerateBackupCodes(userID uuid.UUID) ([]string, error) {
	codes := make([]string, 10)

	// Delete old backup codes
	_, err := tm.db.Exec(`DELETE FROM backup_codes WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 10; i++ {
		codeBytes := make([]byte, 6)
		_, err := rand.Read(codeBytes)
		if err != nil {
			return nil, err
		}

		code := base32.StdEncoding.EncodeToString(codeBytes)[:8]
		codes[i] = code

		// Store hashed backup code
		_, err = tm.db.Exec(`
			INSERT INTO backup_codes (user_id, code_hash, used, created_at)
			VALUES ($1, $2, false, $3)
		`, userID, HashBackupCode(code), time.Now())

		if err != nil {
			return nil, err
		}
	}

	return codes, nil
}

// ValidateBackupCode checks and marks backup code as used
func (tm *TOTPManager) ValidateBackupCode(userID uuid.UUID, code string) (bool, error) {
	codeHash := HashBackupCode(code)

	var exists bool
	err := tm.db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM backup_codes 
			WHERE user_id = $1 AND code_hash = $2 AND used = false
		)
	`, userID, codeHash).Scan(&exists)

	if err != nil {
		return false, err
	}

	if !exists {
		return false, nil
	}

	// Mark as used
	_, err = tm.db.Exec(`
		UPDATE backup_codes SET used = true WHERE user_id = $1 AND code_hash = $2
	`, userID, codeHash)

	return err == nil, err
}

// HashBackupCode creates a hash of backup code for storage
func HashBackupCode(code string) string {
	hash := sha256.Sum256([]byte(code))
	return hex.EncodeToString(hash[:])
}
