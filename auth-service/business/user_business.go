package business

import (
	"database/sql"
	"encoding/json"
	"time"

	"auth-service/crypto"
	"auth-service/models"
	"auth-service/security"

	"github.com/google/uuid"
)

type UserBusiness struct {
	db *sql.DB
}

// NewUserBusiness creates a new user business instance
func NewUserBusiness(db *sql.DB) *UserBusiness {
	return &UserBusiness{db: db}
}

// CreateUser registers a new user with encrypted blob, hashed password, and initial settings
func (b *UserBusiness) CreateUser(username, password string) (*models.User, error) {
	// Validate username
	username = security.SanitizeInput(username)
	if err := security.ValidateUsername(username); err != nil {
		return nil, err
	}

	// Validate password strength
	if err := security.ValidatePassword(password); err != nil {
		return nil, err
	}

	var exists bool
	err := b.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`, username).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, sql.ErrNoRows
	}

	passwordHash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, err
	}

	blobSalt, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}

	// Generate master key for encrypting chat keys
	masterKey, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}

	userBlob := map[string]interface{}{
		"version":    1,
		"master_key": masterKey, // Main key for encrypting chat keys
		"settings": map[string]interface{}{
			"theme":         "dark",
			"notifications": true,
		},
	}

	blobData, err := json.Marshal(userBlob)
	if err != nil {
		return nil, err
	}

	key := crypto.DeriveKey(password, blobSalt)
	encryptedBlob, err := crypto.EncryptAESGCM(key, blobData)
	if err != nil {
		return nil, err
	}

	userID := uuid.New()
	user := &models.User{
		ID:            userID,
		Username:      username,
		PasswordHash:  passwordHash,
		EncryptedBlob: encryptedBlob,
		BlobSalt:      blobSalt,
		KeyVersion:    1,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	_, err = b.db.Exec(`INSERT INTO users (id, username, password_hash, encrypted_blob, blob_salt, key_version)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		userID, username, passwordHash, encryptedBlob, blobSalt, 1)

	return user, err
}

// Login authenticates user by verifying password against stored hash and returns user data
func (b *UserBusiness) Login(username, password string) (*models.User, error) {
	var user models.User

	err := b.db.QueryRow(`SELECT id, username, password_hash, encrypted_blob, blob_salt, key_version, created_at, updated_at
		FROM users WHERE username = $1`, username).Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.EncryptedBlob,
		&user.BlobSalt,
		&user.KeyVersion,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	if !crypto.CheckPasswordHash(password, user.PasswordHash) {
		return nil, sql.ErrNoRows
	}

	return &user, nil
}

// ChangePassword decrypts blob with old password, re-encrypts with new password, updates hash and increments key_version
func (b *UserBusiness) ChangePassword(userID uuid.UUID, oldPassword, newPassword string) error {
	var user models.User
	err := b.db.QueryRow(`SELECT password_hash, encrypted_blob, blob_salt, key_version
		FROM users WHERE id = $1`, userID).Scan(&user.PasswordHash, &user.EncryptedBlob, &user.BlobSalt, &user.KeyVersion)

	if err != nil {
		return err
	}

	if !crypto.CheckPasswordHash(oldPassword, user.PasswordHash) {
		return sql.ErrNoRows
	}

	oldKey := crypto.DeriveKey(oldPassword, user.BlobSalt)
	decryptedBlob, err := crypto.DecryptAESGCM(oldKey, user.EncryptedBlob)
	if err != nil {
		return err
	}

	newBlobSalt, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}

	newKey := crypto.DeriveKey(newPassword, newBlobSalt)
	newEncryptedBlob, err := crypto.EncryptAESGCM(newKey, decryptedBlob)
	if err != nil {
		return err
	}

	newPasswordHash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return err
	}

	_, err = b.db.Exec(`UPDATE users
	SET password_hash = $1, encrypted_blob = $2, blob_salt = $3, key_version = key_version + 1
	WHERE id = $4`, newPasswordHash, newEncryptedBlob, newBlobSalt, userID)

	return err
}

// GetUserData retrieves encrypted blob, salt, and key version for a specific user
func (b *UserBusiness) GetUserData(userID uuid.UUID) (encryptedBlob, blobSalt []byte, keyVersion int, err error) {
	err = b.db.QueryRow(`SELECT encrypted_blob, blob_salt, key_version
	FROM users WHERE id = $1`, userID).Scan(&encryptedBlob, &blobSalt, &keyVersion)

	return
}
