package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID            uuid.UUID `json:"id"`
	Username      string    `json:"username"`
	PasswordHash  []byte    `json:"-"` //bcrypt
	EncryptedBlob []byte    `json:"-"` //all data under password
	BlobSalt      []byte    `json:"-"` //salt for password
	KeyVersion    int       `json:"key_version"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Session struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	TokenHash []byte    `json:"-"` //hash of refresh token
	UserAgent string    `json:"user_agent"`
	IPAddress string    `json:"ip_address"`
	ExpiresAt time.Time `json:"expires"`
	CreatedAt time.Time `json:"created_at"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Password string `json:"password" binding:"required,min=12"` //min len of password = 12
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	UserID        uuid.UUID `json:"user_id"`
	Username      string    `json:"username"`
	EncryptedBlob []byte    `json:"encrypted_blob"` //all data of user
	BlobSalt      []byte    `json:"blob_salt"`      //salt for decrypt
	KeyVersion    int       `json:"key_version"`    //check changes of password
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

type LogoutRequest struct {
	LogoutAll bool `json:"logout_all"` //shutdown all devices
}
