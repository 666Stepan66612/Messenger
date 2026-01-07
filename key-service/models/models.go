package models

import (
	"time"

	"github.com/google/uuid"
)

// UserKeys represents public keys for a user
type UserKeys struct {
	UserID          uuid.UUID `json:"user_id"`
	IdentityKey     []byte    `json:"identity_key"`     // Ed25519 public key
	SignedPreKey    []byte    `json:"signed_prekey"`    // X25519 public key
	PreKeySignature []byte    `json:"prekey_signature"` // Signature of prekey
	CreatedAt       time.Time `json:"created_at"`
}

// OneTimeKey represents ephemeral key for initial handshake
type OneTimeKey struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	KeyData   []byte     `json:"key_data"`
	Used      bool       `json:"used"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// ChatKey represents encrypted symmetric key for a chat
type ChatKey struct {
	LookupHash      string    `json:"lookup_hash"`       // HMAC-SHA256(userID + chatID + serverSalt)
	EncryptedKey    []byte    `json:"encrypted_key"`     // AES-256 key encrypted with user's blob key
	EncryptedPeerID []byte    `json:"encrypted_peer_id"` // Peer user ID encrypted
	Nonce           []byte    `json:"nonce"`             // GCM nonce
	CreatedAt       time.Time `json:"created_at"`
}

// UploadKeysRequest is the request to upload user's public keys
type UploadKeysRequest struct {
	IdentityKey     []byte   `json:"identity_key" binding:"required"`
	SignedPreKey    []byte   `json:"signed_prekey" binding:"required"`
	PreKeySignature []byte   `json:"prekey_signature" binding:"required"`
	OneTimeKeys     [][]byte `json:"one_time_keys" binding:"required,min=10"` // At least 10 prekeys
}

// GetKeysResponse returns public keys for a user
type GetKeysResponse struct {
	UserID          uuid.UUID `json:"user_id"`
	IdentityKey     []byte    `json:"identity_key"`
	SignedPreKey    []byte    `json:"signed_prekey"`
	PreKeySignature []byte    `json:"prekey_signature"`
	OneTimeKey      []byte    `json:"one_time_key,omitempty"` // May be nil if all used
}

// CreateChatKeyRequest stores encrypted chat key
type CreateChatKeyRequest struct {
	ChatID          string `json:"chat_id" binding:"required"`
	EncryptedKey    []byte `json:"encrypted_key" binding:"required"`
	EncryptedPeerID []byte `json:"encrypted_peer_id" binding:"required"`
	Nonce           []byte `json:"nonce" binding:"required"`
}

// StoreChatKeyRequest for internal use
type StoreChatKeyRequest struct {
	LookupHash      string
	EncryptedKey    []byte
	EncryptedPeerID []byte
	Nonce           []byte
}

// GetChatKeyResponse returns encrypted chat key
type GetChatKeyResponse struct {
	EncryptedKey    []byte    `json:"encrypted_key"`
	EncryptedPeerID []byte    `json:"encrypted_peer_id"`
	Nonce           []byte    `json:"nonce"`
	CreatedAt       time.Time `json:"created_at"`
}
