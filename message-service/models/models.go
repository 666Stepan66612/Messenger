package models

import (
	"time"

	"github.com/google/uuid"
)

// Message represents an encrypted message in a chat
type Message struct {
	ID               uuid.UUID  `json:"id"`
	ChatID           string     `json:"chat_id"`
	SenderID         uuid.UUID  `json:"sender_id"`
	EncryptedContent []byte     `json:"encrypted_content"` // AES-GCM encrypted message
	Nonce            []byte     `json:"nonce"`             // GCM nonce
	MessageType      string     `json:"message_type"`      // text, image, file, etc.
	ReplyToID        *uuid.UUID `json:"reply_to_id,omitempty"`
	ReadAt           *time.Time `json:"read_at,omitempty"`
	EditedAt         *time.Time `json:"edited_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// Attachment represents a file attachment metadata
type Attachment struct {
	ID            uuid.UUID `json:"id"`
	MessageID     uuid.UUID `json:"message_id"`
	EncryptedURL  []byte    `json:"encrypted_url"`           // Encrypted S3/storage URL
	EncryptedName []byte    `json:"encrypted_name"`          // Original filename
	EncryptedMIME []byte    `json:"encrypted_mime"`          // MIME type
	Size          int64     `json:"size"`                    // File size in bytes
	ThumbnailURL  string    `json:"thumbnail_url,omitempty"` // Optional thumbnail
	CreatedAt     time.Time `json:"created_at"`
}

// SendMessageRequest is the request to send a message
type SendMessageRequest struct {
	ChatID           string     `json:"chat_id" binding:"required"`
	EncryptedContent []byte     `json:"encrypted_content" binding:"required"`
	Nonce            []byte     `json:"nonce" binding:"required"`
	MessageType      string     `json:"message_type" binding:"required"` // text, image, file
	ReplyToID        *uuid.UUID `json:"reply_to_id,omitempty"`
}

// GetMessagesResponse returns paginated messages
type GetMessagesResponse struct {
	Messages   []Message `json:"messages"`
	TotalCount int64     `json:"total_count"`
	HasMore    bool      `json:"has_more"`
}

// ChatInfo represents basic chat information
type ChatInfo struct {
	ChatID        string    `json:"chat_id"`
	LastMessageAt time.Time `json:"last_message_at"`
	UnreadCount   int       `json:"unread_count"`
	LastMessage   *Message  `json:"last_message,omitempty"`
}
