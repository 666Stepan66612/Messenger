package business

import (
	"database/sql"
	"time"

	"message-service/models"

	"github.com/google/uuid"
)

type MessageBusiness struct {
	db *sql.DB
}

func NewMessageBusiness(db *sql.DB) *MessageBusiness {
	return &MessageBusiness{db: db}
}

// SendMessage stores an encrypted message
func (b *MessageBusiness) SendMessage(senderID uuid.UUID, req models.SendMessageRequest) (*models.Message, error) {
	message := &models.Message{
		ID:               uuid.New(),
		ChatID:           req.ChatID,
		SenderID:         senderID,
		EncryptedContent: req.EncryptedContent,
		Nonce:            req.Nonce,
		MessageType:      req.MessageType,
		ReplyToID:        req.ReplyToID,
		CreatedAt:        time.Now(),
	}

	_, err := b.db.Exec(`
		INSERT INTO messages (id, chat_id, sender_id, encrypted_content, nonce, message_type, reply_to_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, message.ID, message.ChatID, message.SenderID, message.EncryptedContent,
		message.Nonce, message.MessageType, message.ReplyToID)

	if err != nil {
		return nil, err
	}

	return message, nil
}

// GetMessages retrieves messages for a chat with pagination
func (b *MessageBusiness) GetMessages(chatID string, limit, offset int) (*models.GetMessagesResponse, error) {
	// Get total count
	var totalCount int64
	err := b.db.QueryRow(`
		SELECT COUNT(*) FROM messages WHERE chat_id = $1
	`, chatID).Scan(&totalCount)
	if err != nil {
		return nil, err
	}

	// Get messages
	rows, err := b.db.Query(`
		SELECT id, chat_id, sender_id, encrypted_content, nonce, message_type, 
		       reply_to_id, read_at, edited_at, created_at
		FROM messages
		WHERE chat_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`, chatID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	messages := []models.Message{}
	for rows.Next() {
		var msg models.Message
		err := rows.Scan(&msg.ID, &msg.ChatID, &msg.SenderID, &msg.EncryptedContent,
			&msg.Nonce, &msg.MessageType, &msg.ReplyToID, &msg.ReadAt, &msg.EditedAt, &msg.CreatedAt)
		if err != nil {
			continue
		}
		messages = append(messages, msg)
	}

	hasMore := int64(offset+limit) < totalCount

	return &models.GetMessagesResponse{
		Messages:   messages,
		TotalCount: totalCount,
		HasMore:    hasMore,
	}, nil
}

// MarkAsRead updates read_at timestamp for a message
func (b *MessageBusiness) MarkAsRead(messageID uuid.UUID, userID uuid.UUID) error {
	_, err := b.db.Exec(`
		UPDATE messages 
		SET read_at = CURRENT_TIMESTAMP
		WHERE id = $1 AND read_at IS NULL
	`, messageID)
	return err
}

// DeleteMessage soft deletes a message for a specific user
func (b *MessageBusiness) DeleteMessage(messageID uuid.UUID, userID uuid.UUID, forEveryone bool) error {
	if forEveryone {
		// Hard delete for everyone
		_, err := b.db.Exec(`DELETE FROM messages WHERE id = $1`, messageID)
		return err
	}

	// Soft delete for specific user
	_, err := b.db.Exec(`
		INSERT INTO deleted_messages (message_id, user_id)
		VALUES ($1, $2)
		ON CONFLICT (message_id, user_id) DO NOTHING
	`, messageID, userID)
	return err
}

// GetUserChats returns list of chats for a user
func (b *MessageBusiness) GetUserChats(userID uuid.UUID) ([]models.ChatInfo, error) {
	rows, err := b.db.Query(`
		SELECT DISTINCT m.chat_id, MAX(m.created_at) as last_message_at,
		       COUNT(CASE WHEN m.read_at IS NULL AND m.sender_id != $1 THEN 1 END) as unread_count
		FROM messages m
		LEFT JOIN deleted_messages dm ON m.id = dm.message_id AND dm.user_id = $1
		WHERE dm.message_id IS NULL
		  AND m.chat_id IN (
		      SELECT chat_id FROM chat_participants WHERE user_id = $1
		  )
		GROUP BY m.chat_id
		ORDER BY last_message_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	chats := []models.ChatInfo{}
	for rows.Next() {
		var chat models.ChatInfo
		err := rows.Scan(&chat.ChatID, &chat.LastMessageAt, &chat.UnreadCount)
		if err != nil {
			continue
		}
		chats = append(chats, chat)
	}

	return chats, nil
}

// JoinChat adds user to chat participants
func (b *MessageBusiness) JoinChat(chatID string, userID uuid.UUID) error {
	_, err := b.db.Exec(`
		INSERT INTO chat_participants (chat_id, user_id)
		VALUES ($1, $2)
		ON CONFLICT (chat_id, user_id) DO NOTHING
	`, chatID, userID)
	return err
}

// UpdateLastRead updates user's last read timestamp for a chat
func (b *MessageBusiness) UpdateLastRead(chatID string, userID uuid.UUID) error {
	_, err := b.db.Exec(`
		UPDATE chat_participants
		SET last_read_at = CURRENT_TIMESTAMP
		WHERE chat_id = $1 AND user_id = $2
	`, chatID, userID)
	return err
}
