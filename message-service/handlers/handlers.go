package handlers

import (
	"database/sql"
	"net/http"
	"strconv"

	"message-service/business"
	"message-service/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type MessageHandler struct {
	db         *sql.DB
	messageBiz *business.MessageBusiness
}

func NewMessageHandler(db *sql.DB) *MessageHandler {
	return &MessageHandler{
		db:         db,
		messageBiz: business.NewMessageBusiness(db),
	}
}

// SendMessage handles sending an encrypted message
// POST /messages/send
func (h *MessageHandler) SendMessage(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	senderID, err := uuid.Parse(userID.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var req models.SendMessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Join chat if not already a participant
	if err := h.messageBiz.JoinChat(req.ChatID, senderID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to join chat"})
		return
	}

	message, err := h.messageBiz.SendMessage(senderID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send message"})
		return
	}

	c.JSON(http.StatusOK, message)
}

// GetMessages retrieves messages for a chat with pagination
// GET /messages/:chatId?limit=50&offset=0
func (h *MessageHandler) GetMessages(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	chatID := c.Param("chatId")
	if chatID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Chat ID required"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	if limit > 100 {
		limit = 100
	}

	messages, err := h.messageBiz.GetMessages(chatID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get messages"})
		return
	}

	// Update last read timestamp
	userUUID, _ := uuid.Parse(userID.(string))
	h.messageBiz.UpdateLastRead(chatID, userUUID)

	c.JSON(http.StatusOK, messages)
}

// MarkAsRead marks a message as read
// PUT /messages/:messageId/read
func (h *MessageHandler) MarkAsRead(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	messageIDStr := c.Param("messageId")
	messageID, err := uuid.Parse(messageIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid message ID"})
		return
	}

	userUUID, _ := uuid.Parse(userID.(string))
	if err := h.messageBiz.MarkAsRead(messageID, userUUID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark as read"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Marked as read"})
}

// DeleteMessage deletes a message
// DELETE /messages/:messageId?for_everyone=false
func (h *MessageHandler) DeleteMessage(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	messageIDStr := c.Param("messageId")
	messageID, err := uuid.Parse(messageIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid message ID"})
		return
	}

	forEveryone, _ := strconv.ParseBool(c.DefaultQuery("for_everyone", "false"))
	userUUID, _ := uuid.Parse(userID.(string))

	if err := h.messageBiz.DeleteMessage(messageID, userUUID, forEveryone); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete message"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Message deleted"})
}

// GetUserChats returns list of user's chats
// GET /chats
func (h *MessageHandler) GetUserChats(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	userUUID, _ := uuid.Parse(userID.(string))
	chats, err := h.messageBiz.GetUserChats(userUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get chats"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"chats": chats})
}
