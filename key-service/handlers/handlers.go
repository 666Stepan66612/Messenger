package handlers

import (
	"database/sql"
	"net/http"

	"key-service/business"
	"key-service/crypto"
	"key-service/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type KeyHandler struct {
	db         *sql.DB
	keyBiz     *business.KeyBusiness
	serverSalt string
}

func NewKeyHandler(db *sql.DB, serverSalt string) *KeyHandler {
	return &KeyHandler{
		db:         db,
		keyBiz:     business.NewKeyBusiness(db),
		serverSalt: serverSalt,
	}
}

// UploadKeys stores user's public keys
// POST /keys/upload
func (h *KeyHandler) UploadKeys(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req models.UploadKeysRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	err := h.keyBiz.UploadUserKeys(userID.(uuid.UUID), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload keys"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":             "Keys uploaded successfully",
		"one_time_keys_count": len(req.OneTimeKeys),
	})
}

// GetKeys retrieves public keys for a user
// GET /keys/:userId
func (h *KeyHandler) GetKeys(c *gin.Context) {
	userIDStr := c.Param("userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	keys, err := h.keyBiz.GetUserKeys(userID)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "User keys not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get keys"})
		return
	}

	c.JSON(http.StatusOK, keys)
}

// CreateChatKey stores encrypted chat key
// POST /chat/key
func (h *KeyHandler) CreateChatKey(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req models.CreateChatKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Generate privacy-preserving lookup hash
	lookupHash := crypto.GenerateLookupHash(
		userID.(uuid.UUID).String(),
		req.ChatID,
		h.serverSalt,
	)

	err := h.keyBiz.StoreChatKey(lookupHash, req.EncryptedKey, req.EncryptedPeerID, req.Nonce)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store chat key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Chat key stored successfully",
		"lookup_hash": lookupHash,
	})
}

// GetChatKey retrieves encrypted chat key
// GET /chat/key/:chatId
func (h *KeyHandler) GetChatKey(c *gin.Context) {
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

	lookupHash := crypto.GenerateLookupHash(
		userID.(uuid.UUID).String(),
		chatID,
		h.serverSalt,
	)

	chatKey, err := h.keyBiz.GetChatKey(lookupHash)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Chat key not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get chat key"})
		return
	}

	c.JSON(http.StatusOK, chatKey)
}

// GetKeyStatus returns user's key upload status
// GET /keys/status
func (h *KeyHandler) GetKeyStatus(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	uid, err := uuid.Parse(userID.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	var hasKeys bool
	var otkCount int

	// Check if user has keys
	err = h.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM user_keys WHERE user_id = $1)`, uid).Scan(&hasKeys)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check keys"})
		return
	}

	// Count unused one-time keys
	if hasKeys {
		h.db.QueryRow(`SELECT COUNT(*) FROM one_time_keys WHERE user_id = $1 AND used = false`, uid).Scan(&otkCount)
	}

	c.JSON(http.StatusOK, gin.H{
		"has_keys":           hasKeys,
		"one_time_keys_left": otkCount,
		"needs_upload":       !hasKeys || otkCount < 5,
	})
}
