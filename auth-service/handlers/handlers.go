package handlers

import (
	"database/sql"
	"net/http"

	"auth-service/business"
	"auth-service/models"
	"auth-service/security"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	db          *sql.DB
	userBiz     *business.UserBusiness
	sessionBiz  *business.SessionBusiness
	totpManager *security.TOTPManager
	auditLogger *security.AuditLogger
	rateLimiter *security.RateLimiter
}

func NewAuthHandler(db *sql.DB) *AuthHandler {
	serverSalt := "default-salt-change-in-production"
	return &AuthHandler{
		db:          db,
		userBiz:     business.NewUserBusiness(db),
		sessionBiz:  business.NewSessionBusiness(db),
		totpManager: security.NewTOTPManager(db),
		auditLogger: security.NewAuditLogger(db),
		rateLimiter: security.NewRateLimiter(db, serverSalt),
	}
}

/*
Register creates a new user account and establishes a session
body: {"username": "string" (3-50 chars), "password": "string" (min 12 chars)}
status success: 201 Created - returns user_id, username, refresh_token, encrypted_blob, blob_salt, key_version
status failed: 400 Bad Request - invalid request format

	409 Conflict - username already taken
	500 Internal Server Error - failed to create user or session
*/
func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	user, err := h.userBiz.CreateUser(req.Username, req.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusConflict, gin.H{"error": "Username already taken"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	refreshToken, err := h.sessionBiz.CreateSession(
		c.Writer,
		user.ID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// Audit log
	ipHash := h.rateLimiter.HashIP(c.ClientIP())
	h.auditLogger.Log(security.EventRegister, &user.ID, ipHash, map[string]interface{}{
		"username": user.Username,
	})

	c.JSON(http.StatusCreated, gin.H{
		"message":        "User created successfully",
		"user_id":        user.ID,
		"username":       user.Username,
		"refresh_token":  refreshToken,
		"encrypted_blob": user.EncryptedBlob,
		"blob_salt":      user.BlobSalt,
		"key_version":    user.KeyVersion,
	})
}

/*
Login authenticates user and creates a new session
body: {"username": "string", "password": "string"}
status success: 200 OK - returns user_id, username, refresh_token, encrypted_blob, blob_salt, key_version
status failed: 409 Conflict - invalid request format

	401 Unauthorized - invalid credentials
	500 Internal Server Error - failed to create session
*/
func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Invalid request"})
		return
	}

	user, err := h.userBiz.Login(req.Username, req.Password)
	ipHash := h.rateLimiter.HashIP(c.ClientIP())

	if err != nil {
		// Audit failed login
		h.auditLogger.Log(security.EventLoginFailed, nil, ipHash, map[string]interface{}{
			"username": req.Username,
		})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check for suspicious activity
	suspicious, reason := h.auditLogger.DetectSuspiciousActivity(user.ID, ipHash)
	if suspicious {
		h.auditLogger.Log(security.EventSuspiciousActivity, &user.ID, ipHash, map[string]interface{}{
			"reason": reason,
		})
	}

	// Check if 2FA is enabled
	has2FA, _ := h.totpManager.Is2FAEnabled(user.ID)

	refreshToken, err := h.sessionBiz.CreateSession(
		c.Writer,
		user.ID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// Audit successful login
	h.auditLogger.Log(security.EventLoginSuccess, &user.ID, ipHash, map[string]interface{}{
		"username":    user.Username,
		"2fa_enabled": has2FA,
	})

	response := gin.H{
		"user_id":        user.ID,
		"username":       user.Username,
		"refresh_token":  refreshToken,
		"encrypted_blob": user.EncryptedBlob,
		"blob_salt":      user.BlobSalt,
		"key_version":    user.KeyVersion,
		"requires_2fa":   has2FA,
	}

	if suspicious {
		response["warning"] = "Suspicious activity detected: " + reason
	}

	c.JSON(http.StatusOK, response)
}

/*
Logout terminates current session or all user sessions (requires authentication via cookie)
body: {"logout_all": bool} - true to logout from all devices, false for current session only
status success: 200 OK - session(s) terminated successfully
status failed: 400 Bad Request - invalid request format

	401 Unauthorized - not authenticated
	500 Internal Server Error - failed to logout
*/
func (h *AuthHandler) Logout(c *gin.Context) {
	var req models.LogoutRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if req.LogoutAll {
		userID, err := h.sessionBiz.ValidateSession(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			return
		}

		if err := h.sessionBiz.LogoutAll(userID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		}
	} else {
		if err := h.sessionBiz.DeleteSession(c.Request); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
			return
		}
	}

	h.sessionBiz.ClearSessionCookies(c.Writer)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

/*
ChangePassword changes the password for the authenticated user (requires authentication via cookie)
body: {"old_password": "string", "new_password": "string" (min 12 chars)}
status success: 200 OK - returns updated encrypted_blob, blob_salt, key_version
status failed: 400 Bad Request - not authenticated or invalid request format

	401 Unauthorized - invalid old password
	500 Internal Server Error - failed to change password or get user data
*/
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID, err := h.sessionBiz.ValidateSession(c.Request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not authenticated"})
		return
	}

	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if err := h.userBiz.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid old password"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to change password"})
		return
	}

	encryptedBlob, blobSalt, keyVersion, err := h.userBiz.GetUserData(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Password changed successfully",
		"encrypted_blob": encryptedBlob,
		"blob_salt":      blobSalt,
		"key_version":    keyVersion,
	})
}

/*
Refresh renews the session and returns updated tokens (requires authentication via cookie)
body: none (uses cookie for authentication)
status success: 200 OK - returns refresh_token, encrypted_blob, blob_salt, key_version
status failed: 401 Unauthorized - invalid session

	500 Internal Server Error - failed to get user data
*/
func (h *AuthHandler) Refresh(c *gin.Context) {
	refreshToken, err := h.sessionBiz.RefreshSession(c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
		return
	}

	userID, err := h.sessionBiz.ValidateSession(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
	}

	encryptedBlob, blobSalt, keyVersion, err := h.userBiz.GetUserData(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"refresh_token":  refreshToken,
		"encrypted_blob": encryptedBlob,
		"blob_salt":      blobSalt,
		"key_version":    keyVersion,
	})
}

/*
Validate checks if the current session is valid and returns user data (requires authentication via cookie)
body: none (uses cookie for authentication)
status success: 200 OK - returns user_id, encrypted_blob, blob_salt, key_version
status failed: 401 Unauthorized - invalid session

	500 Internal Server Error - failed to get user data
*/
func (h *AuthHandler) Validate(c *gin.Context) {
	userID, err := h.sessionBiz.ValidateSession(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
		return
	}

	encryptedBlob, blobSalt, keyVersion, err := h.userBiz.GetUserData(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":        userID,
		"encrypted_blob": encryptedBlob,
		"blob_salt":      blobSalt,
		"key_version":    keyVersion,
	})
}
