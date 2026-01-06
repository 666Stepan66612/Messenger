package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Setup2FA generates TOTP secret and QR code URI for enabling 2FA
func (h *AuthHandler) Setup2FA(c *gin.Context) {
	userID, err := h.sessionBiz.ValidateSession(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Get username
	username, _, _, err := h.userBiz.GetUserData(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user data"})
		return
	}

	secret, uri, err := h.totpManager.GenerateSecret(userID, string(username))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret":  secret,
		"qr_uri":  uri,
		"message": "Scan QR code with authenticator app, then call /2fa/enable with a valid code",
	})
}

// Enable2FA validates TOTP code and enables 2FA
func (h *AuthHandler) Enable2FA(c *gin.Context) {
	userID, err := h.sessionBiz.ValidateSession(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	err = h.totpManager.Enable2FA(userID, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate backup codes
	backupCodes, err := h.totpManager.GenerateBackupCodes(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate backup codes"})
		return
	}

	// Audit log
	ipHash := h.rateLimiter.HashIP(c.ClientIP())
	h.auditLogger.Log("2fa_enabled", &userID, ipHash, nil)

	c.JSON(http.StatusOK, gin.H{
		"message":      "2FA enabled successfully",
		"backup_codes": backupCodes,
		"warning":      "Save these backup codes in a secure place. Each can only be used once.",
	})
}

// Disable2FA disables 2FA (requires current TOTP code)
func (h *AuthHandler) Disable2FA(c *gin.Context) {
	userID, err := h.sessionBiz.ValidateSession(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	err = h.totpManager.Disable2FA(userID, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Audit log
	ipHash := h.rateLimiter.HashIP(c.ClientIP())
	h.auditLogger.Log("2fa_disabled", &userID, ipHash, nil)

	c.JSON(http.StatusOK, gin.H{
		"message": "2FA disabled successfully",
	})
}

// Verify2FA validates TOTP code during login
func (h *AuthHandler) Verify2FA(c *gin.Context) {
	userID, err := h.sessionBiz.ValidateSession(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Try TOTP code first
	valid, err := h.totpManager.ValidateTOTP(userID, req.Code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if !valid {
		// Try backup code
		valid, err = h.totpManager.ValidateBackupCode(userID, req.Code)
		if err != nil || !valid {
			ipHash := h.rateLimiter.HashIP(c.ClientIP())
			h.auditLogger.Log("2fa_failed", &userID, ipHash, nil)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid code"})
			return
		}
	}

	// Audit log
	ipHash := h.rateLimiter.HashIP(c.ClientIP())
	h.auditLogger.Log("2fa_success", &userID, ipHash, nil)

	c.JSON(http.StatusOK, gin.H{
		"message": "2FA verified successfully",
	})
}

// GetSecurityEvents returns audit logs for the authenticated user
func (h *AuthHandler) GetSecurityEvents(c *gin.Context) {
	userID, err := h.sessionBiz.ValidateSession(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	events, err := h.auditLogger.GetUserEvents(userID, 50)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get security events"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"events": events,
	})
}
