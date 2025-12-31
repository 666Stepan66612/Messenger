package middleware

import (
	"auth-service/business"
	"net/http"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware(sessionBiz *business.SessionBusiness) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/register" ||
			c.Request.URL.Path == "/login" ||
			c.Request.URL.Path == "/refresh" {
			c.Next()
			return
		}

		userID, err := sessionBiz.ValidateSession(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		c.Set("user_id", userID)
		c.Next()
	}
}
