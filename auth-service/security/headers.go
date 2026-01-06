package security

import (
	"github.com/gin-gonic/gin"
)

// SecureHeadersMiddleware adds security headers to all responses
func SecureHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// HSTS - Force HTTPS for 1 year
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Enable XSS protection
		c.Header("X-XSS-Protection", "1; mode=block")

		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")

		// Content Security Policy - strict
		c.Header("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self'")

		// Referrer policy - no referrer for privacy
		c.Header("Referrer-Policy", "no-referrer")

		// Permissions policy - disable all browser features
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()")

		// Remove server identification
		c.Header("Server", "")
		c.Header("X-Powered-By", "")

		c.Next()
	}
}

// CORSMiddleware handles CORS with security in mind
func CORSMiddleware(allowedOrigins []string) gin.HandlerFunc {
	allowedOriginsMap := make(map[string]bool)
	for _, origin := range allowedOrigins {
		allowedOriginsMap[origin] = true
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Only allow whitelisted origins
		if allowedOriginsMap[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
		} else if len(allowedOrigins) == 0 {
			// Development mode - allow all (WARNING: remove in production)
			c.Header("Access-Control-Allow-Origin", "*")
		}

		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PUT")
		c.Header("Access-Control-Max-Age", "86400") // 24 hours

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
