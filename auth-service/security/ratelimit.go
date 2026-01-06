package security

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter manages rate limiting with IP hashing for privacy
type RateLimiter struct {
	db          *sql.DB
	serverSalt  string
	attempts    map[string]*attemptRecord
	mu          sync.RWMutex
	cleanupDone chan bool
}

type attemptRecord struct {
	count      int
	firstTime  time.Time
	blockUntil time.Time
}

// NewRateLimiter creates a new rate limiter instance
func NewRateLimiter(db *sql.DB, serverSalt string) *RateLimiter {
	rl := &RateLimiter{
		db:          db,
		serverSalt:  serverSalt,
		attempts:    make(map[string]*attemptRecord),
		cleanupDone: make(chan bool),
	}

	// Start cleanup goroutine
	go rl.cleanupExpiredRecords()

	return rl
}

// hashIP creates SHA-256 hash of IP with server salt (privacy-preserving)
func (rl *RateLimiter) HashIP(ip string) string {
	hash := sha256.Sum256([]byte(ip + rl.serverSalt))
	return hex.EncodeToString(hash[:])
}

// CheckLoginAttempt verifies if login attempt is allowed
// Returns: allowed (bool), retryAfter (seconds), error
func (rl *RateLimiter) CheckLoginAttempt(ipHash string) (bool, int, error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	record, exists := rl.attempts[ipHash]

	// Check if blocked
	if exists && now.Before(record.blockUntil) {
		retryAfter := int(record.blockUntil.Sub(now).Seconds())
		return false, retryAfter, nil
	}

	// Reset if window expired (15 minutes)
	if !exists || now.Sub(record.firstTime) > 15*time.Minute {
		rl.attempts[ipHash] = &attemptRecord{
			count:     1,
			firstTime: now,
		}
		return true, 0, nil
	}

	// Increment counter
	record.count++

	// Progressive blocking:
	// 5 attempts = 1 min block
	// 10 attempts = 5 min block
	// 15 attempts = 15 min block
	// 20+ attempts = 1 hour block
	switch {
	case record.count >= 20:
		record.blockUntil = now.Add(1 * time.Hour)
	case record.count >= 15:
		record.blockUntil = now.Add(15 * time.Minute)
	case record.count >= 10:
		record.blockUntil = now.Add(5 * time.Minute)
	case record.count >= 5:
		record.blockUntil = now.Add(1 * time.Minute)
	}

	if !record.blockUntil.IsZero() && now.Before(record.blockUntil) {
		retryAfter := int(record.blockUntil.Sub(now).Seconds())

		// Log to database for persistent tracking
		rl.logFailedAttempt(ipHash, record.count)

		return false, retryAfter, nil
	}

	return true, 0, nil
}

// RecordSuccessfulLogin resets the attempt counter for IP
func (rl *RateLimiter) RecordSuccessfulLogin(ipHash string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, ipHash)

	// Log successful login
	rl.db.Exec(`
		INSERT INTO login_attempts (ip_hash, success, attempts_count)
		VALUES ($1, $2, $3)
	`, ipHash, true, 1)
}

// logFailedAttempt records failed attempt in database
func (rl *RateLimiter) logFailedAttempt(ipHash string, count int) {
	rl.db.Exec(`
		INSERT INTO login_attempts (ip_hash, success, attempts_count)
		VALUES ($1, $2, $3)
	`, ipHash, false, count)
}

// cleanupExpiredRecords removes old records from memory every 30 minutes
func (rl *RateLimiter) cleanupExpiredRecords() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for key, record := range rl.attempts {
				// Remove if older than 1 hour and not blocked
				if now.Sub(record.firstTime) > 1*time.Hour && now.After(record.blockUntil) {
					delete(rl.attempts, key)
				}
			}
			rl.mu.Unlock()
		case <-rl.cleanupDone:
			return
		}
	}
}

// Stop gracefully stops the rate limiter
func (rl *RateLimiter) Stop() {
	close(rl.cleanupDone)
}

// RateLimitMiddleware creates a Gin middleware for rate limiting
func RateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only apply to login/register endpoints
		if c.Request.URL.Path != "/login" && c.Request.URL.Path != "/register" {
			c.Next()
			return
		}

		ip := c.ClientIP()
		ipHash := rl.HashIP(ip)

		allowed, retryAfter, err := rl.CheckLoginAttempt(ipHash)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Rate limit check failed"})
			c.Abort()
			return
		}

		if !allowed {
			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many attempts",
				"retry_after": retryAfter,
			})
			c.Abort()
			return
		}

		c.Next()

		// Record success if login was successful (status 200 or 201)
		if c.Writer.Status() == 200 || c.Writer.Status() == 201 {
			rl.RecordSuccessfulLogin(ipHash)
		}
	}
}
