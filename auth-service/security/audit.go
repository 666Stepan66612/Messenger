package security

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AuditEventType defines the type of security event
type AuditEventType string

const (
	EventLoginSuccess       AuditEventType = "login_success"
	EventLoginFailed        AuditEventType = "login_failed"
	EventRegister           AuditEventType = "register"
	EventPasswordChange     AuditEventType = "password_change"
	EventLogout             AuditEventType = "logout"
	EventLogoutAll          AuditEventType = "logout_all"
	EventSessionValidation  AuditEventType = "session_validation"
	EventRateLimitExceeded  AuditEventType = "rate_limit_exceeded"
	Event2FAEnabled         AuditEventType = "2fa_enabled"
	Event2FADisabled        AuditEventType = "2fa_disabled"
	Event2FASuccess         AuditEventType = "2fa_success"
	Event2FAFailed          AuditEventType = "2fa_failed"
	EventSuspiciousActivity AuditEventType = "suspicious_activity"
)

// AuditLogger handles security event logging
type AuditLogger struct {
	db *sql.DB
}

// AuditEvent represents a security event
type AuditEvent struct {
	ID        uuid.UUID              `json:"id"`
	UserID    *uuid.UUID             `json:"user_id,omitempty"`
	EventType AuditEventType         `json:"event_type"`
	IPHash    string                 `json:"ip_hash"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(db *sql.DB) *AuditLogger {
	return &AuditLogger{db: db}
}

// Log records a security event
func (al *AuditLogger) Log(eventType AuditEventType, userID *uuid.UUID, ipHash string, metadata map[string]interface{}) error {
	eventID := uuid.New()
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	_, err = al.db.Exec(`
		INSERT INTO audit_logs (id, user_id, event_type, ip_hash, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, eventID, userID, eventType, ipHash, metadataJSON, time.Now())

	return err
}

// GetUserEvents retrieves audit events for a specific user
func (al *AuditLogger) GetUserEvents(userID uuid.UUID, limit int) ([]AuditEvent, error) {
	rows, err := al.db.Query(`
		SELECT id, user_id, event_type, ip_hash, metadata, created_at
		FROM audit_logs
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []AuditEvent
	for rows.Next() {
		var event AuditEvent
		var metadataJSON []byte

		err := rows.Scan(
			&event.ID,
			&event.UserID,
			&event.EventType,
			&event.IPHash,
			&metadataJSON,
			&event.CreatedAt,
		)
		if err != nil {
			continue
		}

		json.Unmarshal(metadataJSON, &event.Metadata)
		events = append(events, event)
	}

	return events, nil
}

// DetectSuspiciousActivity checks for suspicious patterns
func (al *AuditLogger) DetectSuspiciousActivity(userID uuid.UUID, ipHash string) (bool, string) {
	// Check for multiple failed logins in last hour
	var failedCount int
	al.db.QueryRow(`
		SELECT COUNT(*)
		FROM audit_logs
		WHERE user_id = $1
		  AND event_type = $2
		  AND created_at > NOW() - INTERVAL '1 hour'
	`, userID, EventLoginFailed).Scan(&failedCount)

	if failedCount >= 3 {
		return true, "multiple_failed_logins"
	}

	// Check for login from new IP (different from last 10 successful logins)
	var knownIPCount int
	al.db.QueryRow(`
		SELECT COUNT(*)
		FROM audit_logs
		WHERE user_id = $1
		  AND event_type = $2
		  AND ip_hash = $3
		  AND created_at > NOW() - INTERVAL '30 days'
		LIMIT 10
	`, userID, EventLoginSuccess, ipHash).Scan(&knownIPCount)

	if knownIPCount == 0 {
		return true, "unknown_ip_address"
	}

	// Check for rapid session creation (>5 sessions in 5 minutes)
	var rapidSessions int
	al.db.QueryRow(`
		SELECT COUNT(*)
		FROM audit_logs
		WHERE user_id = $1
		  AND event_type = $2
		  AND created_at > NOW() - INTERVAL '5 minutes'
	`, userID, EventLoginSuccess).Scan(&rapidSessions)

	if rapidSessions >= 5 {
		return true, "rapid_session_creation"
	}

	return false, ""
}
