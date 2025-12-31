package business

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/http"
	"time"

	"auth-service/crypto"

	"github.com/google/uuid"
)

type SessionBusiness struct {
	db *sql.DB
}

// NewSessionBusiness creates a new session business instance
func NewSessionBusiness(db *sql.DB) *SessionBusiness {
	return &SessionBusiness{db: db}
}

// setSessionCookies sets refresh_token and session_id cookies with secure flags
func (b *SessionBusiness) setSessionCookies(w http.ResponseWriter, refreshToken, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   30 * 24 * 60 * 60,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   30 * 24 * 60 * 60,
	})
}

// ClearSessionCookies removes session cookies by setting MaxAge to -1
func (b *SessionBusiness) ClearSessionCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Path:     "/",
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// CreateSession generates a new session with refresh token, stores it in DB, and sets cookies
func (b *SessionBusiness) CreateSession(w http.ResponseWriter, userID uuid.UUID, userAgent, ipAddress string) (string, error) {
	refreshToken := make([]byte, 32)
	if _, err := rand.Read(refreshToken); err != nil {
		return "", err
	}

	refreshTokenHash := crypto.HashToken(refreshToken)
	refreshTokenB64 := base64.URLEncoding.EncodeToString(refreshToken)

	sessionID := uuid.New()
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	_, err := b.db.Exec(`
	INSERT INTO sessions (id, user_id, token_hash, user_agent,ip_address, expires_at)
	VALUES ($1, $2, $3, $4, $5, $6)`, sessionID, userID, refreshTokenHash, userAgent, ipAddress, expiresAt)

	if err != nil {
		return "", err
	}

	b.setSessionCookies(w, refreshTokenB64, sessionID.String())

	return refreshTokenB64, nil
}

// ValidateSession verifies session cookies, checks token validity and expiration, returns userID
func (b *SessionBusiness) ValidateSession(r *http.Request) (uuid.UUID, error) {
	refreshTokenCookie, err := r.Cookie("refresh_token")
	if err != nil {
		return uuid.Nil, err
	}

	sessionIDCookie, err := r.Cookie("session_id")
	if err != nil {
		return uuid.Nil, err
	}

	refreshToken, err := base64.URLEncoding.DecodeString(refreshTokenCookie.Value)
	if err != nil {
		return uuid.Nil, err
	}

	refreshTokenHash := crypto.HashToken(refreshToken)
	sessionID, err := uuid.Parse(sessionIDCookie.Value)
	if err != nil {
		return uuid.Nil, err
	}

	var userID uuid.UUID
	var expiresAt time.Time

	err = b.db.QueryRow(`
		SELECT user_id, expires_at
		FROM sessions
		WHERE id = $1 AND token_hash = $2 AND expires_at > NOW()
		`, sessionID, refreshTokenHash).Scan(&userID, &expiresAt)

	if err != nil {
		return uuid.Nil, err
	}

	var revoked bool
	b.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM revoked_sessions WHERE token_hash = $1)
	`, refreshTokenHash).Scan(&revoked)
	if revoked {
		return uuid.Nil, sql.ErrNoRows
	}

	return userID, nil
}

// DeleteSession revokes the current session by adding token to revoked list and deleting from sessions table
func (b *SessionBusiness) DeleteSession(r *http.Request) error {
	refreshTokenCookie, err := r.Cookie("refresh_token")
	if err != nil {
		return err
	}

	refreshToken, err := base64.URLEncoding.DecodeString(refreshTokenCookie.Value)
	if err != nil {
		return err
	}

	refreshTokenHash := crypto.HashToken(refreshToken)

	_, err = b.db.Exec(`INSERT INTO revoked_sessions (token_hash) 
	VALUES ($1) 
	ON CONFLICT DO NOTHING`, refreshTokenHash)
	if err != nil {
		return err
	}

	_, err = b.db.Exec(`DELETE FROM sessions
		WHERE token_hash = $1`, refreshTokenHash)

	return err
}

// RefreshSession validates current session, deletes it, and creates a new one with fresh tokens
func (b *SessionBusiness) RefreshSession(w http.ResponseWriter, r *http.Request) (string, error) {
	userID, err := b.ValidateSession(r)
	if err != nil {
		return "", err
	}

	userAgent := r.UserAgent()
	ipAddress := r.RemoteAddr

	if err := b.DeleteSession(r); err != nil {
		return "", err
	}

	return b.CreateSession(w, userID, userAgent, ipAddress)
}

// LogoutAll revokes all sessions for a specific user by adding all tokens to revoked list
func (b *SessionBusiness) LogoutAll(userID uuid.UUID) error {
	rows, err := b.db.Query(`
	SELECT token_hash 
	FROM sessions
	WHERE user_id = $1
	`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var tokenHash []byte
		if err := rows.Scan(&tokenHash); err != nil {
			continue
		}
		b.db.Exec(`
		INSERT INTO revoked_sessions (token_hash)
		VALUES ($1)
		ON CONFLICT DO NOTHING
		`, tokenHash)
	}

	_, err = b.db.Exec("DELETE FROM sessions WHERE user_id = $1", userID)

	return err
}
