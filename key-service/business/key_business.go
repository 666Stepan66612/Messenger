package business

import (
	"database/sql"
	"time"

	"key-service/models"

	"github.com/google/uuid"
)

type KeyBusiness struct {
	db *sql.DB
}

func NewKeyBusiness(db *sql.DB) *KeyBusiness {
	return &KeyBusiness{db: db}
}

// UploadUserKeys stores user's public keys
func (b *KeyBusiness) UploadUserKeys(userID uuid.UUID, req models.UploadKeysRequest) error {
	tx, err := b.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Insert or update user keys
	_, err = tx.Exec(`
		INSERT INTO user_keys (user_id, identity_key, signed_prekey, prekey_signature)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id) DO UPDATE SET
			identity_key = $2,
			signed_prekey = $3,
			prekey_signature = $4,
			created_at = CURRENT_TIMESTAMP
	`, userID, req.IdentityKey, req.SignedPreKey, req.PreKeySignature)
	if err != nil {
		return err
	}

	// Delete old one-time keys
	_, err = tx.Exec(`DELETE FROM one_time_keys WHERE user_id = $1`, userID)
	if err != nil {
		return err
	}

	// Insert new one-time keys
	for _, keyData := range req.OneTimeKeys {
		_, err = tx.Exec(`
			INSERT INTO one_time_keys (user_id, key_data)
			VALUES ($1, $2)
		`, userID, keyData)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetUserKeys retrieves public keys for a user
func (b *KeyBusiness) GetUserKeys(userID uuid.UUID) (*models.GetKeysResponse, error) {
	var resp models.GetKeysResponse
	resp.UserID = userID

	// Get user keys
	err := b.db.QueryRow(`
		SELECT identity_key, signed_prekey, prekey_signature
		FROM user_keys
		WHERE user_id = $1
	`, userID).Scan(&resp.IdentityKey, &resp.SignedPreKey, &resp.PreKeySignature)
	if err != nil {
		return nil, err
	}

	// Get one unused one-time key and mark it as used
	var otkID uuid.UUID
	err = b.db.QueryRow(`
		UPDATE one_time_keys
		SET used = true, used_at = CURRENT_TIMESTAMP
		WHERE id = (
			SELECT id FROM one_time_keys
			WHERE user_id = $1 AND used = false
			ORDER BY created_at ASC
			LIMIT 1
		)
		RETURNING id, key_data
	`, userID).Scan(&otkID, &resp.OneTimeKey)

	// If no one-time keys available, that's ok (optional)
	if err == sql.ErrNoRows {
		resp.OneTimeKey = nil
	} else if err != nil {
		return nil, err
	}

	return &resp, nil
}

// StoreChatKey saves encrypted chat key
func (b *KeyBusiness) StoreChatKey(lookupHash string, encryptedKey, encryptedPeerID, nonce []byte) error {
	_, err := b.db.Exec(`
		INSERT INTO chat_keys (lookup_hash, encrypted_key, encrypted_peer_id, nonce)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (lookup_hash) DO UPDATE SET
			encrypted_key = $2,
			encrypted_peer_id = $3,
			nonce = $4,
			created_at = CURRENT_TIMESTAMP
	`, lookupHash, encryptedKey, encryptedPeerID, nonce)
	return err
}

// GetChatKey retrieves encrypted chat key
func (b *KeyBusiness) GetChatKey(lookupHash string) (*models.ChatKey, error) {
	var chatKey models.ChatKey
	chatKey.LookupHash = lookupHash

	err := b.db.QueryRow(`
		SELECT encrypted_key, encrypted_peer_id, nonce, created_at
		FROM chat_keys
		WHERE lookup_hash = $1
	`, lookupHash).Scan(&chatKey.EncryptedKey, &chatKey.EncryptedPeerID, &chatKey.Nonce, &chatKey.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &chatKey, nil
}

// GetUserChats returns all chat lookup hashes for a user
func (b *KeyBusiness) GetUserChats(userID uuid.UUID) ([]string, error) {
	rows, err := b.db.Query(`
		SELECT lookup_hash FROM chat_keys
		WHERE created_at > $1
		ORDER BY created_at DESC
	`, time.Now().Add(-90*24*time.Hour)) // Last 90 days
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			continue
		}
		hashes = append(hashes, hash)
	}

	return hashes, nil
}
