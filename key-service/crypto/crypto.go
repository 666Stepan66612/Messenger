package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// GenerateLookupHash creates HMAC-SHA256 for privacy-preserving lookup
func GenerateLookupHash(userID, chatID, serverSalt string) string {
	h := hmac.New(sha256.New, []byte(serverSalt))
	h.Write([]byte(userID + chatID))
	return hex.EncodeToString(h.Sum(nil))
}

// GenerateChatID creates deterministic chat ID from two user IDs
func GenerateChatID(userID1, userID2 string) string {
	// Alphabetical order for consistency
	if userID1 < userID2 {
		return userID1 + ":" + userID2
	}
	return userID2 + ":" + userID1
}
