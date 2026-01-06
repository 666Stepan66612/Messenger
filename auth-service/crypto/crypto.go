package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// generating an aes256 swith from password and salt
func DeriveKey(password string, salt []byte) []byte {
	hash := sha512.New()
	hash.Write([]byte(password))
	hash.Write(salt)
	return hash.Sum(nil)[:32] //aes256 requires 32 bytes
}

// ecrypt data aes-gcm
func EncryptAESGCM(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decrypt data aes-gcm
func DecryptAESGCM(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("cipher too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// generating hash of refresh token
func HashToken(token []byte) []byte {
	hash := sha256.Sum256(token)
	return hash[:]
}

// bcrypt password hashing (for backward compatibility)
func HashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

// HashPasswordArgon2 creates Argon2id hash (recommended for new passwords)
func HashPasswordArgon2(password string, salt []byte) []byte {
	// Argon2id parameters (OWASP recommended)
	// time=3, memory=64MB, threads=4, keyLen=32
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
}

// CheckPasswordHashConstantTime uses constant-time comparison to prevent timing attacks
func CheckPasswordHashConstantTime(password string, hash []byte) bool {
	computedHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false
	}

	// Use constant-time comparison
	return subtle.ConstantTimeCompare(computedHash, hash) == 1
}

// check password (original bcrypt method)
func CheckPasswordHash(password string, hash []byte) bool {
	err := bcrypt.CompareHashAndPassword(hash, []byte(password))
	// Use constant-time to prevent timing attacks on error
	result := err == nil
	subtle.ConstantTimeSelect(0, 0, 1) // Add timing noise
	return result
}

// generate random bytes
func RandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}

	return bytes, nil
}
