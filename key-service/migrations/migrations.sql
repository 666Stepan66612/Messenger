-- User public keys (openly accessible)
CREATE TABLE user_keys (
    user_id UUID PRIMARY KEY,
    identity_key BYTEA NOT NULL,        -- Ed25519 public key (long-term identity)
    signed_prekey BYTEA NOT NULL,       -- X25519 public key (medium-term)
    prekey_signature BYTEA NOT NULL,    -- Signature of prekey by identity key
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- One-time prekeys (ephemeral keys for perfect forward secrecy)
CREATE TABLE one_time_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES user_keys(user_id) ON DELETE CASCADE,
    key_data BYTEA NOT NULL,            -- X25519 public key
    used BOOLEAN DEFAULT false,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_one_time_keys_user ON one_time_keys(user_id, used);
CREATE INDEX idx_one_time_keys_created ON one_time_keys(created_at);

-- Chat keys (encrypted symmetric keys for conversations)
CREATE TABLE chat_keys (
    lookup_hash VARCHAR(64) PRIMARY KEY,  -- HMAC-SHA256(userID + chatID + serverSalt)
    encrypted_key BYTEA NOT NULL,         -- AES-256 key encrypted with user's password-derived key
    encrypted_peer_id BYTEA NOT NULL,     -- Peer user ID encrypted (for privacy)
    nonce BYTEA NOT NULL,                 -- GCM nonce for encryption
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_chat_keys_created ON chat_keys(created_at);

-- Cleanup old one-time keys (optional, for maintenance)
-- DELETE FROM one_time_keys WHERE used = true AND used_at < NOW() - INTERVAL '30 days';
