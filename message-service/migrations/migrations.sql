-- Messages table (stores encrypted messages)
CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_id VARCHAR(255) NOT NULL,           -- Chat identifier (deterministic from user IDs)
    sender_id UUID NOT NULL,                 -- User who sent the message
    encrypted_content BYTEA NOT NULL,        -- AES-GCM encrypted message content
    nonce BYTEA NOT NULL,                    -- GCM nonce for decryption
    message_type VARCHAR(50) DEFAULT 'text', -- text, image, file, voice, etc.
    reply_to_id UUID,                        -- Reference to replied message
    read_at TIMESTAMP,                       -- When message was read
    edited_at TIMESTAMP,                     -- When message was last edited
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (reply_to_id) REFERENCES messages(id) ON DELETE SET NULL
);

-- Indexes for performance
CREATE INDEX idx_messages_chat_created ON messages(chat_id, created_at DESC);
CREATE INDEX idx_messages_sender ON messages(sender_id);
CREATE INDEX idx_messages_chat_unread ON messages(chat_id, read_at) WHERE read_at IS NULL;

-- Attachments table (for files, images, etc.)
CREATE TABLE attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    encrypted_url BYTEA NOT NULL,            -- Encrypted storage URL
    encrypted_name BYTEA NOT NULL,           -- Encrypted original filename
    encrypted_mime BYTEA NOT NULL,           -- Encrypted MIME type
    size BIGINT NOT NULL,                    -- File size in bytes
    thumbnail_url TEXT,                      -- Optional thumbnail (if image/video)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_attachments_message ON attachments(message_id);

-- Chat participants (for group chats and permissions)
CREATE TABLE chat_participants (
    chat_id VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_read_at TIMESTAMP,                  -- Last time user read messages
    is_admin BOOLEAN DEFAULT false,
    is_muted BOOLEAN DEFAULT false,
    
    PRIMARY KEY (chat_id, user_id)
);

CREATE INDEX idx_chat_participants_user ON chat_participants(user_id);

-- Deleted messages tracking (for soft deletes)
CREATE TABLE deleted_messages (
    message_id UUID NOT NULL,
    user_id UUID NOT NULL,                   -- Who deleted it (for "delete for me")
    deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (message_id, user_id)
);

CREATE INDEX idx_deleted_messages_user ON deleted_messages(user_id);

-- Cleanup old messages (optional, uncomment if needed)
-- DELETE FROM messages WHERE created_at < NOW() - INTERVAL '1 year';
