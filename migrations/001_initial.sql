-- Initial migration for auth microservice
-- Create tables for users, device_sessions, verification_codes, account_activity, and rate_limits

-- Users table
CREATE TABLE users (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified INTEGER DEFAULT 0, -- SQLite boolean (0/1)
    first_name TEXT,
    last_name TEXT,
    avatar_url TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Device sessions with refresh tokens
CREATE TABLE device_sessions (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token TEXT UNIQUE NOT NULL,
    device_fingerprint TEXT NOT NULL, -- Client-generated fingerprint
    user_agent TEXT,
    ip_address TEXT,
    trusted INTEGER DEFAULT 0, -- SQLite boolean
    expires_at TEXT NOT NULL,
    last_used TEXT DEFAULT (datetime('now')),
    created_at TEXT DEFAULT (datetime('now'))
);

-- Temporary verification codes (email verification, password reset)
CREATE TABLE verification_codes (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    email TEXT, -- For verification before user creation
    code TEXT NOT NULL,
    code_type TEXT NOT NULL, -- 'email_verification', 'password_reset'
    expires_at TEXT NOT NULL,
    used INTEGER DEFAULT 0, -- SQLite boolean
    attempts INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Account activity audit trail
CREATE TABLE account_activity (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    activity_type TEXT NOT NULL, -- 'login', 'logout', 'register', 'password_change'
    details TEXT, -- Simple JSON
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Rate limiting (fallback if Redis unavailable)
CREATE TABLE rate_limits (
    id TEXT PRIMARY KEY, -- "login:email" or "register:ip"
    attempts INTEGER DEFAULT 1,
    window_start TEXT,
    blocked_until TEXT
);

-- Performance indexes
CREATE INDEX idx_device_sessions_user_id ON device_sessions(user_id);
CREATE INDEX idx_device_sessions_refresh_token ON device_sessions(refresh_token);
CREATE INDEX idx_verification_codes_lookup ON verification_codes(email, code_type, used, expires_at);
CREATE INDEX idx_account_activity_user_id ON account_activity(user_id, created_at);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_rate_limits_id ON rate_limits(id);

-- Trigger for automatic updated_at timestamp
CREATE TRIGGER update_users_timestamp 
    AFTER UPDATE ON users
    FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = datetime('now') WHERE id = NEW.id;
END;