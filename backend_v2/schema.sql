-- VaultX Database Schema for PostgreSQL (Supabase) - Updated with Extension Support

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Encryption keys table (stores user-specific encryption keys)
CREATE TABLE IF NOT EXISTS encryption_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id)
);

-- Credentials table (updated with website fields)
CREATE TABLE IF NOT EXISTS credentials (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    website_url VARCHAR(500) NOT NULL,
    website_name VARCHAR(255),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    username VARCHAR(255) NOT NULL,
    encrypted_password TEXT NOT NULL,
    encryption_key_id INTEGER NOT NULL REFERENCES encryption_keys(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Excluded sites table (for sites user doesn't want to save passwords for)
CREATE TABLE IF NOT EXISTS excluded_sites (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain VARCHAR(500) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, domain)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_credentials_website_url ON credentials(website_url);
CREATE INDEX IF NOT EXISTS idx_encryption_keys_user_id ON encryption_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_excluded_sites_user_id ON excluded_sites(user_id);
CREATE INDEX IF NOT EXISTS idx_excluded_sites_domain ON excluded_sites(domain);

-- Insert default test users (passwords are hashed with bcrypt)
-- Default users: admin/admin123 and user1/pass123
INSERT INTO users (username, password_hash) VALUES 
    ('admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5eo3kYGxE7TXK'),
    ('user1', '$2b$12$rMeGo8Z5hG7mXKXvL3L3auVYJqQ0lH3xE8vZPqXqJqN8KqGxE7TXK')
ON CONFLICT (username) DO NOTHING;

-- Migration script for existing installations
-- Run this if you're upgrading from the previous version:
/*
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS website_url VARCHAR(500);
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS website_name VARCHAR(255);
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE credentials ALTER COLUMN first_name DROP NOT NULL;
ALTER TABLE credentials ALTER COLUMN last_name DROP NOT NULL;

-- Update existing credentials to have a default website URL
UPDATE credentials SET website_url = 'manual-entry' WHERE website_url IS NULL;
UPDATE credentials SET website_name = first_name || ' ' || last_name WHERE website_name IS NULL;

-- Now make website_url NOT NULL
ALTER TABLE credentials ALTER COLUMN website_url SET NOT NULL;
*/
