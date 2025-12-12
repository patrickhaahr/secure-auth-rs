-- Migration: Add third-party file upload support
-- This migration adds:
-- 1. origin_type and upload_status columns to files table
-- 2. third_party_senders table for authorized senders
-- 3. New audit action types

PRAGMA foreign_keys = ON;

-- ============================================================================
-- Extend files table with origin tracking and quarantine status
-- ============================================================================

-- Add origin_type column (default 'internal' for existing files)
ALTER TABLE files ADD COLUMN origin_type TEXT NOT NULL DEFAULT 'internal'
    CHECK(origin_type IN ('internal', 'third_party'));

-- Add upload_status column (default 'approved' for existing files)
ALTER TABLE files ADD COLUMN upload_status TEXT NOT NULL DEFAULT 'approved'
    CHECK(upload_status IN ('quarantine', 'approved', 'rejected'));

-- Add sender_id for third-party uploads (NULL for internal uploads)
ALTER TABLE files ADD COLUMN sender_id TEXT;

-- ============================================================================
-- Create third_party_senders table
-- ============================================================================

CREATE TABLE third_party_senders (
    id TEXT PRIMARY KEY,                              -- Unique sender ID (e.g., "server2")
    name TEXT NOT NULL,                               -- Human-readable name
    ed25519_public_key TEXT NOT NULL UNIQUE,          -- Hex-encoded Ed25519 public key (64 chars)
    is_active INTEGER NOT NULL DEFAULT 1,             -- 0 = disabled, 1 = active
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_upload_at TIMESTAMP,                         -- Track last activity
    
    CHECK(length(ed25519_public_key) = 64),           -- Ed25519 public key is 32 bytes = 64 hex chars
    CHECK(is_active IN (0, 1))
);

-- ============================================================================
-- Indexes for performance
-- ============================================================================

CREATE INDEX idx_files_origin_type ON files(origin_type);
CREATE INDEX idx_files_upload_status ON files(upload_status);
CREATE INDEX idx_files_sender_id ON files(sender_id);
CREATE INDEX idx_third_party_senders_active ON third_party_senders(is_active);
