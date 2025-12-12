-- Down migration: Remove third-party file upload support

-- Drop indexes first
DROP INDEX IF EXISTS idx_files_origin_type;
DROP INDEX IF EXISTS idx_files_upload_status;
DROP INDEX IF EXISTS idx_files_sender_id;
DROP INDEX IF EXISTS idx_third_party_senders_active;

-- Drop third_party_senders table
DROP TABLE IF EXISTS third_party_senders;

-- SQLite doesn't support DROP COLUMN in older versions
-- We need to recreate the files table without the new columns
-- This is a destructive migration - backup data first!

-- Create temporary table with original schema
CREATE TABLE files_backup AS SELECT 
    id, filename, file_type, blake3_hash, uploaded_by, uploaded_at 
FROM files;

-- Drop original table
DROP TABLE files;

-- Recreate original table
CREATE TABLE files (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    file_type TEXT NOT NULL,
    blake3_hash TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (blake3_hash) REFERENCES physical_files(blake3_hash) ON DELETE RESTRICT
);

-- Restore data
INSERT INTO files (id, filename, file_type, blake3_hash, uploaded_by, uploaded_at)
SELECT id, filename, file_type, blake3_hash, uploaded_by, uploaded_at FROM files_backup;

-- Drop backup
DROP TABLE files_backup;

-- Recreate original indexes
CREATE INDEX idx_files_uploaded_by ON files(uploaded_by);
CREATE INDEX idx_files_uploaded_at ON files(uploaded_at);
CREATE INDEX idx_files_blake3_hash ON files(blake3_hash);
