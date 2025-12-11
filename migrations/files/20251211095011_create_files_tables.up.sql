PRAGMA foreign_keys = ON;

-- Physical files (actual data on disk)
-- If two admins upload the same PDF, we store it once here
-- Reference counting ensures we don't delete files still in use 
CREATE TABLE physical_files (
    blake3_hash TEXT PRIMARY KEY,            -- 64-char hex hash (also storage filename)
    file_size INTEGER NOT NULL,              -- Bytes (max 1GB = 1073741824)
    storage_path TEXT NOT NULL,              -- "files/content/abc123hash.bin"
    ref_count INTEGER NOT NULL DEFAULT 1,    -- How many logical files point here
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK(file_size > 0 AND file_size <= 1073741824),
    CHECK(ref_count >= 0)
);

-- Logical files (What users/admins see in the GUI)
-- Multiple logical files can point to the same physical file
CREATE TABLE files (
    id TEXT PRIMARY KEY,                     -- UUID v7
    filename TEXT NOT NULL,                  -- Original user-provided filename
    file_type TEXT NOT NULL,                 -- MIME type
    blake3_hash TEXT NOT NULL,               -- Link to physical file
    uploaded_by TEXT NOT NULL,               -- Account ID (16-char alphanumeric)
    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (blake3_hash) REFERENCES physical_files(blake3_hash) ON DELETE RESTRICT
);

-- File permissions (many-to-many: files <-> accounts)
CREATE TABLE file_permissions (
    file_id TEXT NOT NULL,
    account_id TEXT NOT NULL,                -- 16-char alphanumeric
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_by TEXT NOT NULL,                -- Admin who granted access

    PRIMARY KEY (file_id, account_id),
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

-- Audit log for file operations
CREATE TABLE file_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    blake3_hash TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN (
        'UPLOAD', 
        'DELETE', 
        'PHYSICAL_DELETE', 
        'PERMISSION_GRANT', 
        'PERMISSION_REVOKE', 
        'DOWNLOAD', 
        'INTEGRITY_FAILURE'
    )),
    performed_by TEXT NOT NULL,              -- AccountId who performed action
    target_account_id TEXT,                  -- For permission actions 
    performed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details TEXT                             -- JSON for additional content
);

-- Indexes for performance 
CREATE INDEX idx_files_uploaded_by ON files(uploaded_by);
CREATE INDEX idx_files_uploaded_at ON files(uploaded_at);
CREATE INDEX idx_files_blake3_hash ON files(blake3_hash);

CREATE INDEX idx_file_permissions_account ON file_permissions(account_id);
CREATE INDEX idx_file_permissions_file ON file_permissions(file_id);
CREATE INDEX idx_file_permissions_granted_by ON file_permissions(granted_by);

CREATE INDEX idx_audit_performed_by ON file_audit_log(performed_by);
CREATE INDEX idx_audit_performed_at ON file_audit_log(performed_at);
CREATE INDEX idx_audit_action ON file_audit_log(action);

