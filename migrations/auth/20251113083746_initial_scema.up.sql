-- Enable foreign keys
PRAGMA foreign_keys = ON;
-- Core account
CREATE TABLE accounts (
    id TEXT PRIMARY KEY COLLATE NOCASE,
    is_verified BOOLEAN NOT NULL DEFAULT 0 CHECK(is_verified IN (0, 1)),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- CPR data
CREATE TABLE cpr_data (
    account_id TEXT PRIMARY KEY,
    cpr_hash TEXT NOT NULL UNIQUE,
    verified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
-- Passkeys
CREATE TABLE passkeys (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    credential_id BLOB UNIQUE NOT NULL,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0 CHECK(sign_count >= 0),
    aaguid BLOB NOT NULL,
    attestation_type TEXT NOT NULL CHECK(attestation_type IN ('none', 'indirect', 'direct')),
    nickname TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
-- TOTP secrets
CREATE TABLE totp_secrets (
    account_id TEXT PRIMARY KEY,
    secret_encrypted BLOB NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'SHA512' CHECK(algorithm IN ('SHA512')),
    digits INTEGER NOT NULL DEFAULT 6 CHECK(digits = 6),
    period INTEGER NOT NULL DEFAULT 30 CHECK(period = 30),
    is_verified BOOLEAN NOT NULL DEFAULT 0 CHECK(is_verified IN (0, 1)),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
-- Admin roles
CREATE TABLE account_roles (
    account_id TEXT PRIMARY KEY,
    is_admin BOOLEAN NOT NULL DEFAULT 0 CHECK(is_admin IN (0, 1)),
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
-- Indexes
CREATE INDEX idx_passkeys_account_id ON passkeys(account_id);
CREATE INDEX idx_passkeys_credential_id ON passkeys(credential_id);
CREATE UNIQUE INDEX idx_cpr_hash ON cpr_data(cpr_hash);
-- Passkey limit trigger
CREATE TRIGGER enforce_passkey_limit 
BEFORE INSERT ON passkeys
FOR EACH ROW
BEGIN
    SELECT CASE 
        WHEN (SELECT COUNT(*) FROM passkeys WHERE account_id = NEW.account_id) >= 5
        THEN RAISE(ABORT, 'Maximum 5 passkeys per account exceeded')
    END;
END;
