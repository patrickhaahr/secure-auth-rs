use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Account model - Core user account
/// Maps to: accounts table
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Account {
    /// UUID v4 (primary key)
    pub id: String,
    /// ISO 8601 timestamp
    pub created_at: String,
    /// Whether account has completed full verification (TOTP + CPR)
    pub is_verified: bool,
}

/// CPR data model - Hashed CPR information
/// Maps to: cpr_data table
/// Note: Debug and Clone deliberately omitted to prevent PII leakage
#[derive(Serialize, Deserialize, FromRow)]
pub struct CprData {
    /// Foreign key to accounts.id
    pub account_id: String,
    /// Argon2id hash for uniqueness check and secure verification
    pub cpr_hash: String,
    /// ISO 8601 timestamp
    pub verified_at: String,
}

impl std::fmt::Debug for CprData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CprData")
            .field("account_id", &self.account_id)
            .field("cpr_hash", &"[REDACTED]")
            .field("verified_at", &self.verified_at)
            .finish()
    }
}

/// Passkey model - WebAuthn credentials
/// Maps to: passkeys table
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Passkey {
    /// UUID v4 (primary key)
    pub id: String,
    /// Foreign key to accounts.id
    pub account_id: String,
    /// WebAuthn raw credential ID (binary)
    pub credential_id: Vec<u8>,
    /// COSE public key bytes
    pub public_key: Vec<u8>,
    /// Signature counter for replay attack prevention (WebAuthn spec: u32)
    pub sign_count: u32,
    /// 16-byte authenticator AAGUID
    pub aaguid: Vec<u8>,
    /// Attestation type: 'none', 'indirect', 'direct'
    pub attestation_type: String,
    /// User-defined nickname for the passkey
    pub nickname: Option<String>,
    /// ISO 8601 timestamp
    pub created_at: String,
    /// ISO 8601 timestamp (nullable)
    pub last_used_at: Option<String>,
}

/// TOTP secret model - Time-based OTP configuration
/// Maps to: totp_secrets table
/// Note: Debug and Clone deliberately omitted to prevent secret leakage
#[derive(Serialize, Deserialize, FromRow)]
pub struct TotpSecret {
    /// Foreign key to accounts.id (primary key)
    pub account_id: String,
    /// Encrypted base32 secret (32+ chars)
    pub secret_encrypted: Vec<u8>,
    /// Algorithm: 'SHA1' (only SHA1 for compatibility)
    pub algorithm: String,
    /// Number of digits: 6
    pub digits: i32,
    /// Time period in seconds: 30
    pub period: i32,
    /// Whether TOTP has been verified with a valid code
    pub is_verified: bool,
    /// ISO 8601 timestamp
    pub created_at: String,
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSecret")
            .field("account_id", &self.account_id)
            .field("secret_encrypted", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("is_verified", &self.is_verified)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Account role model - Admin flags
/// Maps to: account_roles table
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AccountRole {
    /// Foreign key to accounts.id (primary key)
    pub account_id: String,
    /// Admin flag (set via DB only, no HTTP endpoint)
    pub is_admin: bool,
    /// ISO 8601 timestamp
    pub assigned_at: String,
}
