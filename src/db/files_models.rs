use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Physical file stored on disk
/// Multiple logical files can point to the same physical file (deduplication)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PhysicalFile {
    pub blake3_hash: String,
    pub file_size: i64,
    pub storage_path: String,
    pub ref_count: i64,
    pub created_at: String,
}

/// Logical file metadata (what users see)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FileMetadata {
    pub id: String,
    pub filename: String,
    pub file_type: String,
    pub blake3_hash: String,
    pub uploaded_by: String,
    pub uploaded_at: String,
}

/// File with size information (for API responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWithSize {
    pub id: String,
    pub filename: String,
    pub file_type: String,
    pub blake3_hash: String,
    pub uploaded_by: String,
    pub uploaded_at: String,
    pub file_size: i64,
}

// ============================================================================
// Third-Party Upload Support
// ============================================================================

/// File origin type - where the file came from
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OriginType {
    /// Uploaded by admin via web UI
    Internal,
    /// Uploaded by external server via PQC API
    ThirdParty,
}

impl OriginType {
    pub fn as_str(&self) -> &'static str {
        match self {
            OriginType::Internal => "internal",
            OriginType::ThirdParty => "third_party",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "internal" => Some(OriginType::Internal),
            "third_party" => Some(OriginType::ThirdParty),
            _ => None,
        }
    }
}

/// File upload status (Zero Trust quarantine workflow)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UploadStatus {
    /// Awaiting admin approval (third-party uploads)
    Quarantine,
    /// Cleared for user access
    Approved,
    /// Admin rejected the file
    Rejected,
}

impl UploadStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            UploadStatus::Quarantine => "quarantine",
            UploadStatus::Approved => "approved",
            UploadStatus::Rejected => "rejected",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "quarantine" => Some(UploadStatus::Quarantine),
            "approved" => Some(UploadStatus::Approved),
            "rejected" => Some(UploadStatus::Rejected),
            _ => None,
        }
    }
}

/// Extended file metadata with origin and status (for third-party files)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWithStatus {
    pub id: String,
    pub filename: String,
    pub file_type: String,
    pub blake3_hash: String,
    pub uploaded_by: String,
    pub uploaded_at: String,
    pub file_size: i64,
    pub origin_type: String,
    pub upload_status: String,
    pub sender_id: Option<String>,
}

/// Authorized third-party sender
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ThirdPartySender {
    pub id: String,
    pub name: String,
    pub ed25519_public_key: String,
    pub is_active: bool,
    pub created_at: String,
    pub last_upload_at: Option<String>,
}

/// File permission record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FilePermission {
    pub file_id: String,
    pub account_id: String,
    pub granted_at: String,
    pub granted_by: String,
}

/// File with its permissions (for admin view)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWithPermissions {
    #[serde(flatten)]
    pub file: FileWithSize,
    pub permissions: Vec<String>, // List of account IDs
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FileAuditLog {
    pub id: i64,
    pub file_id: String,
    pub filename: String,
    pub blake3_hash: String,
    pub action: String,
    pub performed_by: String,
    pub target_account_id: Option<String>,
    pub performed_at: String,
    pub details: Option<String>,
}

/// Actions for audit logging
#[derive(Debug, Clone, Copy)]
pub enum AuditAction {
    Upload,
    Delete,
    PermissionGrant,
    PermissionRevoke,
    Download,
    IntegrityFailure,
    /// Third-party upload received
    ThirdPartyUpload,
    /// Quarantined file approved by admin
    QuarantineApprove,
    /// Quarantined file rejected by admin
    QuarantineReject,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::Upload => "UPLOAD",
            AuditAction::Delete => "DELETE",
            AuditAction::PermissionGrant => "PERMISSION_GRANT",
            AuditAction::PermissionRevoke => "PERMISSION_REVOKE",
            AuditAction::Download => "DOWNLOAD",
            AuditAction::IntegrityFailure => "INTEGRITY_FAILURE",
            AuditAction::ThirdPartyUpload => "THIRD_PARTY_UPLOAD",
            AuditAction::QuarantineApprove => "QUARANTINE_APPROVE",
            AuditAction::QuarantineReject => "QUARANTINE_REJECT",
        }
    }
}
