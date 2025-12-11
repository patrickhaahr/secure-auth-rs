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
        }
    }
}
