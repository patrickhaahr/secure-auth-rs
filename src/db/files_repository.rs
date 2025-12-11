use super::files_models::{AuditAction, FileMetadata, FilePermission, FileWithSize, PhysicalFile};
use sqlx::{Pool, Sqlite};

// ============================================================================
// Physical Files
// ============================================================================

/// Insert a new physical file record
pub async fn insert_physical_file(
    pool: &Pool<Sqlite>,
    blake3_hash: &str,
    file_size: i64,
    storage_path: &str,
) -> Result<PhysicalFile, sqlx::Error> {
    let result = sqlx::query_as::<_, PhysicalFile>(
        r#"
        INSERT INTO physical_files (blake3_hash, file_size, storage_path, ref_count, created_at)
        VALUES (?, ? , ?, 1, datetime('now'))
        RETURNING blake3_hash, file_size, storage_path, ref_count, created_at
        "#,
    )
    .bind(blake3_hash)
    .bind(file_size)
    .bind(storage_path)
    .fetch_one(pool)
    .await;

    match &result {
        Ok(pf) => {
            tracing::info!(hash = %pf.blake3_hash, size = %pf.file_size, "Physical file created")
        }
        Err(e) => tracing::error!(error = %e, "Failed to create physical file"),
    }

    result
}

/// Get physical file by hash
pub async fn get_physical_file(
    pool: &Pool<Sqlite>,
    blake3_hash: &str,
) -> Result<Option<PhysicalFile>, sqlx::Error> {
    sqlx::query_as::<_, PhysicalFile>(
        "SELECT blake3_hash, file_size, storage_path, ref_count, created_at FROM physical_files WHERE blake3_hash = ?",
    )
    .bind(blake3_hash)
    .fetch_optional(pool)
    .await
}

/// Increment reference count (when another logical file uses same hash)
pub async fn increment_ref_count(
    pool: &Pool<Sqlite>,
    blake3_hash: &str,
) -> Result<u64, sqlx::Error> {
    let result =
        sqlx::query("UPDATE physical_files SET ref_count = ref_count + 1 WHERE blake3_hash = ?")
            .bind(blake3_hash)
            .execute(pool)
            .await?;

    tracing::debug!(hash = %blake3_hash, "Incremented ref_count");
    Ok(result.rows_affected())
}

/// Decrement reference count and return count
pub async fn decrement_ref_count(
    pool: &Pool<Sqlite>,
    blake3_hash: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query("UPDATE physical_files SET ref_count = ref_count - 1 WHERE blake3_hash = ?")
        .bind(blake3_hash)
        .execute(pool)
        .await?;

    let result: (i64,) =
        sqlx::query_as("SELECT ref_count FROM physical_files WHERE blake3_hash = ?")
            .bind(blake3_hash)
            .fetch_one(pool)
            .await?;

    tracing::debug!(hash = %blake3_hash, new_count = %result.0, "Decremented ref_count");
    Ok(result.0)
}

/// Delete physical file record (only when ref_count reaches 0)
pub async fn delete_physical_file(
    pool: &Pool<Sqlite>,
    blake3_hash: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM physical_files WHERE blake3_hash = ? AND ref_count = 0")
        .bind(blake3_hash)
        .execute(pool)
        .await?;

    if result.rows_affected() > 0 {
        tracing::info!(hash = %blake3_hash, "Physical file record deleted");
    }
    Ok(result.rows_affected())
}

// ============================================================================
// Logical Files
// ============================================================================

/// Insert a new logical file record
pub async fn insert_file(
    pool: &Pool<Sqlite>,
    id: &str,
    filename: &str,
    file_type: &str,
    blake3_hash: &str,
    uploaded_by: &str,
) -> Result<FileMetadata, sqlx::Error> {
    let result = sqlx::query_as::<_, FileMetadata>(
        r#"
                INSERT INTO files (id, filename, file_type, blake3_hash, uploaded_by, uploaded_at)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
                RETURNING id, filename, file_type, blake3_hash, uploaded_by, uploaded_at
                "#,
    )
    .bind(id)
    .bind(filename)
    .bind(file_type)
    .bind(blake3_hash)
    .bind(uploaded_by)
    .fetch_one(pool)
    .await;

    match &result {
        Ok(f) => tracing::info!(file_id = %f.id, filename = %f.filename, "File metadata created"),
        Err(e) => tracing::error!(error = %e, "Failed to create file metadata"),
    }

    result
}

/// Get file by ID
pub async fn get_file_by_id(
    pool: &Pool<Sqlite>,
    file_id: &str,
) -> Result<Option<FileMetadata>, sqlx::Error> {
    sqlx::query_as::<_, FileMetadata>(
        "SELECT id, filename, file_type, blake3_hash, uploaded_by, uploaded_at FROM files WHERE id = ?",
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await
}

/// Get file with size by ID (joins with physical_files)
pub async fn get_file_with_size(
    pool: &Pool<Sqlite>,
    file_id: &str,
) -> Result<Option<FileWithSize>, sqlx::Error> {
    let result: Option<(String, String, String, String, String, String, i64)> = sqlx::query_as(
        r#"
        SELECT f.id, f.filename, f.file_type, f.blake3_hash, f.uploaded_by, f.uploaded_at, pf.file_size
        FROM files f
        JOIN physical_files pf ON f.blake3_hash = pf.blake3_hash
        WHERE f.id = ?
        "#,
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await?;

    Ok(result.map(
        |(id, filename, file_type, blake3_hash, uploaded_by, uploaded_at, file_size)| {
            FileWithSize {
                id,
                filename,
                file_type,
                blake3_hash,
                uploaded_by,
                uploaded_at,
                file_size,
            }
        },
    ))
}

/// Get all files uploaded by a specific admin
pub async fn get_files_by_uploader(
    pool: &Pool<Sqlite>,
    uploader_id: &str,
) -> Result<Vec<FileWithSize>, sqlx::Error> {
    let results: Vec<(String, String, String, String, String, String, i64)> = sqlx::query_as(
        r#"
        SELECT f.id, f.filename, f.file_type, f.blake3_hash, f.uploaded_by, f.uploaded_at, pf.file_size
        FROM files f
        JOIN physical_files pf ON f.blake3_hash = pf.blake3_hash
        WHERE f.uploaded_by = ?
        ORDER BY f.uploaded_at DESC
        "#,
    )
    .bind(uploader_id)
    .fetch_all(pool)
    .await?;

    Ok(results
        .into_iter()
        .map(
            |(id, filename, file_type, blake3_hash, uploaded_by, uploaded_at, file_size)| {
                FileWithSize {
                    id,
                    filename,
                    file_type,
                    blake3_hash,
                    uploaded_by,
                    uploaded_at,
                    file_size,
                }
            },
        )
        .collect())
}

/// Delete file by ID
pub async fn delete_file(pool: &Pool<Sqlite>, file_id: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM files WHERE id = ?")
        .bind(file_id)
        .execute(pool)
        .await?;

    if result.rows_affected() > 0 {
        tracing::info!(file_id = %file_id, "File metadata deleted");
    }
    Ok(result.rows_affected())
}

// ============================================================================
// Permissions
// ============================================================================

/// Grant file access to an account
pub async fn grant_permission(
    pool: &Pool<Sqlite>,
    file_id: &str,
    account_id: &str,
    granted_by: &str,
) -> Result<FilePermission, sqlx::Error> {
    let result = sqlx::query_as::<_, FilePermission>(
        r#"
                INSERT INTO file_permissions (file_id, account_id, granted_by, granted_at)
                VALUES (?, ?, ?, datetime('now'))
                ON CONFLICT(file_id, account_id) DO NOTHING
                RETURNING file_id, account_id, granted_at, granted_by
                "#,
    )
    .bind(file_id)
    .bind(account_id)
    .bind(granted_by)
    .fetch_one(pool)
    .await;

    match &result {
        Ok(p) => {
            tracing::info!(file_id = %p.file_id, account_id = %p.account_id, "Permission granted")
        }
        Err(e) => tracing::error!(error = %e, "Failed to grant permission"),
    }

    result
}

/// Revoke file access from an account
pub async fn revoke_permission(
    pool: &Pool<Sqlite>,
    file_id: &str,
    account_id: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM file_permissions WHERE file_id = ? AND account_id = ?")
        .bind(file_id)
        .bind(account_id)
        .execute(pool)
        .await?;

    if result.rows_affected() > 0 {
        tracing::info!(file_id = %file_id, account_id = %account_id, "Permission revoked");
    }
    Ok(result.rows_affected())
}

/// Get all account IDs with permission for a file
pub async fn get_file_permissions(
    pool: &Pool<Sqlite>,
    file_id: &str,
) -> Result<Vec<String>, sqlx::Error> {
    let results: Vec<(String,)> =
        sqlx::query_as("SELECT account_id FROM file_permissions WHERE file_id = ?")
            .bind(file_id)
            .fetch_all(pool)
            .await?;

    Ok(results.into_iter().map(|(id,)| id).collect())
}

/// Get all files accessible to an account
pub async fn get_files_for_account(
    pool: &Pool<Sqlite>,
    account_id: &str,
) -> Result<Vec<FileWithSize>, sqlx::Error> {
    let results: Vec<(String, String, String, String, String, String, i64)> = sqlx::query_as(
        r#"
        SELECT f.id, f.filename, f.file_type, f.blake3_hash, f.uploaded_by, f.uploaded_at, pf.file_size
        FROM files f
        JOIN physical_files pf ON f.blake3_hash = pf.blake3_hash
        JOIN file_permissions fp ON f.id = fp.file_id
        WHERE fp.account_id = ?
        ORDER BY f.uploaded_at DESC
        "#,
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;

    Ok(results
        .into_iter()
        .map(
            |(id, filename, file_type, blake3_hash, uploaded_by, uploaded_at, file_size)| {
                FileWithSize {
                    id,
                    filename,
                    file_type,
                    blake3_hash,
                    uploaded_by,
                    uploaded_at,
                    file_size,
                }
            },
        )
        .collect())
}

/// Check if account has access to a file
pub async fn verify_file_access(
    pool: &Pool<Sqlite>,
    file_id: &str,
    account_id: &str,
) -> Result<bool, sqlx::Error> {
    let result: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM file_permissions WHERE file_id = ? AND account_id = ?",
    )
    .bind(file_id)
    .bind(account_id)
    .fetch_one(pool)
    .await?;

    Ok(result.0 > 0)
}

/// Check if account is the uploader of a file
pub async fn is_file_uploader(
    pool: &Pool<Sqlite>,
    file_id: &str,
    account_id: &str,
) -> Result<bool, sqlx::Error> {
    let result: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM files WHERE id = ? AND uploaded_by = ?")
            .bind(file_id)
            .bind(account_id)
            .fetch_one(pool)
            .await?;

    Ok(result.0 > 0)
}

// ============================================================================
// Audit Logging
// ============================================================================

/// Log a file operation
pub async fn log_audit(
    pool: &Pool<Sqlite>,
    file_id: &str,
    filename: &str,
    blake3_hash: &str,
    action: AuditAction,
    performed_by: &str,
    target_account_id: Option<&str>,
    details: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO file_audit_log (file_id, filename, blake3_hash, action, performed_by, target_account_id, details, performed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        "#,
    )
    .bind(file_id)
    .bind(filename)
    .bind(blake3_hash)
    .bind(action.as_str())
    .bind(performed_by)
    .bind(target_account_id)
    .bind(details)
    .execute(pool)
    .await?;

    tracing::debug!(
        file_id = %file_id,
        action = %action.as_str(),
        performed_by = %performed_by,
        "Audit log entry created"
    );

    Ok(())
}
