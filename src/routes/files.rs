//! File upload/download routes
//!
//! Admin routes: upload, manage permissions, delete
//! User routes: list accessible files, download with verification

use crate::{
    AppState,
    crypto::file_integrity,
    db::{files_models::AuditAction, files_repository},
    middleware::auth::AuthenticatedUser,
};
use axum::{
    Json,
    body::Body,
    extract::{Multipart, Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

/// Maximum file size: 50MB
const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// Storage directory for files
const STORAGE_DIR: &str = "files/content";

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct FileResponse {
    pub id: String,
    pub filename: String,
    pub file_type: String,
    pub file_size: i64,
    pub blake3_hash: String,
    pub uploaded_by: String,
    pub uploaded_at: String,
}

#[derive(Debug, Serialize)]
pub struct FileWithPermissionsResponse {
    #[serde(flatten)]
    pub file: FileResponse,
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub file_id: String,
    pub filename: String,
    pub blake3_hash: String,
    pub file_size: i64,
    pub deduplicated: bool,
    pub permissions_granted: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PermissionRequest {
    pub account_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub status: String, // "verified" or "contaminated"
    pub blake3_hash: String,
    pub file_size: i64,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Ensure storage directory exists
async fn ensure_storage_dir() -> Result<(), std::io::Error> {
    fs::create_dir_all(STORAGE_DIR).await
}

// Get storage path for file hash
fn get_storage_path(blake3_hash: &str) -> PathBuf {
    PathBuf::from(STORAGE_DIR).join(format!("{}.bin", blake3_hash))
}

/// Sanitize filename to prevent path traversal
fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .filter(|c| {
            !matches!(
                c,
                '/' | '\\' | '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
            )
        })
        .take(255)
        .collect()
}

/// Streams multipart data to a temp file while computing the hash.
/// This prevents loading large files into RAM.
/// Returns: (TempFilePath, Blake3Hash, FileSize)
async fn process_upload_stream(
    mut field_stream: impl Stream<Item = Result<bytes::Bytes, axum::extract::multipart::MultipartError>>
    + Unpin,
) -> Result<(std::path::PathBuf, String, u64), (StatusCode, String)> {
    // 1. Create temp file
    let temp_file_id = uuid::Uuid::new_v4();
    let temp_path = std::path::Path::new("files/temp").join(temp_file_id.to_string());

    // Ensure temp dir exists
    if let Some(parent) = temp_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage error".to_string(),
            )
        })?;
    }

    let mut file = tokio::fs::File::create(&temp_path).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to create temp file");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage error".to_string(),
        )
    })?;

    // 2. Initialize Hasher
    let mut hasher = blake3::Hasher::new();
    let mut total_size: u64 = 0;

    // 3. Stream loop
    while let Some(chunk_result) = field_stream.next().await {
        let chunk = chunk_result.map_err(|e| {
            tracing::error!(error = %e, "Multipart stream error");
            (StatusCode::BAD_REQUEST, "Upload interrupted".to_string())
        })?;

        let len = chunk.len() as u64;
        total_size += len;

        if total_size > MAX_FILE_SIZE {
            // Cleanup and fail
            let _ = file.flush().await;
            drop(file);
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("File exceeds size limit of 50MB"),
            ));
        }

        // Update Hash state AND write to disk
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|e| {
            tracing::error!(error = %e, "Write error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage write error".to_string(),
            )
        })?;
    }

    // 4. Finalize
    file.flush()
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Flush error".to_string()))?;
    let hash = hasher.finalize().to_hex().to_string();

    Ok((temp_path, hash, total_size))
}

// ============================================================================
// Admin Handlers
// ============================================================================

/// POST /api/admin/files/upload
/// Upload a new file (admin only)
pub async fn upload_file(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, (StatusCode, String)> {
    // Make sure storage directories exist
    ensure_storage_dir().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage init error".to_string(),
        )
    })?;

    // Variables to hold form data
    let mut temp_file_path: Option<std::path::PathBuf> = None;
    let mut filename: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut blake3_hash: Option<String> = None;
    let mut file_size: u64 = 0;
    let mut account_ids: Vec<String> = Vec::new();

    // Parse multipart form
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid form".to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();

        match name.as_str() {
            "file" => {
                filename = field.file_name().map(|s| sanitize_filename(s));
                content_type = field.content_type().map(|s| s.to_string());

                // STREAMING UPLOAD (No large RAM buffer)
                let (path, hash, size) = process_upload_stream(field).await?;

                temp_file_path = Some(path);
                blake3_hash = Some(hash);
                file_size = size;
            }
            "account_ids" => {
                if let Ok(text) = field.text().await {
                    if let Ok(ids) = serde_json::from_str::<Vec<String>>(&text) {
                        account_ids = ids;
                    }
                }
            }
            _ => {} // Ignore other fields
        }
    }

    // Validation
    let filename = filename.ok_or((StatusCode::BAD_REQUEST, "No filename provided".to_string()))?;
    let hash = blake3_hash.ok_or((StatusCode::BAD_REQUEST, "File upload failed".to_string()))?;
    let temp_path = temp_file_path.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Temp file lost".to_string(),
    ))?;

    let file_type = content_type.unwrap_or_else(|| {
        mime_guess::from_path(&filename)
            .first_or_octet_stream()
            .to_string()
    });

    // ====================================================
    // DEDUPLICATION LOGIC
    // ====================================================

    // Check if physical file exists
    let existing = files_repository::get_physical_file(&state.files_db, &hash)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB Error".to_string()))?;

    let deduplicated = existing.is_some();
    let final_storage_path = get_storage_path(&hash);

    if deduplicated {
        // CASE A: File exists
        // 1. Delete our temp file (we don't need it)
        let _ = tokio::fs::remove_file(&temp_path).await;

        // 2. Increment Ref Count
        files_repository::increment_ref_count(&state.files_db, &hash)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB Error".to_string()))?;

        tracing::info!("File deduplicated: {}", hash);
    } else {
        // CASE B: New file
        // 1. Move temp file -> final location
        tokio::fs::rename(&temp_path, &final_storage_path)
            .await
            .map_err(|e| {
                tracing::error!("Failed to move to temp file: {}", e);
                // Fallback: Copy and Delete if rename fails
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Storage move error".to_string(),
                )
            })?;

        // 2. Insert physical record
        if let Err(_e) = files_repository::insert_physical_file(
            &state.files_db,
            &hash,
            file_size as i64,
            final_storage_path.to_string_lossy().as_ref(),
        )
        .await
        {
            // Cleanup if DB fails
            let _ = tokio::fs::remove_file(&final_storage_path).await;
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "DB Insert Error".to_string(),
            ));
        }
    }

    // ====================================================
    // LOGICAL FILE & PERMISSIONS
    // ====================================================

    let file_id = uuid::Uuid::now_v7().to_string();

    files_repository::insert_file(
        &state.files_db,
        &file_id,
        &filename,
        &file_type,
        &hash,
        &user.account_id,
    )
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB Error".to_string()))?;

    // Grant Permissions
    let mut granted_permissions = Vec::new();
    for account_id in &account_ids {
        if files_repository::grant_permission(
            &state.files_db,
            &file_id,
            account_id,
            &user.account_id,
        )
        .await
        .is_ok()
        {
            granted_permissions.push(account_id.clone());
        }
    }

    // Audit logs
    let _ = files_repository::log_audit(
        &state.files_db,
        &file_id,
        &filename,
        &hash,
        AuditAction::Upload,
        &user.account_id,
        None,
        Some(&format!(
            r#"{{"deduplicated": {}, "size": {}}}"#,
            deduplicated, file_size
        )),
    )
    .await;

    tracing::info!(
        file_id = %file_id,
        filename = %filename,
        hash = %hash,
        size = %file_size,
        deduplicated = %deduplicated,
        permissions = ?granted_permissions,
        uploaded_by = %user.account_id,
        "File uploaded successfully"
    );

    Ok(Json(UploadResponse {
        file_id,
        filename,
        blake3_hash: hash,
        file_size: file_size as i64,
        deduplicated,
        permissions_granted: granted_permissions,
    }))
}

/// GET /api/admin/files
/// List all files uploaded by the current admin
pub async fn list_admin_files(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<FileWithPermissionsResponse>>, (StatusCode, String)> {
    let files = files_repository::get_files_by_uploader(&state.files_db, &user.account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to fetch files");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    let mut responses = Vec::new();
    for file in files {
        let permissions = files_repository::get_file_permissions(&state.files_db, &file.id)
            .await
            .unwrap_or_default();

        responses.push(FileWithPermissionsResponse {
            file: FileResponse {
                id: file.id,
                filename: file.filename,
                file_type: file.file_type,
                file_size: file.file_size,
                blake3_hash: file.blake3_hash,
                uploaded_by: file.uploaded_by,
                uploaded_at: file.uploaded_at,
            },
            permissions,
        });
    }

    Ok(Json(responses))
}

/// GET /api/admin/files/{file_id}/permissions
/// Get permissions for a specific file
/// Note: Any admin can view permissions (route is already admin-protected)
pub async fn get_file_permissions(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    _user: AuthenticatedUser,
) -> Result<Json<Vec<String>>, (StatusCode, String)> {
    // Verify file exists
    if files_repository::get_file_by_id(&state.files_db, &file_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?
        .is_none()
    {
        return Err((StatusCode::NOT_FOUND, "File not found".to_string()));
    }

    let permissions = files_repository::get_file_permissions(&state.files_db, &file_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to fetch permissions");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    Ok(Json(permissions))
}

/// POST /api/admin/files/{file_id}/permissions/grant
/// Grant access to accounts
/// Note: Any admin can grant permissions (route is already admin-protected)
pub async fn grant_permissions(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    user: AuthenticatedUser,
    Json(request): Json<PermissionRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Verify file exists
    let file = files_repository::get_file_by_id(&state.files_db, &file_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?
        .ok_or((StatusCode::NOT_FOUND, "File not found".to_string()))?;

    for account_id in &request.account_ids {
        if files_repository::grant_permission(
            &state.files_db,
            &file_id,
            account_id,
            &user.account_id,
        )
        .await
        .is_ok()
        {
            let _ = files_repository::log_audit(
                &state.files_db,
                &file_id,
                &file.filename,
                &file.blake3_hash,
                AuditAction::PermissionGrant,
                &user.account_id,
                Some(account_id),
                None,
            )
            .await;
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/admin/files/{file_id}/permissions/revoke
/// Revoke access from accounts
/// Note: Any admin can revoke permissions (route is already admin-protected)
pub async fn revoke_permissions(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    user: AuthenticatedUser,
    Json(request): Json<PermissionRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Verify file exists
    let file = files_repository::get_file_by_id(&state.files_db, &file_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?
        .ok_or((StatusCode::NOT_FOUND, "File not found".to_string()))?;

    for account_id in &request.account_ids {
        let _ = files_repository::revoke_permission(&state.files_db, &file_id, account_id).await;
        let _ = files_repository::log_audit(
            &state.files_db,
            &file_id,
            &file.filename,
            &file.blake3_hash,
            AuditAction::PermissionRevoke,
            &user.account_id,
            Some(account_id),
            None,
        )
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/admin/files/{file_id}
/// Delete a file (admin only, must be owner)
pub async fn delete_file(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    user: AuthenticatedUser,
) -> Result<StatusCode, (StatusCode, String)> {
    // Get file info
    let file = files_repository::get_file_by_id(&state.files_db, &file_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?
        .ok_or((StatusCode::NOT_FOUND, "File not found".to_string()))?;

    // Verify ownership
    if file.uploaded_by != user.account_id {
        return Err((StatusCode::FORBIDDEN, "Not file owner".to_string()));
    }

    // Delete logical file (permissions cascade automatically)
    files_repository::delete_file(&state.files_db, &file_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to delete file");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    // Decrement reference count
    let new_ref_count = files_repository::decrement_ref_count(&state.files_db, &file.blake3_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to decrement ref_count");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    // Delete physical file if no more references
    if new_ref_count == 0 {
        let storage_path = get_storage_path(&file.blake3_hash);
        if let Err(e) = fs::remove_file(&storage_path).await {
            tracing::warn!(error = %e, path = ?storage_path, "Failed to delete physical file");
        } else {
            tracing::info!(hash = %file.blake3_hash, "Physical file deleted");
        }

        // Delete physical file record
        let _ = files_repository::delete_physical_file(&state.files_db, &file.blake3_hash).await;
    }

    // Log deletion
    let _ = files_repository::log_audit(
        &state.files_db,
        &file_id,
        &file.filename,
        &file.blake3_hash,
        AuditAction::Delete,
        &user.account_id,
        None,
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/admin/files/{file_id}/download
/// Download a file (admin can download their uploaded files)
pub async fn admin_download_file(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    user: AuthenticatedUser,
) -> Result<Response, (StatusCode, String)> {
    // Get file info
    let file = files_repository::get_file_with_size(&state.files_db, &file_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?
        .ok_or((StatusCode::NOT_FOUND, "File not found".to_string()))?;

    // Verify ownership
    if file.uploaded_by != user.account_id {
        return Err((StatusCode::FORBIDDEN, "Not file owner".to_string()));
    }

    download_verified_file_stream(
        &state,
        &file_id,
        &file.filename,
        &file.blake3_hash,
        &file.file_type,
        file.file_size, // Now passing size!
        &user.account_id,
    )
    .await
}

// ============================================================================
// User Handlers
// ============================================================================

/// GET /api/files
/// List all files accessible to the current user
pub async fn list_user_files(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<FileResponse>>, (StatusCode, String)> {
    let files = files_repository::get_files_for_account(&state.files_db, &user.account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to fetch files");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    let responses: Vec<FileResponse> = files
        .into_iter()
        .map(|f| FileResponse {
            id: f.id,
            filename: f.filename,
            file_type: f.file_type,
            file_size: f.file_size,
            blake3_hash: f.blake3_hash,
            uploaded_by: f.uploaded_by,
            uploaded_at: f.uploaded_at,
        })
        .collect();

    Ok(Json(responses))
}

/// GET /api/files/{file_id}/download
/// Download a file with verification (user must have permission)
pub async fn download_file(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    user: AuthenticatedUser,
) -> Result<Response, (StatusCode, String)> {
    // Check permission
    if !files_repository::verify_file_access(&state.files_db, &file_id, &user.account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?
    {
        return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
    }

    // Get file info
    let file = files_repository::get_file_with_size(&state.files_db, &file_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?
        .ok_or((StatusCode::NOT_FOUND, "File not found".to_string()))?;

    download_verified_file_stream(
        &state,
        &file_id,
        &file.filename,
        &file.blake3_hash,
        &file.file_type,
        file.file_size,
        &user.account_id,
    )
    .await
}

/// GET /api/files/{file_id}/verify
/// Verify file integrity without downloading
pub async fn verify_file(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    user: AuthenticatedUser,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    // Check permission
    if !files_repository::verify_file_access(&state.files_db, &file_id, &user.account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?
    {
        return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
    }

    // Get file info
    let file = files_repository::get_file_with_size(&state.files_db, &file_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?
        .ok_or((StatusCode::NOT_FOUND, "File not found".to_string()))?;

    let storage_path = get_storage_path(&file.blake3_hash);

    // Verify integrity (Already safe - reads chunk by chunk)
    match file_integrity::verify_file_integrity(&storage_path, &file.blake3_hash).await {
        Ok(true) => {
            tracing::info!(file_id = %file_id, "File integrity verified");
            Ok(Json(VerifyResponse {
                status: "verified".to_string(),
                blake3_hash: file.blake3_hash,
                file_size: file.file_size,
            }))
        }
        Ok(false) | Err(_) => {
            tracing::error!(file_id = %file_id, "File integrity check FAILED");

            // Log integrity failure
            let _ = files_repository::log_audit(
                &state.files_db,
                &file_id,
                &file.filename,
                &file.blake3_hash,
                AuditAction::IntegrityFailure,
                &user.account_id,
                None,
                None,
            )
            .await;

            Ok(Json(VerifyResponse {
                status: "contaminated".to_string(),
                blake3_hash: file.blake3_hash,
                file_size: file.file_size,
            }))
        }
    }
}

// ============================================================================
// SHARED DOWNLOAD LOGIC (SECURE STREAMING)
// ============================================================================

/// Downloads a file using a 2-Pass secure approach:
/// 1. Scan file on disk to verify hash (Low Memory - 64KB buffer)
/// 2. If valid, open stream and send to user
///
/// This ensures 50MB+ files don't crash the server by loading into RAM.
async fn download_verified_file_stream(
    state: &AppState,
    file_id: &str,
    filename: &str,
    blake3_hash: &str,
    file_type: &str,
    file_size: i64,
    account_id: &str,
) -> Result<Response, (StatusCode, String)> {
    let storage_path = get_storage_path(blake3_hash);

    // ---------------------------------------------------------
    // PASS 1: VERIFICATION (Scan disk, do not load to RAM)
    // ---------------------------------------------------------
    match file_integrity::verify_file_integrity(&storage_path, blake3_hash).await {
        Ok(true) => {
            // Valid! Proceed to stream.
        }
        Ok(false) => {
            tracing::error!(file_id = %file_id, "Integrity check failed - hash mismatch - Blocked download");

            let _ = files_repository::log_audit(
                &state.files_db,
                file_id,
                filename,
                blake3_hash,
                AuditAction::IntegrityFailure,
                account_id,
                None,
                Some(&format!(
                    r#"{{"reason": "Hash mismatch during pre-flight"}}"#
                )),
            )
            .await;

            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "File contaminated - download blocked".to_string(),
            ));
        }
        Err(e) => {
            tracing::error!(file_id = %file_id, error = ?e, "Integrity check failed - Blocked download");

            let _ = files_repository::log_audit(
                &state.files_db,
                file_id,
                filename,
                blake3_hash,
                AuditAction::IntegrityFailure,
                account_id,
                None,
                Some(&format!(
                    r#"{{"reason": "Hash mismatch during pre-flight"}}"#
                )),
            )
            .await;

            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "File contaminated - download blocked".to_string(),
            ));
        }
    }

    // ---------------------------------------------------------
    // PASS 2: STREAMING (Send to user)
    // ---------------------------------------------------------
    let file = fs::File::open(&storage_path).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to open file for streaming");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "File read error".to_string(),
        )
    })?;

    // Log successful download start
    let _ = files_repository::log_audit(
        &state.files_db,
        file_id,
        filename,
        blake3_hash,
        AuditAction::Download,
        account_id,
        None,
        None,
    )
    .await;

    // Create stream
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    // Security Headers + Progress Bar Support (Content-Length)
    let headers = [
        (header::CONTENT_TYPE, file_type.to_string()),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        ),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        (header::CONTENT_LENGTH, file_size.to_string()),
        (
            header::HeaderName::from_static("x-file-integrity"),
            "verified".to_string(),
        ),
        (
            header::HeaderName::from_static("x-blake3-hash"),
            blake3_hash.to_string(),
        ),
    ];

    Ok((headers, body).into_response())
}
