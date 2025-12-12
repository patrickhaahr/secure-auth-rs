//! Admin endpoints for managing quarantined files
//!
//! Admins must review and approve third-party uploads before they
//! are accessible to users.

use crate::{
    db::{files_models::{AuditAction, FileWithStatus}, files_repository},
    middleware::auth::AuthenticatedUser,
    AppState,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

/// GET /api/admin/quarantine
/// List all quarantined files waiting for approval
pub async fn list_quarantined(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
) -> Result<Json<Vec<FileWithStatus>>, (StatusCode, String)> {
    let files = files_repository::get_quarantined_files(&state.files_db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to fetch quarantined files");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    Ok(Json(files))
}

/// POST /api/admin/quarantine/{file_id}/approve
/// Approve a quarantined file
pub async fn approve_file(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    user: AuthenticatedUser,
) -> Result<StatusCode, (StatusCode, String)> {
    let rows_affected = files_repository::approve_file(&state.files_db, &file_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to approve file");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    if rows_affected == 0 {
        return Err((StatusCode::NOT_FOUND, "File not found or not in quarantine".to_string()));
    }

    // Get file info for logging
    if let Ok(Some(file)) = files_repository::get_file_with_status(&state.files_db, &file_id).await {
        let _ = files_repository::log_audit(
            &state.files_db,
            &file_id,
            &file.filename,
            &file.blake3_hash,
            AuditAction::QuarantineApprove,
            &user.account_id,
            None,
            None,
        )
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/admin/quarantine/{file_id}/reject
/// Reject a quarantined file
pub async fn reject_file(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    user: AuthenticatedUser,
) -> Result<StatusCode, (StatusCode, String)> {
    let rows_affected = files_repository::reject_file(&state.files_db, &file_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to reject file");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    if rows_affected == 0 {
        return Err((StatusCode::NOT_FOUND, "File not found or not in quarantine".to_string()));
    }

    // Get file info for logging
    if let Ok(Some(file)) = files_repository::get_file_with_status(&state.files_db, &file_id).await {
        let _ = files_repository::log_audit(
            &state.files_db,
            &file_id,
            &file.filename,
            &file.blake3_hash,
            AuditAction::QuarantineReject,
            &user.account_id,
            None,
            None,
        )
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}
