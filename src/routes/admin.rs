use crate::{AppState, db::repository, middleware::auth::AuthenticatedUser};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::Serialize;

#[derive(Serialize)]
pub struct AdminCheckResponse {
    is_admin: bool,
}

#[derive(Serialize)]
pub struct UserResponse {
    id: String,
    created_at: String,
    is_verified: bool,
}

impl From<crate::db::models::Account> for UserResponse {
    fn from(account: crate::db::models::Account) -> Self {
        Self {
            id: account.id,
            created_at: account.created_at,
            is_verified: account.is_verified,
        }
    }
}

/// GET /api/admin/check
/// Check if the authenticated user has admin privileges
pub async fn check_admin_access(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<AdminCheckResponse>, (StatusCode, String)> {
    let is_admin = repository::is_admin(&state.db, &user.account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check admin status");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    if is_admin {
        tracing::info!(account_id = %user.account_id, "Admin access granted");
        Ok(Json(AdminCheckResponse { is_admin: true }))
    } else {
        tracing::warn!(account_id = %user.account_id, "Admin access denied");
        Err((StatusCode::FORBIDDEN, "Admin access required".to_string()))
    }
}

/// GET /api/admin/users
/// List all users (admin only)
pub async fn list_users(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
) -> Result<Json<Vec<UserResponse>>, (StatusCode, String)> {
    let accounts = repository::get_all_accounts(&state.db).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to retrieve accounts");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Database error".to_string(),
        )
    })?;

    let users: Vec<UserResponse> = accounts.into_iter().map(UserResponse::from).collect();
    tracing::info!(count = %users.len(), "Admin retrieved user list");

    Ok(Json(users))
}

/// DELETE /api/admin/users/{account_id}
/// Delete a user (admin only)
pub async fn delete_user(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    _user: AuthenticatedUser,
) -> Result<StatusCode, (StatusCode, String)> {
    let rows_affected = repository::delete_account(&state.db, &account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, account_id = %account_id, "Failed to delete account");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    if rows_affected > 0 {
        tracing::info!(account_id = %account_id, "Admin deleted account");
        Ok(StatusCode::NO_CONTENT)
    } else {
        tracing::warn!(account_id = %account_id, "Admin attempted to delete non-existent account");
        Err((StatusCode::NOT_FOUND, "Account not found".to_string()))
    }
}
