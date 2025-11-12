use crate::{middleware::auth::AuthenticatedUser, AppState, db::repository};
use axum::{extract::State, http::StatusCode, response::Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct AdminCheckResponse {
    is_admin: bool,
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
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
        })?;

    if is_admin {
        tracing::info!(account_id = %user.account_id, "Admin access granted");
        Ok(Json(AdminCheckResponse { is_admin: true }))
    } else {
        tracing::warn!(account_id = %user.account_id, "Admin access denied");
        Err((StatusCode::FORBIDDEN, "Admin access required".to_string()))
    }
}