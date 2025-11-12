use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

use crate::{AppState, db::repository, middleware::auth::AuthenticatedUser};

/// Middleware that ensures the authenticated user has submitted CPR data
/// before accessing protected endpoints (except /api/account/cpr itself)
pub async fn require_cpr(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path().to_string();

    // Skip CPR check for the CPR submission endpoint itself
    if path == "/api/account/cpr" {
        return Ok(next.run(request).await);
    }

    // Check if user has submitted CPR
    let has_cpr = repository::has_cpr(&state.db, &user.account_id)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                account_id = %user.account_id,
                "Failed to check CPR status"
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if !has_cpr {
        tracing::warn!(
            account_id = %user.account_id,
            path = %path,
            "Access denied: CPR submission required"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}
