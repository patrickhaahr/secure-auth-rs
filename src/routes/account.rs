use crate::{middleware::auth::AuthenticatedUser, AppState, crypto::cpr, db::repository};
use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};

// Request/Response Types

#[derive(Deserialize)]
pub struct CprSubmitRequest {
    account_id: String,
    cpr: String,
}

#[derive(Serialize)]
pub struct CprSubmitResponse {
    success: bool,
    message: String,
}

// Handlers

/// POST /api/account/cpr
/// Store CPR number (hashed) for an account
pub async fn submit_cpr(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(payload): Json<CprSubmitRequest>,
) -> Result<Json<CprSubmitResponse>, (StatusCode, String)> {
    let account_id = payload.account_id;
    let cpr = payload.cpr;

    // Authorization check: user must own the account or be admin
    if user.account_id != account_id {
        let is_admin = repository::is_admin(&state.db, &user.account_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to check admin status");
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
            })?;

        if !is_admin {
            tracing::warn!(
                requesting_account = %user.account_id,
                target_account = %account_id,
                "Unauthorized CPR submission attempt"
            );
            return Err((StatusCode::FORBIDDEN, "Unauthorized".to_string()));
        }
    }

    // Verify account exists
    let account_exists = repository::account_exists(&state.db, &account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to verify account");
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
        })?;

    if !account_exists {
        return Err((StatusCode::BAD_REQUEST, "Invalid account".to_string()));
    }

    // Hash the CPR number
    let cpr_hash = cpr::hash_cpr(&cpr).map_err(|e| {
        tracing::error!(error = %e, "Failed to hash CPR");
        (StatusCode::BAD_REQUEST, "Invalid CPR format".to_string())
    })?;

    // Insert CPR data - database UNIQUE constraint on cpr_hash will prevent duplicates
    match repository::insert_cpr_data(&state.db, &account_id, &cpr_hash).await {
        Ok(_) => {
            tracing::info!("CPR stored successfully");
            Ok(Json(CprSubmitResponse {
                success: true,
                message: "CPR stored successfully".to_string(),
            }))
        }
        Err(e) => {
            // Check if this is a unique constraint violation
            let error_str = e.to_string();
            if error_str.contains("UNIQUE constraint failed") {
                tracing::warn!("Attempted to register duplicate CPR");
                // Return generic error to prevent CPR enumeration
                Err((
                    StatusCode::BAD_REQUEST,
                    "Unable to process request".to_string(),
                ))
            } else {
                tracing::error!(error = %e, "Failed to store CPR data");
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to store CPR".to_string(),
                ))
            }
        }
    }
}
