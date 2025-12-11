use crate::{AppState, crypto::cpr, db::repository, middleware::auth::AuthenticatedUser};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
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

#[derive(Serialize)]
pub struct AccountStatusResponse {
    is_verified: bool,
    has_totp: bool,
    has_cpr: bool,
}

#[derive(Deserialize)]
pub struct CprVerifyRequest {
    account_id: String,
    cpr: String,
}

#[derive(Serialize)]
pub struct CprVerifyResponse {
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
        let is_admin = repository::is_admin(&state.auth_db, &user.account_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to check admin status");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error".to_string(),
                )
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
    let account_exists = repository::account_exists(&state.auth_db, &account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to verify account");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
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
    match repository::insert_cpr_data(&state.auth_db, &account_id, &cpr_hash).await {
        Ok(_) => {
            tracing::info!("CPR stored successfully");

            // Check if TOTP is verified, if so, mark account as fully verified
            let totp_verified = sqlx::query_scalar!(
                r#"
                    SELECT is_verified FROM totp_secrets WHERE account_id = ?
                    "#,
                account_id
            )
            .fetch_one(&state.auth_db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to check TOTP verification status");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error".to_string(),
                )
            })?;

            if totp_verified {
                repository::set_account_verified(&state.auth_db, &account_id)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to mark account as verified");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to verify account".to_string(),
                        )
                    })?;

                tracing::info!(account_id = %account_id, "Account fully verified (TOTP + CPR)");
            }

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

/// GET /api/account/{account_id}/status
/// Get account verification status
pub async fn get_account_status(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
) -> Result<Json<AccountStatusResponse>, (StatusCode, String)> {
    // Verify account exists
    let account_exists = repository::account_exists(&state.auth_db, &account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to verify account");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    if !account_exists {
        return Err((StatusCode::NOT_FOUND, "Account not found".to_string()));
    }

    // Check verification status
    let is_verified = repository::is_account_verified(&state.auth_db, &account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check account verification");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    // Check if TOTP is configured and verified
    let has_totp_count: i64 = sqlx::query_scalar!(
        r#"
            SELECT COUNT(*)
            FROM totp_secrets 
            WHERE account_id = ? AND is_verified = TRUE
            "#,
        account_id
    )
    .fetch_one(&state.auth_db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to check TOTP status");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Database error".to_string(),
        )
    })?;

    let has_totp = has_totp_count > 0;

    // Check if CPR is submitted
    let has_cpr = repository::has_cpr(&state.auth_db, &account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check CPR status");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    tracing::debug!(
        account_id = %account_id,
        is_verified = %is_verified,
        has_totp = %has_totp,
        has_cpr = %has_cpr,
        "Account status retrieved"
    );

    Ok(Json(AccountStatusResponse {
        is_verified,
        has_totp,
        has_cpr,
    }))
}

/// POST /api/account/cpr/verify
/// Verify CPR number for login (doesn't store, just validates)
pub async fn verify_cpr_for_login(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(payload): Json<CprVerifyRequest>,
) -> Result<Json<CprVerifyResponse>, (StatusCode, String)> {
    let account_id = payload.account_id;
    let cpr = payload.cpr;

    // Authorization check: user must own the account or be admin
    if user.account_id != account_id {
        let is_admin = repository::is_admin(&state.auth_db, &user.account_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to check admin status");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error".to_string(),
                )
            })?;

        if !is_admin {
            tracing::warn!(
                requesting_account = %user.account_id,
                target_account = %account_id,
                "Unauthorized CPR verification attempt"
            );
            return Err((StatusCode::FORBIDDEN, "Unauthorized".to_string()));
        }
    }

    // Verify account exists
    let account_exists = repository::account_exists(&state.auth_db, &account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to verify account");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    if !account_exists {
        return Err((StatusCode::BAD_REQUEST, "Invalid account".to_string()));
    }

    // Get stored CPR hash for this account
    let stored_cpr_hash = repository::get_cpr_hash_by_account(&state.auth_db, &account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to retrieve stored CPR hash");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    let stored_cpr_hash = match stored_cpr_hash {
        Some(hash) => hash,
        None => {
            tracing::warn!(account_id = %account_id, "CPR verification failed - no CPR stored");
            return Ok(Json(CprVerifyResponse {
                success: false,
                message: "Invalid CPR".to_string(),
            }));
        }
    };

    // Verify CPR against stored hash using peppered verification
    let is_valid = cpr::verify_cpr(&cpr, &stored_cpr_hash).map_err(|e| {
        tracing::error!(error = %e, "Failed to verify CPR");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "CPR verification failed".to_string(),
        )
    })?;

    if is_valid {
        tracing::info!(account_id = %account_id, "CPR verified successfully for login");
        Ok(Json(CprVerifyResponse {
            success: true,
            message: "CPR verified".to_string(),
        }))
    } else {
        tracing::warn!(account_id = %account_id, "CPR verification failed - incorrect CPR");
        Ok(Json(CprVerifyResponse {
            success: false,
            message: "Invalid CPR".to_string(),
        }))
    }
}
