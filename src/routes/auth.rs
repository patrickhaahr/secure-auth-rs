use axum::{
    extract::State, 
    http::StatusCode, 
    response::Json,
};
use axum_extra::extract::cookie::CookieJar;
use crate::middleware::auth::AuthenticatedUser;
use serde::{Deserialize, Serialize};

use crate::{
    AppState,
    crypto::{account, totp},
    db::repository,
};

// Response - Requests DTOs
#[derive(Deserialize)]
pub struct SignupRequest {}

#[derive(Serialize)]
pub struct SignupResponse {
    account_id: String,
}

#[derive(Deserialize)]
pub struct TotpSetupRequest {
    account_id: String,
}

#[derive(Serialize)]
pub struct TotpSetupResponse {
    secret: String,
    qr_uri: String,
    otpauth_uri: String,
}

#[derive(Deserialize)]
pub struct TotpVerifyRequest {
    account_id: String,
    code: String,
}

#[derive(Serialize)]
pub struct TotpVerifyResponse {
    verified: bool,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    account_id: String,
    code: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

#[derive(Serialize)]
pub struct LogoutResponse {
    success: bool,
    message: String,
}

#[derive(Serialize)]
pub struct AuthStatusResponse {
    authenticated: bool,
}

// Handlers

/// POST /api/singup
/// Generates a new account with random account ID
pub async fn signup(
    State(state): State<AppState>,
) -> Result<Json<SignupResponse>, (StatusCode, String)> {
    // Generate random account ID
    let account_id = account::generate_account_id();

    // Create account in database
    repository::create_account(&state.auth_db, &account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create account");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create account".to_string(),
            )
        })?;

    tracing::info!(account_id = %account_id, "New account created");

    Ok(Json(SignupResponse { account_id }))
}

/// POST /api/login/totp/setup
/// Generates TOTP secret and returns QR code URI
pub async fn totp_setup(
    State(state): State<AppState>,
    Json(payload): Json<TotpSetupRequest>,
) -> Result<Json<TotpSetupResponse>, (StatusCode, String)> {
    let account_id = payload.account_id;

    // Load encryption key from .env
    let encryption_key = totp::load_encryption_key().map_err(|e| {
        tracing::error!(error = %e, "Failed to load TOTP encryption key");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server configuration error".to_string(),
        )
    })?;

    // Generate TOTP secret
    let secret = totp::generate_totp_secret();

    // Encrypt secret for storage
    let encryption_secret = totp::encrypt_totp_secret(&secret, &encryption_key).map_err(|e| {
        tracing::error!(error = %e, "Failed to encrypt TOTP secret");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to encrypt secret".to_string(),
        )
    })?;

    // Store encrypted secret in database
    repository::insert_totp_secret(&state.auth_db, &account_id, &encryption_secret)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, account_id = %account_id, "Failed to store TOTP secret");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to store TOTP secret".to_string(),
            )
        })?;

    // Generate QR code image (base64 data URI)
    let qr_uri = totp::generate_qr_uri(&secret, &account_id, "SecureAuthRS").map_err(|e| {
        tracing::error!(error = %e, "Failed to generate QR code URI");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate QR code URI".to_string(),
        )
    })?;

    // Generate otpauth:// URI for manual entry
    let otpauth_uri =
        totp::generate_otpauth_uri(&secret, &account_id, "SecureAuthRS").map_err(|e| {
            tracing::error!(error = %e, "Failed to generate otpauth URI");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate otpauth URI".to_string(),
            )
        })?;

    tracing::info!(account_id = %account_id, "TOTP setup completed");

    Ok(Json(TotpSetupResponse {
        secret,
        qr_uri,
        otpauth_uri,
    }))
}

/// POST /api/login/totp/verify
/// Verifies TOTP code and marks secret as verified
pub async fn totp_verify(
    State(state): State<AppState>,
    Json(payload): Json<TotpVerifyRequest>,
) -> Result<Json<TotpVerifyResponse>, (StatusCode, String)> {
    let account_id = payload.account_id;
    let code = payload.code;

    // Load encryption key
    let encryption_key = totp::load_encryption_key().map_err(|e| {
        tracing::error!(error = %e, "Failed to load TOTP encryption key");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server configuration error".to_string(),
        )
    })?;

    // Fetch TOTP secret from database
    let totp_record = sqlx::query!(
        r#"
                SELECT secret_encrypted
                FROM totp_secrets
                WHERE account_id = ?
            "#,
        account_id
    )
    .fetch_optional(&state.auth_db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Database query failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Database error".to_string(),
        )
    })?;

    let totp_record = totp_record.ok_or_else(|| {
        tracing::warn!(account_id, "TOTP secret not found");
        (StatusCode::NOT_FOUND, "TOTP not configured".to_string())
    })?;

    // Decrypt secret
    let secret = totp::decrypt_totp_secret(&totp_record.secret_encrypted, &encryption_key)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to decrypt TOTP secret");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to decrypt TOTP secret".to_string(),
            )
        })?;

    // Verify TOTP code
    let is_valid = totp::verify_totp_code(&secret, &code).map_err(|e| {
        tracing::error!(error = %e, "TOTP verification error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Verification failed".to_string(),
        )
    })?;

    if !is_valid {
        tracing::warn!(account_id = %account_id, "Invalid TOTP code during verification");
        return Ok(Json(TotpVerifyResponse { verified: false }));
    }

    // Mark TOTP as verified
    repository::verify_totp(&state.auth_db, &account_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to mark TOTP as verified");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to verify TOTP".to_string(),
            )
        })?;

    tracing::info!(account_id = %account_id, "TOTP verified successfully");

    Ok(Json(TotpVerifyResponse { verified: true }))
}

/// POST /api/login
/// Login with acccount_id and TOTP code
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), (StatusCode, String)> {
    let account_id = payload.account_id;
    let code = payload.code;

    // Load encryption key
    let encryption_key = totp::load_encryption_key().map_err(|e| {
        tracing::error!(error = %e, "Failed to load TOTP encryption key");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server configuration error".to_string(),
        )
    })?;

    // Fetch TOTP secret and verify it's been verified
    let totp_record = sqlx::query!(
        r#"
            SELECT secret_encrypted, is_verified
            FROM totp_secrets
            WHERE account_id = ?
        "#,
        account_id
    )
    .fetch_optional(&state.auth_db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Database query failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Database error".to_string(),
        )
    })?;

    let totp_record = totp_record.ok_or_else(|| {
        tracing::warn!(account_id = %account_id, "Account not found or TOTP not configured");
        (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string())
    })?;

    // Check if TOTP is verified
    if !totp_record.is_verified {
        tracing::warn!(account_id = %account_id, "TOTP not yet verified");
        return Err((
            StatusCode::FORBIDDEN,
            "TOTP must be verified before login".to_string(),
        ));
    }

    // Decrypt secret
    let secret = totp::decrypt_totp_secret(&totp_record.secret_encrypted, &encryption_key)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to decrypt TOTP secret");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to decrypt TOTP secret".to_string(),
            )
        })?;

    // Verify TOTP code
    let is_valid = totp::verify_totp_code(&secret, &code).map_err(|e| {
        tracing::error!(error = %e, "TOTP verification error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Verification failed".to_string(),
        )
    })?;

    if !is_valid {
        tracing::warn!(account_id = %account_id, "Invalid TOTP code during login");
        return Ok((jar, Json(LoginResponse {
            success: false,
            message: "Invalid code".to_string(),
            token: None,
        })));
    }

    // Generate JWT token
    let token = crate::middleware::auth::generate_token(&account_id).map_err(|e| {
        tracing::error!(error = %e, "Failed to generate JWT token");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate session token".to_string(),
        )
    })?;

    // Create and set httpOnly cookie
    let auth_cookie = crate::middleware::auth::create_auth_cookie(&token);
    let jar = jar.add(auth_cookie);

    tracing::info!(account_id = %account_id, "Login successful");

    Ok((jar, Json(LoginResponse {
        success: true,
        message: "Login successful".to_string(),
        token: Some(token),
    })))
}

/// POST /api/logout
/// Logout by clearing the auth cookie
pub async fn logout(
    jar: CookieJar,
) -> Result<(CookieJar, Json<LogoutResponse>), (StatusCode, String)> {
    // Create cookie to clear auth token
    let clear_cookie = crate::middleware::auth::create_clear_auth_cookie();
    let jar = jar.add(clear_cookie);

    tracing::info!("User logged out");

    Ok((jar, Json(LogoutResponse {
        success: true,
        message: "Logout successful".to_string(),
    })))
}

/// GET /api/auth/status
/// Check if user is authenticated (has valid cookie)
pub async fn auth_status(
    user: Result<AuthenticatedUser, (StatusCode, String)>,
) -> Json<AuthStatusResponse> {
    Json(AuthStatusResponse {
        authenticated: user.is_ok(),
    })
}
