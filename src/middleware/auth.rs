use crate::AppState;
use axum::{
    RequestPartsExt,
    extract::{FromRequestParts, State},
    http::{StatusCode, request::Parts},
    middleware::Next,
    response::Response,
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
    extract::cookie::{CookieJar, Cookie},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use time::Duration;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // account_id
    pub exp: usize,  // expiry timestamp
    pub iat: usize,  // issued at timestamp
}

#[derive(Clone)]
pub struct AuthenticatedUser {
    pub account_id: String,
}

/// Generate JWT token for authenticated user
pub fn generate_token(account_id: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        tracing::warn!("JWT_SECRET not set, using default (insecure for production!)");
        "default_secret_change_in_production".to_string()
    });

    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::hours(1); // Shorter expiry for cookies

    let claims = Claims {
        sub: account_id.to_string(),
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// Create secure httpOnly cookie with JWT token
pub fn create_auth_cookie(token: &str) -> Cookie<'static> {
    Cookie::build(("auth_token", token.to_string()))
        .http_only(true)
        .secure(true) // HTTPS only
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .max_age(Duration::hours(1)) // Match token expiry
        .path("/")
        .build()
}

/// Create cookie to clear auth token
pub fn create_clear_auth_cookie() -> Cookie<'static> {
    Cookie::build(("auth_token", "".to_string()))
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .max_age(Duration::seconds(-1)) // Expire immediately
        .path("/")
        .build()
}

/// Verify JWT token and extract claims
pub fn verify_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "default_secret_change_in_production".to_string());

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;

    Ok(token_data.claims)
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Try to extract token from Authorization header first (for backward compatibility)
        if let Ok(TypedHeader(Authorization(bearer))) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
        {
            // Verify token from header
            let claims = verify_token(bearer.token()).map_err(|e| {
                tracing::warn!(error = %e, "Invalid JWT token from header");
                (StatusCode::UNAUTHORIZED, "Invalid token".to_string())
            })?;

            return Ok(AuthenticatedUser {
                account_id: claims.sub,
            });
        }

        // Try to extract token from cookies
        let cookies = parts
            .extract::<CookieJar>()
            .await
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Missing authentication".to_string(),
                )
            })?;

        if let Some(cookie) = cookies.get("auth_token") {
            let token = cookie.value();
            
            // Verify token from cookie
            let claims = verify_token(token).map_err(|e| {
                tracing::warn!(error = %e, "Invalid JWT token from cookie");
                (StatusCode::UNAUTHORIZED, "Invalid token".to_string())
            })?;

            Ok(AuthenticatedUser {
                account_id: claims.sub,
            })
        } else {
            Err((
                StatusCode::UNAUTHORIZED,
                "Missing authentication token".to_string(),
            ))
        }
    }
}

/// Middleware to require admin privileges
pub async fn require_admin(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let is_admin = crate::db::repository::is_admin(&state.auth_db, &user.account_id)
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
        Ok(next.run(request).await)
    } else {
        tracing::warn!(account_id = %user.account_id, "Admin access denied");
        Err((StatusCode::FORBIDDEN, "Admin access required".to_string()))
    }
}
