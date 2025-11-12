use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,      // account_id
    pub exp: usize,       // expiry timestamp
    pub iat: usize,       // issued at timestamp
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
    let exp = now + chrono::Duration::hours(24);

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

/// Verify JWT token and extract claims
pub fn verify_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        "default_secret_change_in_production".to_string()
    });

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

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Extract Authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Missing or invalid authorization header".to_string(),
                )
            })?;

        // Verify token
        let claims = verify_token(bearer.token()).map_err(|e| {
            tracing::warn!(error = %e, "Invalid JWT token");
            (StatusCode::UNAUTHORIZED, "Invalid token".to_string())
        })?;

        Ok(AuthenticatedUser {
            account_id: claims.sub,
        })
    }
}
