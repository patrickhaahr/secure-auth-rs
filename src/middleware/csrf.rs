use axum::{
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rand::Rng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const CSRF_HEADER: &str = "X-CSRF-Token";
const CSRF_TOKEN_LENGTH: usize = 32;
const TOKEN_EXPIRY_SECONDS: u64 = 3600; // 1 hour

#[derive(Clone)]
pub struct CsrfProtection {
    tokens: Arc<Mutex<HashMap<String, u64>>>, // token -> expiry timestamp
}

impl CsrfProtection {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generate a new CSRF token
    pub fn generate_token(&self) -> String {
        let token: String = rand::rng()
            .sample_iter(rand::distr::Alphanumeric)
            .take(CSRF_TOKEN_LENGTH)
            .map(char::from)
            .collect();

        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + TOKEN_EXPIRY_SECONDS;

        let mut tokens = self.tokens.lock().unwrap();
        tokens.insert(token.clone(), expiry);

        // Cleanup expired tokens
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        tokens.retain(|_, &mut exp| exp > now);

        token
    }

    /// Verify a CSRF token
    pub fn verify_token(&self, token: &str) -> bool {
        let mut tokens = self.tokens.lock().unwrap();
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if token exists and is not expired
        if let Some(&expiry) = tokens.get(token) {
            if expiry > now {
                // Token is valid, remove it (one-time use)
                tokens.remove(token);
                return true;
            } else {
                // Token expired, remove it
                tokens.remove(token);
            }
        }

        false
    }

    /// Middleware to verify CSRF tokens on state-changing requests
    pub async fn middleware(&self, req: Request, next: Next) -> Response {
        // Only verify CSRF on state-changing methods
        match *req.method() {
            Method::GET | Method::HEAD | Method::OPTIONS => {
                // Safe methods don't need CSRF protection
                return next.run(req).await;
            }
            _ => {}
        }

        // Extract CSRF token from header
        let token = req
            .headers()
            .get(CSRF_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if token.is_empty() {
            tracing::warn!("CSRF token missing in request");
            return (StatusCode::FORBIDDEN, "CSRF token required").into_response();
        }

        if !self.verify_token(token) {
            tracing::warn!(token = %token, "Invalid or expired CSRF token");
            return (StatusCode::FORBIDDEN, "Invalid or expired CSRF token").into_response();
        }

        next.run(req).await
    }
}

impl Default for CsrfProtection {
    fn default() -> Self {
        Self::new()
    }
}
