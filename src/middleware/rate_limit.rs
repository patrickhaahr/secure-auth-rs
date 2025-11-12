//! GDPR-Compliant Rate Limiting
//!
//! This implementation uses a multi-tier approach under GDPR "legitimate interest":
//!
//! 1. IP-based limiting (primary): Uses client IP from trusted proxy headers
//!    - Checks X-Forwarded-For, X-Real-IP, CF-Connecting-IP in order
//!    - Falls back to socket address if no proxy headers
//!
//! 2. Session-based limiting (fallback): Uses HTTP-only session cookies
//!    - Cookies are "technically necessary" under GDPR (no consent required)
//!    - Short expiry (15 minutes) minimizes tracking
//!    - SameSite=Strict for security
//!
//! 3. Challenge-based responses: Instead of blocking, we require proof-of-work
//!    or CAPTCHA after threshold (future enhancement)
//!
//! Legal Basis: GDPR Art. 6(1)(f) - Legitimate Interest (security)
//! No browser fingerprinting or invasive tracking is used.

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Identifier for rate limiting - either IP address or session ID
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub(crate) enum ClientIdentifier {
    Ip(IpAddr),
    Session(String),
}

/// Action to take based on rate limit check
#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitAction {
    Allow,
    RequireChallenge,
    Block,
}

#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<ClientIdentifier, Vec<Instant>>>>,
    max_requests: usize,
    challenge_threshold: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        // Challenge threshold is 50% of max_requests
        let challenge_threshold = max_requests / 2;
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            challenge_threshold,
            window,
        }
    }

    /// Check rate limit and return appropriate action
    pub fn check_rate_limit(&self, identifier: ClientIdentifier) -> RateLimitAction {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();

        // Get or create entry for this identifier
        let client_requests = requests.entry(identifier).or_default();

        // Remove requests outside the time window
        client_requests.retain(|&time| now.duration_since(time) < self.window);

        let request_count = client_requests.len();

        // Determine action based on request count
        if request_count < self.challenge_threshold {
            client_requests.push(now);
            RateLimitAction::Allow
        } else if request_count < self.max_requests {
            client_requests.push(now);
            RateLimitAction::RequireChallenge
        } else {
            RateLimitAction::Block
        }
    }

    /// Extract client IP from headers or socket address
    /// Checks proxy headers in order: X-Forwarded-For, X-Real-IP, CF-Connecting-IP
    fn extract_client_ip(headers: &HeaderMap, socket_addr: Option<SocketAddr>) -> Option<IpAddr> {
        // Check X-Forwarded-For (most common proxy header)
        if let Some(forwarded) = headers.get("x-forwarded-for")
            && let Ok(forwarded_str) = forwarded.to_str()
            && let Some(first_ip) = forwarded_str.split(',').next()
            && let Ok(ip) = first_ip.trim().parse::<IpAddr>()
        {
            tracing::debug!("Using IP from X-Forwarded-For: {}", ip);
            return Some(ip);
        }

        // Check X-Real-IP (Nginx)
        if let Some(real_ip) = headers.get("x-real-ip")
            && let Ok(ip_str) = real_ip.to_str()
            && let Ok(ip) = ip_str.parse::<IpAddr>()
        {
            tracing::debug!("Using IP from X-Real-IP: {}", ip);
            return Some(ip);
        }

        // Check CF-Connecting-IP (Cloudflare)
        if let Some(cf_ip) = headers.get("cf-connecting-ip")
            && let Ok(ip_str) = cf_ip.to_str()
            && let Ok(ip) = ip_str.parse::<IpAddr>()
        {
            tracing::debug!("Using IP from CF-Connecting-IP: {}", ip);
            return Some(ip);
        }

        // Fallback to socket address
        if let Some(addr) = socket_addr {
            tracing::debug!("Using IP from socket address: {}", addr.ip());
            return Some(addr.ip());
        }

        None
    }

    /// Extract session ID from cookie jar
    fn extract_session_from_cookie(jar: &CookieJar) -> Option<String> {
        jar.get("rl_session").map(|cookie| cookie.value().to_string())
    }

    /// Create a new session cookie for rate limiting
    fn create_session_cookie(session_id: String) -> Cookie<'static> {
        // Cookie expiry: 15 minutes (900 seconds)
        Cookie::build(("rl_session", session_id))
            .http_only(true)
            .same_site(axum_extra::extract::cookie::SameSite::Strict)
            .max_age(time::Duration::seconds(900))
            .path("/")
            .build()
    }

    pub async fn middleware(
        &self,
        jar: CookieJar,
        req: Request,
        next: Next,
    ) -> (CookieJar, Response) {
        let headers = req.headers();
        let socket_addr = req.extensions().get::<SocketAddr>().copied();

        // Try to extract IP address first (primary method)
        let identifier = if let Some(ip) = Self::extract_client_ip(headers, socket_addr) {
            tracing::debug!("Rate limiting by IP: {}", ip);
            ClientIdentifier::Ip(ip)
        } else {
            // Fallback to session-based identification
            tracing::warn!("No IP address available, falling back to session-based rate limiting");
            
            if let Some(session_id) = Self::extract_session_from_cookie(&jar) {
                tracing::debug!("Using existing session for rate limiting: {}", &session_id[..8]);
                ClientIdentifier::Session(session_id)
            } else {
                // Create new session
                let new_session_id = Uuid::new_v4().to_string();
                tracing::debug!("Created new session for rate limiting: {}", &new_session_id[..8]);
                ClientIdentifier::Session(new_session_id.clone())
            }
        };

        // Check rate limit
        let action = self.check_rate_limit(identifier.clone());

        match action {
            RateLimitAction::Allow => {
                // Set session cookie if using session-based limiting
                let jar = if let ClientIdentifier::Session(session_id) = identifier {
                    jar.add(Self::create_session_cookie(session_id))
                } else {
                    jar
                };
                
                let response = next.run(req).await;
                (jar, response)
            }
            RateLimitAction::RequireChallenge => {
                // For future enhancement: return challenge requirement
                // For now, we'll still allow but log a warning
                tracing::warn!("Client approaching rate limit threshold");
                
                let jar = if let ClientIdentifier::Session(session_id) = identifier {
                    jar.add(Self::create_session_cookie(session_id))
                } else {
                    jar
                };
                
                let response = next.run(req).await;
                (jar, response)
            }
            RateLimitAction::Block => {
                tracing::warn!("Rate limit exceeded for client");
                let response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    axum::Json(json!({
                        "error": "Rate limit exceeded",
                        "message": "Too many requests. Please try again later."
                    })),
                )
                    .into_response();
                (jar, response)
            }
        }
    }
}
