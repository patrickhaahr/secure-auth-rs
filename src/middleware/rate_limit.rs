use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    pub fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();

        // Get or create entry for this IP
        let ip_requests = requests.entry(ip).or_insert_with(Vec::new);

        // Remove requests outside the time window
        ip_requests.retain(|&time| now.duration_since(time) < self.window);

        // Check if under limit
        if ip_requests.len() < self.max_requests {
            ip_requests.push(now);
            true
        } else {
            false
        }
    }

    pub async fn middleware(
        &self,
        req: Request,
        next: Next,
    ) -> Response {
        // Extract IP from connection info - fail if unavailable
        let ip = match req.extensions().get::<std::net::SocketAddr>() {
            Some(addr) => addr.ip(),
            None => {
                tracing::warn!("Unable to determine client IP address");
                return (
                    StatusCode::BAD_REQUEST,
                    "Unable to determine client IP address",
                )
                    .into_response();
            }
        };

        if !self.check_rate_limit(ip) {
            return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
        }

        next.run(req).await
    }
}
