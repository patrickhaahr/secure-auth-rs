mod crypto;
mod db;
mod middleware;
mod routes;

use axum::{
    extract::State,
    middleware as axum_middleware,
    Router,
    routing::{get, post},
    Json,
};
use sqlx::Pool;
use sqlx::Sqlite;
use std::time::Duration;
use tower_http::services::ServeDir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState {
    pub db: Pool<Sqlite>,
    pub csrf: middleware::csrf::CsrfProtection,
}

#[tokio::main]
async fn main() {
    // Initialize tracing/logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "secure_auth_rs=info,tower_governor=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize database connection pool
    let pool = db::init_pool()
        .await
        .expect("Failed to initialize database pool");

    tracing::info!("Database connected and migrations completed");

    // Initialize CSRF protection
    let csrf_protection = middleware::csrf::CsrfProtection::new();

    let app_state = AppState {
        db: pool,
        csrf: csrf_protection.clone(),
    };

    // Verify static directory exists
    let static_dir = std::path::Path::new("static");
    if !static_dir.exists() {
        tracing::error!("Static directory not found at path: {:?}", static_dir);
        panic!("Static directory 'static' does not exist in current directory");
    }
    let canonical_path = static_dir
        .canonicalize()
        .unwrap_or_else(|_| static_dir.to_path_buf());
    tracing::info!("Serving static files from: {:?}", canonical_path);

    // Configure rate limiting for TOTP endpoints
    // 5 requests per minute per IP to prevent brute force attacks
    let rate_limiter = middleware::rate_limit::RateLimiter::new(5, Duration::from_secs(60));

    // Create router with proper middleware scoping
    
    // Rate-limited routes (TOTP verification and login)
    let rate_limited_routes = Router::new()
        .route("/api/login/totp/verify", post(routes::auth::totp_verify))
        .route("/api/login", post(routes::auth::login))
        .layer(axum_middleware::from_fn(move |jar, req, next| {
            let limiter = rate_limiter.clone();
            async move { limiter.middleware(jar, req, next).await }
        }));

    // Authenticated routes that require CPR submission
    // These routes are protected by CSRF + Auth + CPR verification
    let cpr_protected_routes = Router::new()
        // Future authenticated endpoints will go here
        // Example: .route("/api/account/profile", get(routes::account::get_profile))
        .layer(axum_middleware::from_fn_with_state(
            app_state.clone(),
            middleware::cpr::require_cpr,
        ))
        .layer(axum_middleware::from_fn({
            let csrf = csrf_protection.clone();
            move |req, next| {
                let csrf = csrf.clone();
                async move { csrf.middleware(req, next).await }
            }
        }));

    // CPR submission route (requires CSRF + Auth, but NOT CPR check since this is how you submit CPR)
    let cpr_submission_route = Router::new()
        .route("/api/account/cpr", post(routes::account::submit_cpr))
        .layer(axum_middleware::from_fn({
            let csrf = csrf_protection.clone();
            move |req, next| {
                let csrf = csrf.clone();
                async move { csrf.middleware(req, next).await }
            }
        }));

    // CSRF-protected routes (all POST routes that don't require auth)
    let csrf_protected_routes = Router::new()
        .route("/api/signup", post(routes::auth::signup))
        .route("/api/login/totp/setup", post(routes::auth::totp_setup))
        .layer(axum_middleware::from_fn(move |req, next| {
            let csrf = csrf_protection.clone();
            async move { csrf.middleware(req, next).await }
        }));

    // Combine all routes
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/csrf-token", get(get_csrf_token))
        .merge(rate_limited_routes)
        .merge(csrf_protected_routes)
        .merge(cpr_submission_route)
        .merge(cpr_protected_routes)
        .fallback_service(ServeDir::new("static"))
        .with_state(app_state);

    // Start server with ConnectInfo to extract client IP
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("Failed to bind to port 3000");

    tracing::info!("Server running on http://127.0.0.1:3000");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .expect("Server failed");
}

async fn health_check() -> &'static str {
    "OK"
}

async fn get_csrf_token(State(state): State<AppState>) -> Json<serde_json::Value> {
    let token = state.csrf.generate_token();
    Json(serde_json::json!({ "csrf_token": token }))
}
