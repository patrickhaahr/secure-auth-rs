mod crypto;
mod db;
mod middleware;
mod routes;
mod tls;

use sqlx::Pool;
use sqlx::Sqlite;
use std::time::Duration;
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

    // Create application with all routes and middleware
    let app = routes::create_app(app_state, csrf_protection, rate_limiter);

    // Load TLS configuration from environment
    let bind_addr = std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1".to_string());
    let https_port = std::env::var("HTTPS_PORT")
        .unwrap_or_else(|_| "3443".to_string())
        .parse::<u16>()
        .expect("HTTPS_PORT must be a valid port number");

    let cert_path =
        std::env::var("TLS_CERT_PATH").expect("TLS_CERT_PATH environment variable required");
    let key_path =
        std::env::var("TLS_KEY_PATH").expect("TLS_KEY_PATH environment variable required");
    let key_password =
        std::env::var("TLS_KEY_PASSWORD").expect("TLS_KEY_PASSWORD environment variable required");

    // Load and validate TLS configuration
    let tls_config = tls::load_tls_config(&cert_path, &key_path, &key_password)
        .await
        .expect(
            "Failed to load TLS configuration - server will not start with invalid certificates",
        );

    let addr: std::net::SocketAddr = format!("{}:{}", bind_addr, https_port)
        .parse()
        .expect("Invalid bind address or port");

    tracing::info!(
        "🔒 HTTPS server starting on https://{}:{}",
        bind_addr,
        https_port
    );
    tracing::info!("✓ TLS certificates validated successfully");

    // Start HTTPS server with TLS
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
        .expect("Server failed");
}
