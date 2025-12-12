use axum::extract::DefaultBodyLimit;
use secure_auth_rs::{
    crypto, db, middleware, routes, tls, AppState
};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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

    tracing::info!("Initializing database connections...");

    // Initialize both database pools concurrently
    let (auth_pool, files_pool) = tokio::try_join!(db::init_auth_pool(), db::init_files_pool())
        .expect("Failed to initialize database pools");

    tracing::info!("Auth and Files databases connected and migrated");

    // Initialize CSRF protection
    let csrf_protection = middleware::csrf::CsrfProtection::new();

    // Load PQ keys
    let pq_sk_path = std::env::var("PQ_SECRET_KEY_PATH")
        .expect("PQ_SECRET_KEY_PATH environment variable required");
    let pq_pk_path = std::env::var("PQ_PUBLIC_KEY_PATH")
        .expect("PQ_PUBLIC_KEY_PATH environment variable required");

    let pq_secret_key = Arc::new(
        crypto::pq_hybrid::load_secret_key(Path::new(&pq_sk_path))
            .expect("Failed to load PQ secret key"),
    );
    let pq_public_key = Arc::new(
        crypto::pq_hybrid::load_public_key(Path::new(&pq_pk_path))
            .expect("Failed to load PQ public key"),
    );

    tracing::info!(
        "PQ hybrid keys loaded. Fingerprint: {}",
        crypto::pq_hybrid::fingerprint(&pq_public_key)
    );

    let app_state = AppState {
        auth_db: auth_pool,
        files_db: files_pool,
        csrf: csrf_protection.clone(),
        pq_secret_key,
        pq_public_key,
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

    // Ensure upload directory exists
    tokio::fs::create_dir_all("files/uploads")
        .await
        .expect("Failed to create files/uploads directory");

    // Configure rate limiting for TOTP endpoints
    // 5 requests per minute per IP to prevent brute force attacks
    let rate_limiter = middleware::rate_limit::RateLimiter::new(5, Duration::from_secs(60));

    // Create application with all routes and middleware
    let app = routes::create_app(app_state, csrf_protection, rate_limiter)
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024));

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
