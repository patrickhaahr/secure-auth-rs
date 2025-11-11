mod crypto;
mod db;

use axum::{Router, routing::get};
use sqlx::Pool;
use sqlx::Sqlite;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Pool<Sqlite>>,
}

#[tokio::main]
async fn main() {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize database connection pool
    let pool = db::init_pool()
        .await
        .expect("Failed to initialize database pool");

    println!("✓ Database connected and migrations completed");

    let app_state = AppState { db: Arc::new(pool) };

    // Create router
    let app = Router::new()
        .route("/health", get(health_check))
        .with_state(app_state);

    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("Failed to bind to port 3000");

    println!("✓ Server running on http://127.0.0.1:3000");

    axum::serve(listener, app).await.expect("Server failed");
}

async fn health_check() -> &'static str {
    "OK"
}
