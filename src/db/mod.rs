pub mod models;
pub mod repository;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Sqlite};
use std::str::FromStr;

/// Initialize the SQLite connection pool
pub async fn init_pool() -> Result<Pool<Sqlite>, sqlx::Error> {
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:auth.db".to_string());

    // Configure SQLite options
    let connect_options = SqliteConnectOptions::from_str(&database_url)?.create_if_missing(true);

    // Create connection pool
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connect_options)
        .await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}
