pub mod auth;
pub mod files;
pub mod files_models;
pub mod files_repository;
pub mod models;
pub mod repository;

// Re-export the init functions so main.rs can call db::init.
// Re-export the init functions so main.rs can call db::init...
pub use auth::init_auth_pool;
pub use files::init_files_pool;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Sqlite};
use std::str::FromStr;
use std::time::Duration;

/// Shared configuration logic to ensure consistent timeouts and settings
async fn create_sqlite_pool(
    env_var: &str,
    default_db_url: &str,
    with_foreign_keys: bool,
) -> Result<Pool<Sqlite>, sqlx::Error> {
    let database_url = std::env::var(env_var).unwrap_or_else(|_| default_db_url.to_string());

    let mut connect_options = SqliteConnectOptions::from_str(&database_url)?
        .create_if_missing(true)
        // WAL mode is highly recommended for concurrency in SQLite
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

    if with_foreign_keys {
        connect_options = connect_options.foreign_keys(true);
    }

    SqlitePoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .idle_timeout(Duration::from_secs(600))
        .connect_with(connect_options)
        .await
}
