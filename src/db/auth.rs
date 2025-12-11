use super::create_sqlite_pool;
use sqlx::{Pool, Sqlite};

pub async fn init_auth_pool() -> Result<Pool<Sqlite>, sqlx::Error> {
    let pool = create_sqlite_pool("AUTH_DATABASE_URL", "sqlite:auth.db", false).await?;

    sqlx::migrate!("./migrations/auth").run(&pool).await?;

    tracing::info!("Auth database migrations completed");
    Ok(pool)
}
