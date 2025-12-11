use super::create_sqlite_pool;
use sqlx::{Pool, Sqlite};

pub async fn init_files_pool() -> Result<Pool<Sqlite>, sqlx::Error> {
    let pool = create_sqlite_pool("FILES_DATABASE_URL", "sqlite:files.db", true).await?;

    sqlx::migrate!("./migrations/files").run(&pool).await?;

    tracing::info!("Files database migrations completed");
    Ok(pool)
}
