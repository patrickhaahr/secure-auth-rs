pub mod crypto;
pub mod db;
pub mod middleware;
pub mod routes;
pub mod tls;

use axum::extract::FromRef;
use sqlx::{Pool, Sqlite};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub auth_db: Pool<Sqlite>,
    pub files_db: Pool<Sqlite>,
    pub csrf: middleware::csrf::CsrfProtection,
    pub pq_secret_key: Arc<crypto::pq_hybrid::HybridSecretKey>,
    pub pq_public_key: Arc<crypto::pq_hybrid::HybridPublicKey>,
}

impl FromRef<AppState> for Pool<Sqlite> {
    fn from_ref(state: &AppState) -> Self {
        state.auth_db.clone()
    }
}
