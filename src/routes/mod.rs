use axum::{
    Json, Router,
    extract::State,
    middleware as axum_middleware,
    routing::{get, post},
};

use tower_http::services::ServeDir;

use crate::AppState;
use crate::middleware::{cpr, csrf, rate_limit};

pub mod account;
pub mod admin;
pub mod auth;

pub fn create_app(
    app_state: AppState,
    csrf_protection: csrf::CsrfProtection,
    rate_limiter: rate_limit::RateLimiter,
) -> Router {
    // Rate-limited routes (TOTP verification and login)
    let rate_limited_routes = Router::new()
        .route("/api/login/totp/verify", post(auth::totp_verify))
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout))
        .layer(axum_middleware::from_fn(move |jar, req, next| {
            let limiter = rate_limiter.clone();
            async move { limiter.middleware(jar, req, next).await }
        }));

    // Authenticated routes that require CPR submission
    // These routes are protected by CSRF + Auth + CPR verification
    let cpr_protected_routes = Router::new()
        .route("/api/admin/check", get(admin::check_admin_access))
        // Future authenticated endpoints will go here
        // Example: .route("/api/account/profile", get(account::get_profile))
        .layer(axum_middleware::from_fn_with_state(
            app_state.clone(),
            cpr::require_cpr,
        ))
        .layer(axum_middleware::from_fn({
            let csrf = csrf_protection.clone();
            move |req, next| {
                let csrf = csrf.clone();
                async move { csrf.middleware(req, next).await }
            }
        }));

    // Admin routes (protected by CSRF + Auth + Admin verification)
    let admin_routes = Router::new()
        .route("/api/admin/users", get(admin::list_users))
        .route(
            "/api/admin/users/{account_id}",
            axum::routing::delete(admin::delete_user),
        )
        .layer(axum_middleware::from_fn_with_state(
            app_state.clone(),
            crate::middleware::auth::require_admin,
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
        .route("/api/account/cpr", post(account::submit_cpr))
        .route(
            "/api/account/cpr/verify",
            post(account::verify_cpr_for_login),
        )
        .layer(axum_middleware::from_fn({
            let csrf = csrf_protection.clone();
            move |req, next| {
                let csrf = csrf.clone();
                async move { csrf.middleware(req, next).await }
            }
        }));

    // CSRF-protected routes (all POST routes that don't require auth)
    let csrf_protected_routes = Router::new()
        .route("/api/signup", post(auth::signup))
        .route("/api/login/totp/setup", post(auth::totp_setup))
        .route(
            "/api/account/{account_id}/status",
            get(account::get_account_status),
        )
        .layer(axum_middleware::from_fn(move |req, next| {
            let csrf = csrf_protection.clone();
            async move { csrf.middleware(req, next).await }
        }));

    // Combine all routes
    Router::new()
        .route("/health", get(health_check))
        .route("/api/csrf-token", get(get_csrf_token))
        .route("/api/auth/status", get(auth::auth_status))
        .merge(rate_limited_routes)
        .merge(csrf_protected_routes)
        .merge(cpr_submission_route)
        .merge(cpr_protected_routes)
        .merge(admin_routes)
        .fallback_service(ServeDir::new("static"))
        .with_state(app_state)
}

async fn health_check() -> &'static str {
    "OK"
}

async fn get_csrf_token(State(state): State<AppState>) -> Json<serde_json::Value> {
    let token = state.csrf.generate_token();
    Json(serde_json::json!({ "csrf_token": token }))
}
