//! Router setup for the REST API.

use std::time::Duration;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{delete, get, patch, post},
    Json, Router,
};
use serde::Serialize;

use crate::api::{auth, sessions, users};
use crate::AppState;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    database: &'static str,
    nats: &'static str,
}

async fn health(State(state): State<AppState>) -> Result<Json<HealthResponse>, StatusCode> {
    // Verify database connectivity
    let db_ok = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();

    // Verify NATS connectivity (actual NATS protocol check)
    let nats_ok = check_nats_connectivity(&state.nats_url).await;

    if db_ok && nats_ok {
        Ok(Json(HealthResponse {
            status: "ok",
            database: "connected",
            nats: "connected",
        }))
    } else {
        if !db_ok {
            tracing::error!("Health check failed: database unreachable");
        }
        if !nats_ok {
            tracing::error!(url = %state.nats_url, "Health check failed: NATS unreachable");
        }
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// Check NATS server connectivity using the NATS protocol.
async fn check_nats_connectivity(nats_url: &str) -> bool {
    // Connect with timeout - this verifies NATS is actually responding
    match tokio::time::timeout(
        Duration::from_secs(2),
        async_nats::connect(nats_url),
    )
    .await
    {
        Ok(Ok(client)) => {
            // Connection successful, flush to ensure server is responsive
            let healthy = client.flush().await.is_ok();
            // Close cleanly
            drop(client);
            healthy
        }
        Ok(Err(_)) | Err(_) => false,
    }
}

/// Create the main API router.
pub fn create_router() -> Router<AppState> {
    Router::new()
        // Health check
        .route("/api/health", get(health))
        // Desktop OAuth callback (redirects to deep link)
        .route("/auth/callback", get(auth::desktop_oauth_callback))
        // Auth endpoints
        .route("/api/auth/status", get(auth::auth_status))
        .route("/api/auth/google/url", get(auth::google_auth_url))
        .route("/api/auth/google/callback", post(auth::google_callback))
        // Apple OAuth (optional - only works if configured)
        .route("/api/auth/apple/url", get(auth::apple_auth_url))
        .route("/api/auth/apple/callback", post(auth::apple_callback))
        // Apple sends POST (not GET like Google)
        .route("/auth/apple/callback", post(auth::desktop_apple_callback))
        .route("/api/auth/otp/request", post(auth::otp_request))
        .route("/api/auth/otp/verify", post(auth::otp_verify))
        .route("/api/auth/refresh", post(auth::refresh_token))
        .route("/api/auth/logout", post(auth::logout))
        // User endpoints
        .route("/api/users/me", get(users::get_me))
        .route("/api/users/me", patch(users::update_me))
        .route("/api/users/me", delete(users::delete_me))
        .route("/api/users/search", get(users::search_by_email))
        .route("/api/users/lookup", post(users::lookup_by_emails))
        .route("/api/users/invite", post(users::invite_user))
        // Session endpoints
        .route("/api/sessions", get(sessions::list_sessions))
        .route("/api/sessions/:id", delete(sessions::delete_session))
        .route("/api/sessions", delete(sessions::delete_other_sessions))
        // NATS credentials
        .route("/api/nats/credentials", get(sessions::get_nats_credentials))
}
