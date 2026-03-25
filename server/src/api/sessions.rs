//! Session API endpoints.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::db::{self, SessionResponse};
use crate::error::AppResult;
use crate::AppState;

// ============================================================================
// Response Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct SessionsResponse {
    pub sessions: Vec<SessionResponse>,
}

#[derive(Debug, Serialize)]
pub struct DeleteSessionsResponse {
    pub deleted: u64,
}

#[derive(Debug, Serialize)]
pub struct NatsCredentialsResponse {
    pub credentials: String,
    /// NATS server URL for client connections.
    pub nats_url: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub deleted: bool,
}

// ============================================================================
// Handlers
// ============================================================================

/// List all active sessions for the current user.
pub async fn list_sessions(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> AppResult<Json<SessionsResponse>> {
    let sessions = db::get_user_sessions(&state.pool, auth_user.user_id).await?;

    // Note: We don't have the current session ID in this context,
    // so we can't mark which one is current. The client should track this.
    let session_responses: Vec<SessionResponse> = sessions
        .into_iter()
        .map(|s| s.to_response(None))
        .collect();

    Ok(Json(SessionsResponse {
        sessions: session_responses,
    }))
}

/// Delete a specific session.
pub async fn delete_session(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(session_id): Path<Uuid>,
) -> AppResult<Json<DeleteResponse>> {
    db::delete_session(&state.pool, session_id, auth_user.user_id).await?;

    Ok(Json(DeleteResponse { deleted: true }))
}

/// Delete all sessions for the current user.
///
/// Note: This will log out the user from all devices including the current one.
/// The client will need to re-authenticate.
pub async fn delete_other_sessions(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> AppResult<Json<DeleteSessionsResponse>> {
    let deleted = db::delete_all_sessions_for_user(&state.pool, auth_user.user_id).await?;

    Ok(Json(DeleteSessionsResponse { deleted }))
}

/// Get NATS credentials for the current user.
pub async fn get_nats_credentials(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> AppResult<Json<NatsCredentialsResponse>> {
    let credentials = state.nats_jwt.generate_user_credentials(&auth_user.user_id)?;

    Ok(Json(NatsCredentialsResponse {
        credentials,
        nats_url: state.nats_public_url.clone(),
    }))
}
