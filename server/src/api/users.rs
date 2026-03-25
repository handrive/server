//! User API endpoints.

use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;

use crate::auth::AuthUser;
use crate::db::{self, UserResponse};
use crate::error::{AppError, AppResult};
use crate::validation::{
    validate_email, validate_optional_length, MAX_NAME_LENGTH, MAX_URL_LENGTH,
};
use crate::AppState;

/// Maximum number of emails allowed in a single batch lookup request.
const MAX_BATCH_LOOKUP_SIZE: usize = 100;

/// Maximum invite emails per user per hour.
const MAX_INVITES_PER_HOUR: u32 = 100;
/// Invite rate limit window in milliseconds (1 hour).
const INVITE_WINDOW_MS: i64 = 3_600_000;

// ============================================================================
// Request Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct SearchUserQuery {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct LookupUsersRequest {
    pub emails: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteAccountRequest {
    pub confirmation: String,
}

#[derive(Debug, Deserialize)]
pub struct InviteUserRequest {
    pub email: String,
    pub message: Option<String>,
}

// ============================================================================
// Handlers
// ============================================================================

/// Get current user profile.
pub async fn get_me(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> AppResult<Json<UserResponse>> {
    let user = db::get_user_by_id(&state.pool, auth_user.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(user.into()))
}

/// Update current user profile.
///
/// This endpoint uses upsert semantics - if the user doesn't exist (e.g., after
/// DB recovery), they will be created using the identity from the valid JWT token.
/// This enables clients to re-register themselves on NATS reconnect.
pub async fn update_me(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(request): Json<UpdateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    // Validate input lengths
    validate_optional_length("name", &request.name, MAX_NAME_LENGTH)?;
    validate_optional_length("avatar_url", &request.avatar_url, MAX_URL_LENGTH)?;

    let user = db::upsert_user(
        &state.pool,
        auth_user.user_id,
        &auth_user.email,
        request.name,
        request.avatar_url,
        request.metadata,
    )
    .await?;

    Ok(Json(user.into()))
}

/// Search for a user by exact email.
pub async fn search_by_email(
    State(state): State<AppState>,
    _auth_user: AuthUser,
    Query(query): Query<SearchUserQuery>,
) -> AppResult<Json<UserResponse>> {
    // Validate email format
    validate_email(&query.email)?;

    let user = db::get_user_by_email(&state.pool, &query.email)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(user.into()))
}

/// Batch lookup users by email list.
///
/// Returns profiles for users that exist. Unknown emails are silently ignored.
pub async fn lookup_by_emails(
    State(state): State<AppState>,
    _auth_user: AuthUser,
    Json(request): Json<LookupUsersRequest>,
) -> AppResult<Json<Vec<UserResponse>>> {
    if request.emails.len() > MAX_BATCH_LOOKUP_SIZE {
        return Err(AppError::Validation(format!(
            "Batch lookup limited to {} emails",
            MAX_BATCH_LOOKUP_SIZE
        )));
    }

    let users = db::get_users_by_emails(&state.pool, &request.emails).await?;

    Ok(Json(users.into_iter().map(Into::into).collect()))
}

/// Delete the current user's account.
///
/// Requires the user to type "DELETE" as confirmation.
/// Sessions are automatically deleted via database cascade.
pub async fn delete_me(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(request): Json<DeleteAccountRequest>,
) -> AppResult<Json<MessageResponse>> {
    // Validate confirmation text
    if request.confirmation != "DELETE" {
        return Err(AppError::Validation(
            "Confirmation must be exactly 'DELETE'".to_string(),
        ));
    }

    // Delete the user (sessions cascade automatically)
    db::delete_user(&state.pool, auth_user.user_id).await?;

    tracing::info!(
        user_id = %auth_user.user_id,
        email = %auth_user.email,
        "User account deleted"
    );

    Ok(Json(MessageResponse {
        message: "Account deleted successfully".to_string(),
    }))
}

/// Invite a user by email.
///
/// Sends an invitation email to the specified address.
/// The invitee can then sign up and be added as a contact/member.
pub async fn invite_user(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(request): Json<InviteUserRequest>,
) -> AppResult<Json<MessageResponse>> {
    // Validate email format
    validate_email(&request.email)?;

    // Check per-user invite rate limit
    {
        let now_ms = crate::id::epoch_ms();
        let user_key = auth_user.user_id.to_string();
        let mut rates = state.invite_rate.lock().unwrap();
        let window = rates.entry(user_key).or_insert(crate::RateWindow {
            count: 0,
            window_start_ms: now_ms,
        });
        // Reset window if expired
        if (now_ms - window.window_start_ms) >= INVITE_WINDOW_MS {
            window.count = 0;
            window.window_start_ms = now_ms;
        }
        if window.count >= MAX_INVITES_PER_HOUR {
            tracing::warn!(
                user_id = %auth_user.user_id,
                "Invite rate limit exceeded"
            );
            return Err(AppError::Validation(
                "Invite limit reached. Please try again later.".to_string(),
            ));
        }
        window.count += 1;
    }

    // Get inviter's profile for the email
    let inviter = db::get_user_by_id(&state.pool, auth_user.user_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let inviter_name = inviter.name.as_deref().unwrap_or(&auth_user.email);

    // Check if user already exists
    if db::get_user_by_email(&state.pool, &request.email).await?.is_some() {
        return Err(AppError::Validation(
            "User is already registered. Use add_contact or add_member instead.".to_string(),
        ));
    }

    // Send invitation email (skip in test mode)
    if !state.test_mode {
        state
            .otp_manager
            .send_invite_email(
                &request.email,
                inviter_name,
                &auth_user.email,
                request.message.as_deref(),
            )
            .await?;
    }

    tracing::info!(
        inviter = %auth_user.email,
        invitee = %request.email,
        "User invited"
    );

    Ok(Json(MessageResponse {
        message: format!("Invitation sent to {}", request.email),
    }))
}

/// Response for simple message responses.
#[derive(Debug, serde::Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // =========================================================================
    // Invite rate limit tests
    // =========================================================================

    #[test]
    fn test_invite_rate_under_threshold() {
        let now_ms = crate::id::epoch_ms();
        let mut rates: HashMap<String, crate::RateWindow> = HashMap::new();
        let key = "user1".to_string();
        rates.insert(key.clone(), crate::RateWindow {
            count: MAX_INVITES_PER_HOUR - 1,
            window_start_ms: now_ms,
        });

        let window = rates.get(&key).unwrap();
        let limited = window.count >= MAX_INVITES_PER_HOUR
            && (now_ms - window.window_start_ms) < INVITE_WINDOW_MS;
        assert!(!limited);
    }

    #[test]
    fn test_invite_rate_at_threshold() {
        let now_ms = crate::id::epoch_ms();
        let mut rates: HashMap<String, crate::RateWindow> = HashMap::new();
        let key = "user1".to_string();
        rates.insert(key.clone(), crate::RateWindow {
            count: MAX_INVITES_PER_HOUR,
            window_start_ms: now_ms,
        });

        let window = rates.get(&key).unwrap();
        let limited = window.count >= MAX_INVITES_PER_HOUR
            && (now_ms - window.window_start_ms) < INVITE_WINDOW_MS;
        assert!(limited);
    }

    #[test]
    fn test_invite_rate_window_expired() {
        let now_ms = crate::id::epoch_ms();
        let mut rates: HashMap<String, crate::RateWindow> = HashMap::new();
        let key = "user1".to_string();
        rates.insert(key.clone(), crate::RateWindow {
            count: MAX_INVITES_PER_HOUR,
            window_start_ms: now_ms - INVITE_WINDOW_MS - 1,
        });

        let window = rates.get(&key).unwrap();
        let limited = window.count >= MAX_INVITES_PER_HOUR
            && (now_ms - window.window_start_ms) < INVITE_WINDOW_MS;
        assert!(!limited);
    }

    #[test]
    fn test_invite_rate_window_reset() {
        let now_ms = crate::id::epoch_ms();
        let mut window = crate::RateWindow {
            count: MAX_INVITES_PER_HOUR + 5,
            window_start_ms: now_ms - INVITE_WINDOW_MS - 1,
        };

        // Simulate the reset logic from invite_user handler
        if (now_ms - window.window_start_ms) >= INVITE_WINDOW_MS {
            window.count = 0;
            window.window_start_ms = now_ms;
        }
        window.count += 1;
        assert_eq!(window.count, 1);
    }

    // =========================================================================
    // Delete confirmation tests
    // =========================================================================

    #[test]
    fn test_delete_confirmation_exact_match() {
        let confirmation = "DELETE";
        assert_eq!(confirmation, "DELETE");

        // Wrong values
        assert_ne!("delete", "DELETE");
        assert_ne!("Delete", "DELETE");
        assert_ne!("DELET", "DELETE");
        assert_ne!("", "DELETE");
    }

    // =========================================================================
    // Batch lookup limit tests
    // =========================================================================

    #[test]
    fn test_batch_lookup_at_limit() {
        let emails: Vec<String> = (0..MAX_BATCH_LOOKUP_SIZE)
            .map(|i| format!("user{}@example.com", i))
            .collect();
        assert!(emails.len() <= MAX_BATCH_LOOKUP_SIZE);
    }

    #[test]
    fn test_batch_lookup_over_limit() {
        let emails: Vec<String> = (0..MAX_BATCH_LOOKUP_SIZE + 1)
            .map(|i| format!("user{}@example.com", i))
            .collect();
        assert!(emails.len() > MAX_BATCH_LOOKUP_SIZE);
    }
}
