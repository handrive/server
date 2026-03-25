//! Database models for Handrive server.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// User model.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub google_id: Option<String>,
    pub apple_id: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: i64,
    pub updated_at: i64,
    pub updated_by: Option<Uuid>,
}

/// User response (public fields only).
#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: i64,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            name: user.name,
            avatar_url: user.avatar_url,
            metadata: user.metadata,
            created_at: user.created_at,
        }
    }
}

/// OTP code model.
#[derive(Debug, Clone, FromRow)]
pub struct OtpCode {
    pub id: Uuid,
    pub email: String,
    pub code: String,
    pub expires_at: i64,
    pub used: bool,
    pub created_at: i64,
}

/// Session model (refresh token).
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub last_used_at: i64,
}

/// Session response (for listing sessions).
#[derive(Debug, Clone, Serialize)]
pub struct SessionResponse {
    pub id: Uuid,
    pub created_at: i64,
    pub last_used_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_current: Option<bool>,
}

impl Session {
    pub fn to_response(&self, current_session_id: Option<Uuid>) -> SessionResponse {
        SessionResponse {
            id: self.id,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
            is_current: current_session_id.map(|cid| cid == self.id),
        }
    }
}
