//! Handrive Server Library
//!
//! Backend service for the Handrive P2P file sharing system.
//! Handles user authentication and NATS credential provisioning.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::FromRef;

pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod env_utils;
pub mod error;
pub mod id;
pub mod logging;
pub mod middleware;
pub mod nats;
pub mod validation;

// Re-export commonly used types
pub use auth::JwtManager;
pub use auth::IdentityGenerator;
pub use config::Config;
pub use error::AppError;

use auth::{apple::AppleOAuth, google::GoogleOAuth, otp::OtpManager};
use nats::NatsJwtGenerator;

/// Tracks failed OTP attempts per email to prevent brute-force attacks.
#[derive(Debug, Clone)]
pub struct OtpAttempt {
    pub count: u32,
    pub first_attempt_ms: i64,
}

/// Thread-safe OTP attempt tracker.
pub type OtpAttemptTracker = Arc<Mutex<HashMap<String, OtpAttempt>>>;

/// Tracks rate-limited actions per user (e.g., invites).
#[derive(Debug, Clone)]
pub struct RateWindow {
    pub count: u32,
    pub window_start_ms: i64,
}

/// Thread-safe per-user rate tracker (user_id string -> rate window).
pub type UserRateTracker = Arc<Mutex<HashMap<String, RateWindow>>>;

/// Application state shared across all handlers.
#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub jwt_manager: JwtManager,
    pub google_oauth: GoogleOAuth,
    /// Apple Sign In OAuth client (optional - only available if configured).
    pub apple_oauth: Option<AppleOAuth>,
    pub otp_manager: OtpManager,
    pub nats_jwt: NatsJwtGenerator,
    /// Identity credential generator for NATS message authentication.
    pub identity_generator: IdentityGenerator,
    /// NATS server URL for health checks (internal).
    pub nats_url: String,
    /// Public-facing NATS URL returned to clients.
    pub nats_public_url: String,
    /// Test mode: disables real email sending, returns OTP in response.
    pub test_mode: bool,
    /// Demo account email for App Store review (lowercase, trimmed).
    pub demo_email: Option<String>,
    /// Demo account static OTP code.
    pub demo_otp: Option<String>,
    /// OTP brute-force attempt tracker (email -> attempts).
    pub otp_attempts: OtpAttemptTracker,
    /// Per-user invite rate tracker (user_id -> rate window).
    pub invite_rate: UserRateTracker,
}

// Implement FromRef for extractors that need specific parts of the state
impl FromRef<AppState> for JwtManager {
    fn from_ref(state: &AppState) -> Self {
        state.jwt_manager.clone()
    }
}

impl FromRef<AppState> for sqlx::PgPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}

