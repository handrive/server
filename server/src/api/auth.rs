//! Authentication API endpoints.

use axum::{
    extract::{Form, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::auth::identity::IdentityCredential;
use crate::auth::{otp::OtpManager, AuthUser, OptionalAuthUser};
use crate::db::{self, User, UserResponse};
use crate::error::{AppError, AppResult};
use crate::validation::{validate_email, validate_length, MAX_OTP_CODE_LENGTH};
use crate::AppState;

/// Maximum OTP verification attempts per email before lockout.
const MAX_OTP_ATTEMPTS: u32 = 5;
/// OTP lockout window in seconds.
const OTP_LOCKOUT_SECS: u64 = 300; // 5 minutes

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct AuthUrlResponse {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct GoogleAuthQuery {
    /// Optional custom redirect URI (for desktop apps using deep links).
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GoogleCallbackRequest {
    pub code: String,
    /// Optional redirect URI that was used during authorization.
    /// Must match what was used to get the auth URL.
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AppleAuthQuery {
    /// Optional custom redirect URI (for desktop apps using deep links).
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AppleCallbackRequest {
    pub code: String,
    /// Optional ID token (Apple may provide this).
    pub id_token: Option<String>,
    /// Optional redirect URI that was used during authorization.
    /// Must match what was used to get the auth URL.
    pub redirect_uri: Option<String>,
}

/// Query parameters for desktop OAuth callback redirect (Google uses GET).
#[derive(Debug, Deserialize)]
pub struct DesktopCallbackQuery {
    pub code: String,
    #[allow(dead_code)]
    pub state: Option<String>,
}

/// Form data for Apple desktop OAuth callback (Apple uses POST).
#[derive(Debug, Deserialize)]
pub struct AppleDesktopCallbackForm {
    pub code: String,
    #[allow(dead_code)]
    pub state: Option<String>,
    /// ID token containing user info (Apple sends this on first sign-in).
    pub id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OtpRequestBody {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct OtpVerifyRequest {
    pub email: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub user: UserResponse,
    pub nats_credentials: String,
    /// NATS server URL for client connections.
    pub nats_url: String,
    pub is_new_user: bool,
    /// Server-signed identity credential for NATS message authentication.
    pub identity_credential: IdentityCredential,
    /// Server's public key for verifying credentials (base64 encoded).
    pub server_public_key: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub refresh_expires_in: u64,
    /// Refreshed identity credential for NATS message authentication.
    pub identity_credential: IdentityCredential,
    /// Server's public key for verifying credentials (base64 encoded).
    pub server_public_key: String,
}

pub use super::users::MessageResponse;

#[derive(Debug, Serialize)]
pub struct AuthStatusResponse {
    pub authenticated: bool,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
}

/// OTP request response (includes code in test mode).
#[derive(Debug, Serialize)]
pub struct OtpRequestResponse {
    pub message: String,
    /// OTP code returned only in test mode for E2E testing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Maximum number of active sessions per user.
const MAX_SESSIONS_PER_USER: i64 = 100;

/// Create tokens and session for a user.
///
/// Returns (access_token, refresh_token).
/// Enforces a maximum session limit per user, evicting the oldest sessions.
async fn create_user_session(state: &AppState, user: &User) -> AppResult<(String, String)> {
    let access_token = state.jwt_manager.generate_access_token(user.id, &user.email)?;
    let refresh_token = state.jwt_manager.generate_refresh_token();
    let token_hash = state.jwt_manager.hash_refresh_token(&refresh_token);

    db::create_session(
        &state.pool,
        user.id,
        &token_hash,
        state.jwt_manager.refresh_ttl_ms(),
    )
    .await?;

    // Evict oldest sessions if over limit
    let evicted = db::enforce_session_limit(&state.pool, user.id, MAX_SESSIONS_PER_USER).await?;
    if evicted > 0 {
        tracing::info!(user_id = %user.id, evicted = evicted, "Evicted old sessions (limit: {})", MAX_SESSIONS_PER_USER);
    }

    Ok((access_token, refresh_token))
}

// ============================================================================
// Handlers
// ============================================================================

/// Get current authentication status.
pub async fn auth_status(auth_user: OptionalAuthUser) -> Json<AuthStatusResponse> {
    match auth_user.0 {
        Some(user) => Json(AuthStatusResponse {
            authenticated: true,
            user_id: Some(user.user_id.to_string()),
            user_email: Some(user.email),
        }),
        None => Json(AuthStatusResponse {
            authenticated: false,
            user_id: None,
            user_email: None,
        }),
    }
}

/// Get Google OAuth authorization URL.
pub async fn google_auth_url(
    State(state): State<AppState>,
    Query(query): Query<GoogleAuthQuery>,
) -> AppResult<Json<AuthUrlResponse>> {
    let csrf_state = state.jwt_manager.generate_csrf_state();
    let url_response = state
        .google_oauth
        .get_auth_url(query.redirect_uri.as_deref(), &csrf_state)?;
    Ok(Json(AuthUrlResponse {
        url: url_response.url,
    }))
}

/// Handle Google OAuth callback.
pub async fn google_callback(
    State(state): State<AppState>,
    Json(request): Json<GoogleCallbackRequest>,
) -> AppResult<Json<AuthResponse>> {
    // Exchange code for user info
    let google_user = state
        .google_oauth
        .exchange_code(&request.code, request.redirect_uri.as_deref())
        .await?;

    // Upsert user in database
    let google_info = db::GoogleUserInfo {
        email: google_user.email.clone(),
        name: google_user.name.clone(),
        avatar_url: google_user.avatar_url.clone(),
        google_id: google_user.id,
    };

    let (user, is_new) = db::upsert_google_user(&state.pool, google_info).await?;

    // Create session and generate tokens
    let (access_token, refresh_token) = create_user_session(&state, &user).await?;

    // Generate NATS credentials
    let nats_credentials = state.nats_jwt.generate_user_credentials(&user.id)?;

    // Generate identity credential (same TTL as access token)
    let identity_credential = state.identity_generator.create_credential(
        &user.email,
        state.jwt_manager.access_ttl_secs() as i64,
    );

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
        expires_in: state.jwt_manager.access_ttl_secs(),
        user: user.into(),
        nats_credentials,
        nats_url: state.nats_public_url.clone(),
        is_new_user: is_new,
        identity_credential,
        server_public_key: state.identity_generator.public_key().to_string(),
    }))
}

/// Handle desktop OAuth callback by redirecting to deep link.
///
/// This endpoint is called by Google OAuth after user grants permission.
/// It receives the authorization code and redirects to the desktop app via deep link.
pub async fn desktop_oauth_callback(
    State(state): State<AppState>,
    Query(query): Query<DesktopCallbackQuery>,
) -> axum::response::Html<String> {
    // Verify CSRF state token
    if let Some(ref csrf_state) = query.state {
        if !state.jwt_manager.verify_csrf_state(csrf_state) {
            tracing::warn!("Invalid or expired CSRF state in Google desktop callback");
            return axum::response::Html(oauth_error_html("Invalid or expired authentication state. Please try signing in again."));
        }
    } else {
        tracing::warn!("Missing CSRF state in Google desktop callback");
        return axum::response::Html(oauth_error_html("Missing authentication state. Please try signing in again."));
    }

    let redirect_url = format!(
        "handrive://auth/callback?code={}",
        urlencoding::encode(&query.code)
    );

    axum::response::Html(oauth_redirect_html(&redirect_url))
}

/// Get Apple Sign In authorization URL.
pub async fn apple_auth_url(
    State(state): State<AppState>,
    Query(query): Query<AppleAuthQuery>,
) -> AppResult<Json<AuthUrlResponse>> {
    let apple_oauth = state
        .apple_oauth
        .as_ref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Apple Sign In not configured")))?;

    let csrf_state = state.jwt_manager.generate_csrf_state();
    let url_response = apple_oauth.get_auth_url(query.redirect_uri.as_deref(), &csrf_state)?;
    Ok(Json(AuthUrlResponse {
        url: url_response.url,
    }))
}

/// Handle Apple Sign In callback.
pub async fn apple_callback(
    State(state): State<AppState>,
    Json(request): Json<AppleCallbackRequest>,
) -> AppResult<Json<AuthResponse>> {
    let apple_oauth = state
        .apple_oauth
        .as_ref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Apple Sign In not configured")))?;

    // Exchange code for user info
    let apple_user = apple_oauth
        .exchange_code(
            &request.code,
            request.id_token.as_deref(),
            request.redirect_uri.as_deref(),
        )
        .await?;

    // Upsert user in database
    let apple_info = db::AppleUserInfo {
        email: apple_user.email.clone(),
        name: apple_user.name.clone(),
        apple_id: apple_user.id,
    };

    let (user, is_new) = db::upsert_apple_user(&state.pool, apple_info).await?;

    // Create session and generate tokens
    let (access_token, refresh_token) = create_user_session(&state, &user).await?;

    // Generate NATS credentials
    let nats_credentials = state.nats_jwt.generate_user_credentials(&user.id)?;

    // Generate identity credential (same TTL as access token)
    let identity_credential = state.identity_generator.create_credential(
        &user.email,
        state.jwt_manager.access_ttl_secs() as i64,
    );

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
        expires_in: state.jwt_manager.access_ttl_secs(),
        user: user.into(),
        nats_credentials,
        nats_url: state.nats_public_url.clone(),
        is_new_user: is_new,
        identity_credential,
        server_public_key: state.identity_generator.public_key().to_string(),
    }))
}

/// Handle desktop Apple OAuth callback by redirecting to deep link.
///
/// This endpoint is called by Apple Sign In after user grants permission.
/// Apple sends a POST request with form data (not GET with query params like Google).
/// It receives the authorization code and redirects to the desktop app via deep link.
pub async fn desktop_apple_callback(
    State(state): State<AppState>,
    Form(form): Form<AppleDesktopCallbackForm>,
) -> axum::response::Html<String> {
    // Verify CSRF state token
    if let Some(ref csrf_state) = form.state {
        if !state.jwt_manager.verify_csrf_state(csrf_state) {
            tracing::warn!("Invalid or expired CSRF state in Apple desktop callback");
            return axum::response::Html(oauth_error_html("Invalid or expired authentication state. Please try signing in again."));
        }
    } else {
        tracing::warn!("Missing CSRF state in Apple desktop callback");
        return axum::response::Html(oauth_error_html("Missing authentication state. Please try signing in again."));
    }

    // Build redirect URL with code and optional id_token
    let mut redirect_url = format!(
        "handrive://auth/callback?code={}&provider=apple",
        urlencoding::encode(&form.code)
    );
    if let Some(ref id_token) = form.id_token {
        redirect_url.push_str(&format!("&id_token={}", urlencoding::encode(id_token)));
    }

    axum::response::Html(oauth_redirect_html(&redirect_url))
}

/// Request OTP code.
pub async fn otp_request(
    State(state): State<AppState>,
    Json(request): Json<OtpRequestBody>,
) -> AppResult<Json<OtpRequestResponse>> {
    // Validate email format and length
    validate_email(&request.email)?;

    let normalized_email = request.email.trim().to_lowercase();

    // Check if this is the demo account (for App Store review)
    let is_demo_account = state.demo_email.as_ref().is_some_and(|demo| demo == &normalized_email)
        && state.demo_otp.is_some();

    if is_demo_account {
        tracing::info!(email = %normalized_email, "Demo account OTP requested - use static code");
        return Ok(Json(OtpRequestResponse {
            message: format!("Verification code sent to {}", request.email),
            code: None,
        }));
    }

    // Generate OTP code
    let code = OtpManager::generate_code();

    // Store OTP in database
    db::create_otp_code(
        &state.pool,
        &request.email,
        &code,
        crate::auth::otp::OTP_TTL_MS,
    )
    .await?;

    // In test mode, skip email and return the code
    if state.test_mode {
        tracing::info!(email = %request.email, "TEST MODE: OTP code generated (not emailed)");
        return Ok(Json(OtpRequestResponse {
            message: format!("TEST MODE: Verification code for {}", request.email),
            code: Some(code),
        }));
    }

    // Send email
    state.otp_manager.send_otp_email(&request.email, &code).await?;

    Ok(Json(OtpRequestResponse {
        message: format!("Verification code sent to {}", request.email),
        code: None,
    }))
}

/// Verify OTP code and authenticate.
pub async fn otp_verify(
    State(state): State<AppState>,
    Json(request): Json<OtpVerifyRequest>,
) -> AppResult<Json<AuthResponse>> {
    // Validate inputs
    validate_email(&request.email)?;
    validate_length("code", &request.code, MAX_OTP_CODE_LENGTH)?;

    let normalized_email = request.email.trim().to_lowercase();

    // Check brute-force lockout before attempting verification
    {
        let now_ms = crate::id::epoch_ms();
        let lockout_window_ms = (OTP_LOCKOUT_SECS * 1000) as i64;
        let attempts = state.otp_attempts.lock().unwrap();
        if let Some(attempt) = attempts.get(&normalized_email) {
            if attempt.count >= MAX_OTP_ATTEMPTS
                && (now_ms - attempt.first_attempt_ms) < lockout_window_ms
            {
                tracing::warn!(
                    email = %normalized_email,
                    attempts = attempt.count,
                    "OTP verification locked out due to too many failed attempts"
                );
                return Err(AppError::Validation(
                    "Too many failed attempts. Please try again later.".to_string(),
                ));
            }
        }
    }

    // Check if this is the demo account with static OTP (for App Store review)
    let is_demo_valid = state.demo_email.as_ref().is_some_and(|demo| demo == &normalized_email)
        && state.demo_otp.as_ref().is_some_and(|otp| otp == &request.code);

    let valid = if is_demo_valid {
        tracing::info!(email = %normalized_email, "Demo account login successful");
        true
    } else {
        // Verify OTP code from database
        db::verify_otp_code(&state.pool, &request.email, &request.code).await?
    };

    if !valid {
        // Track failed attempt
        let now_ms = crate::id::epoch_ms();
        let lockout_window_ms = (OTP_LOCKOUT_SECS * 1000) as i64;
        let mut attempts = state.otp_attempts.lock().unwrap();
        let attempt = attempts.entry(normalized_email.clone()).or_insert(crate::OtpAttempt {
            count: 0,
            first_attempt_ms: now_ms,
        });
        // Reset window if expired
        if (now_ms - attempt.first_attempt_ms) >= lockout_window_ms {
            attempt.count = 0;
            attempt.first_attempt_ms = now_ms;
        }
        attempt.count += 1;
        return Err(AppError::InvalidCredentials);
    }

    // Clear failed attempts on successful verification
    {
        let mut attempts = state.otp_attempts.lock().unwrap();
        attempts.remove(&normalized_email);
    }

    // Upsert user
    let (user, is_new) = db::upsert_otp_user(&state.pool, &request.email).await?;

    // Create session and generate tokens
    let (access_token, refresh_token) = create_user_session(&state, &user).await?;

    // Generate NATS credentials
    let nats_credentials = state.nats_jwt.generate_user_credentials(&user.id)?;

    // Generate identity credential (same TTL as access token)
    let identity_credential = state.identity_generator.create_credential(
        &user.email,
        state.jwt_manager.access_ttl_secs() as i64,
    );

    Ok(Json(AuthResponse {
        access_token,
        refresh_token,
        expires_in: state.jwt_manager.access_ttl_secs(),
        user: user.into(),
        nats_credentials,
        nats_url: state.nats_public_url.clone(),
        is_new_user: is_new,
        identity_credential,
        server_public_key: state.identity_generator.public_key().to_string(),
    }))
}

/// Refresh access token with token rotation.
///
/// This implements refresh token rotation for improved security:
/// - The old refresh token is invalidated (session deleted)
/// - A new refresh token is issued with each refresh
/// - If an old token is reused, it indicates potential token theft
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(request): Json<RefreshTokenRequest>,
) -> AppResult<Json<RefreshResponse>> {
    let old_token_hash = state.jwt_manager.hash_refresh_token(&request.refresh_token);

    // Find and validate session
    let session = db::get_session_by_token(&state.pool, &old_token_hash)
        .await?
        .ok_or(AppError::InvalidCredentials)?;

    // Get user
    let user = db::get_user_by_id(&state.pool, session.user_id)
        .await?
        .ok_or(AppError::InvalidCredentials)?;

    // Delete old session (invalidate old refresh token)
    db::delete_session(&state.pool, session.id, user.id).await?;

    // Create new session and generate tokens
    let (access_token, new_refresh_token) = create_user_session(&state, &user).await?;

    // Generate fresh identity credential
    let identity_credential = state.identity_generator.create_credential(
        &user.email,
        state.jwt_manager.access_ttl_secs() as i64,
    );

    tracing::debug!(user_id = %user.id, "Refresh token rotated");

    Ok(Json(RefreshResponse {
        access_token,
        refresh_token: new_refresh_token,
        expires_in: state.jwt_manager.access_ttl_secs(),
        refresh_expires_in: state.jwt_manager.refresh_ttl_secs(),
        identity_credential,
        server_public_key: state.identity_generator.public_key().to_string(),
    }))
}

/// Logout (revoke all sessions for the user).
pub async fn logout(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> AppResult<Json<MessageResponse>> {
    // Delete all sessions for this user
    let count = db::delete_all_sessions_for_user(&state.pool, auth_user.user_id).await?;

    tracing::info!(user_id = %auth_user.user_id, sessions_deleted = count, "User logged out");

    Ok(Json(MessageResponse {
        message: "Logged out successfully".to_string(),
    }))
}

// ============================================================================
// HTML Helpers (XSS-safe)
// ============================================================================

/// HTML-escape a string to prevent XSS.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Generate XSS-safe OAuth redirect HTML.
///
/// Uses a `<meta>` tag for the redirect URL stored in a data attribute,
/// avoiding direct interpolation into JavaScript context.
fn oauth_redirect_html(redirect_url: &str) -> String {
    let escaped_url = html_escape(redirect_url);
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta id="redirect-target" data-url="{escaped_url}">
    <title>Redirecting to Handrive...</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }}
        .container {{
            text-align: center;
            padding: 2rem;
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        h1 {{ color: #333; font-size: 1.5rem; margin-bottom: 0.5rem; }}
        p {{ color: #666; margin: 0.5rem 0; }}
        .success {{ color: #22c55e; font-size: 3rem; margin-bottom: 1rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="success">✓</div>
        <h1>Sign in successful!</h1>
        <p>You can close this tab and return to Handrive.</p>
    </div>
    <script>
        var url = document.getElementById('redirect-target').getAttribute('data-url');
        if (url && url.indexOf('handrive://') === 0) {{
            window.location.href = url;
            setTimeout(function() {{ window.close(); }}, 100);
        }}
    </script>
</body>
</html>"#
    )
}

/// Generate error HTML for OAuth callback failures.
fn oauth_error_html(message: &str) -> String {
    let escaped_message = html_escape(message);
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Sign in failed - Handrive</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }}
        .container {{
            text-align: center;
            padding: 2rem;
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        h1 {{ color: #333; font-size: 1.5rem; margin-bottom: 0.5rem; }}
        p {{ color: #666; margin: 0.5rem 0; }}
        .error {{ color: #ef4444; font-size: 3rem; margin-bottom: 1rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error">✗</div>
        <h1>Sign in failed</h1>
        <p>{escaped_message}</p>
    </div>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // =========================================================================
    // html_escape tests
    // =========================================================================

    #[test]
    fn test_html_escape_ampersand() {
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn test_html_escape_less_than() {
        assert_eq!(html_escape("a<b"), "a&lt;b");
    }

    #[test]
    fn test_html_escape_greater_than() {
        assert_eq!(html_escape("a>b"), "a&gt;b");
    }

    #[test]
    fn test_html_escape_double_quote() {
        assert_eq!(html_escape(r#"a"b"#), "a&quot;b");
    }

    #[test]
    fn test_html_escape_single_quote() {
        assert_eq!(html_escape("a'b"), "a&#x27;b");
    }

    #[test]
    fn test_html_escape_combined_xss_payload() {
        let input = r#"<script>alert("xss")</script>"#;
        let escaped = html_escape(input);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(!escaped.contains('"'));
    }

    #[test]
    fn test_html_escape_passthrough() {
        assert_eq!(html_escape("hello world"), "hello world");
    }

    #[test]
    fn test_html_escape_empty_string() {
        assert_eq!(html_escape(""), "");
    }

    #[test]
    fn test_html_escape_no_double_escape() {
        // Already-escaped content should be escaped again (correct behavior)
        assert_eq!(html_escape("&amp;"), "&amp;amp;");
    }

    #[test]
    fn test_html_escape_all_special_chars_in_one() {
        let input = "&<>\"'";
        let escaped = html_escape(input);
        assert_eq!(escaped, "&amp;&lt;&gt;&quot;&#x27;");
    }

    // =========================================================================
    // oauth_redirect_html tests
    // =========================================================================

    #[test]
    fn test_oauth_redirect_html_contains_url() {
        let html = oauth_redirect_html("handrive://auth/callback?code=abc");
        assert!(html.contains("handrive://auth/callback?code=abc"));
    }

    #[test]
    fn test_oauth_redirect_html_escapes_dangerous_chars() {
        let html = oauth_redirect_html("handrive://callback?x=<script>");
        // The escaped URL in the data attribute should not contain raw angle brackets
        assert!(html.contains("data-url=\"handrive://callback?x=&lt;script&gt;\""));
    }

    #[test]
    fn test_oauth_redirect_html_contains_data_attribute() {
        let html = oauth_redirect_html("handrive://auth/callback?code=abc");
        assert!(html.contains("data-url="));
    }

    // =========================================================================
    // oauth_error_html tests
    // =========================================================================

    #[test]
    fn test_oauth_error_html_contains_message() {
        let html = oauth_error_html("Something went wrong");
        assert!(html.contains("Something went wrong"));
    }

    #[test]
    fn test_oauth_error_html_escapes_xss() {
        let html = oauth_error_html("<script>alert('xss')</script>");
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn test_oauth_error_html_contains_heading() {
        let html = oauth_error_html("error");
        assert!(html.contains("Sign in failed"));
    }

    // =========================================================================
    // OTP lockout tracking tests
    // =========================================================================

    #[test]
    fn test_otp_lockout_under_threshold() {
        let attempts: HashMap<String, crate::OtpAttempt> = HashMap::new();
        let email = "test@example.com".to_string();
        // No entry means no lockout
        assert!(!attempts.contains_key(&email));
    }

    #[test]
    fn test_otp_lockout_at_threshold() {
        let now_ms = crate::id::epoch_ms();
        let mut attempts: HashMap<String, crate::OtpAttempt> = HashMap::new();
        let email = "test@example.com".to_string();
        attempts.insert(email.clone(), crate::OtpAttempt {
            count: MAX_OTP_ATTEMPTS,
            first_attempt_ms: now_ms,
        });

        let lockout_window_ms = (OTP_LOCKOUT_SECS * 1000) as i64;
        let attempt = attempts.get(&email).unwrap();
        let locked = attempt.count >= MAX_OTP_ATTEMPTS
            && (now_ms - attempt.first_attempt_ms) < lockout_window_ms;
        assert!(locked);
    }

    #[test]
    fn test_otp_lockout_window_expired() {
        let now_ms = crate::id::epoch_ms();
        let lockout_window_ms = (OTP_LOCKOUT_SECS * 1000) as i64;
        let mut attempts: HashMap<String, crate::OtpAttempt> = HashMap::new();
        let email = "test@example.com".to_string();
        attempts.insert(email.clone(), crate::OtpAttempt {
            count: MAX_OTP_ATTEMPTS,
            first_attempt_ms: now_ms - lockout_window_ms - 1,
        });

        let attempt = attempts.get(&email).unwrap();
        let locked = attempt.count >= MAX_OTP_ATTEMPTS
            && (now_ms - attempt.first_attempt_ms) < lockout_window_ms;
        assert!(!locked);
    }

    #[test]
    fn test_otp_lockout_window_reset() {
        let now_ms = crate::id::epoch_ms();
        let lockout_window_ms = (OTP_LOCKOUT_SECS * 1000) as i64;
        let mut attempt = crate::OtpAttempt {
            count: MAX_OTP_ATTEMPTS + 2,
            first_attempt_ms: now_ms - lockout_window_ms - 1,
        };

        // Simulate the reset logic from otp_verify
        if (now_ms - attempt.first_attempt_ms) >= lockout_window_ms {
            attempt.count = 0;
            attempt.first_attempt_ms = now_ms;
        }
        attempt.count += 1;
        assert_eq!(attempt.count, 1);
    }

    #[test]
    fn test_otp_lockout_clear_on_success() {
        let now_ms = crate::id::epoch_ms();
        let attempts = Arc::new(Mutex::new(HashMap::new()));
        let email = "test@example.com".to_string();
        {
            let mut map = attempts.lock().unwrap();
            map.insert(email.clone(), crate::OtpAttempt {
                count: 3,
                first_attempt_ms: now_ms,
            });
        }
        // Simulate clear on success
        {
            let mut map = attempts.lock().unwrap();
            map.remove(&email);
        }
        let map = attempts.lock().unwrap();
        assert!(!map.contains_key(&email));
    }
}
