//! Repository layer for database operations.
//!
//! Uses upsert operations with deterministic IDs for idempotent creation.

use sqlx::{PgPool, Row, postgres::PgRow};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::id::{epoch_ms, normalize_email, user_id};

use super::models::*;

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract a User from a database row.
fn user_from_row(row: &PgRow) -> User {
    User {
        id: row.get("id"),
        email: row.get("email"),
        name: row.get("name"),
        avatar_url: row.get("avatar_url"),
        google_id: row.get("google_id"),
        apple_id: row.get("apple_id"),
        metadata: row.get::<Option<serde_json::Value>, _>("metadata").unwrap_or(serde_json::json!({})),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        updated_by: row.get("updated_by"),
    }
}

/// Extract a Session from a database row.
fn session_from_row(row: &PgRow) -> Session {
    Session {
        id: row.get("id"),
        user_id: row.get("user_id"),
        token_hash: row.get("token_hash"),
        expires_at: row.get("expires_at"),
        created_at: row.get("created_at"),
        last_used_at: row.get("last_used_at"),
    }
}

/// Google user info from OAuth.
pub struct GoogleUserInfo {
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub google_id: String,
}

/// Apple user info from Sign in with Apple.
pub struct AppleUserInfo {
    pub email: String,
    pub name: Option<String>,
    pub apple_id: String,
}

// ============================================================================
// User Repository
// ============================================================================

/// Upsert a user from Google OAuth.
///
/// Returns (User, is_new) where is_new is true if user was created.
pub async fn upsert_google_user(
    pool: &PgPool,
    info: GoogleUserInfo,
) -> AppResult<(User, bool)> {
    let id = user_id(&info.email);
    let now = epoch_ms();
    let email = normalize_email(&info.email);

    // Use xmax = 0 to detect insert vs update
    let row = sqlx::query(
        r#"
        INSERT INTO users (id, email, name, avatar_url, google_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $6)
        ON CONFLICT (id) DO UPDATE SET
            -- Only fill in name/avatar if existing value is NULL or empty (preserve user customizations)
            name = COALESCE(NULLIF(users.name, ''), EXCLUDED.name, users.name),
            avatar_url = COALESCE(NULLIF(users.avatar_url, ''), EXCLUDED.avatar_url, users.avatar_url),
            google_id = COALESCE(EXCLUDED.google_id, users.google_id),
            updated_at = EXCLUDED.updated_at
        RETURNING id, email, name, avatar_url, google_id, apple_id, metadata, created_at, updated_at, updated_by, (xmax = 0) AS is_new
        "#,
    )
    .bind(id)
    .bind(&email)
    .bind(&info.name)
    .bind(&info.avatar_url)
    .bind(&info.google_id)
    .bind(now)
    .fetch_one(pool)
    .await?;

    let user = user_from_row(&row);
    let is_new: bool = row.get("is_new");
    Ok((user, is_new))
}

/// Upsert a user from Apple Sign In.
///
/// Returns (User, is_new) where is_new is true if user was created.
pub async fn upsert_apple_user(
    pool: &PgPool,
    info: AppleUserInfo,
) -> AppResult<(User, bool)> {
    let id = user_id(&info.email);
    let now = epoch_ms();
    let email = normalize_email(&info.email);

    // Use xmax = 0 to detect insert vs update
    let row = sqlx::query(
        r#"
        INSERT INTO users (id, email, name, apple_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $5)
        ON CONFLICT (id) DO UPDATE SET
            -- Only fill in name if existing value is NULL or empty (preserve user customizations)
            name = COALESCE(NULLIF(users.name, ''), EXCLUDED.name, users.name),
            apple_id = COALESCE(EXCLUDED.apple_id, users.apple_id),
            updated_at = EXCLUDED.updated_at
        RETURNING id, email, name, avatar_url, google_id, apple_id, metadata, created_at, updated_at, updated_by, (xmax = 0) AS is_new
        "#,
    )
    .bind(id)
    .bind(&email)
    .bind(&info.name)
    .bind(&info.apple_id)
    .bind(now)
    .fetch_one(pool)
    .await?;

    let user = user_from_row(&row);
    let is_new: bool = row.get("is_new");
    Ok((user, is_new))
}

/// Upsert a user from email OTP authentication.
///
/// Creates minimal user profile if new; returns (User, is_new).
pub async fn upsert_otp_user(pool: &PgPool, email: &str) -> AppResult<(User, bool)> {
    let id = user_id(email);
    let now = epoch_ms();
    let email = normalize_email(email);
    let default_name = crate::id::email_to_name(&email);

    let row = sqlx::query(
        r#"
        INSERT INTO users (id, email, name, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $4)
        ON CONFLICT (id) DO UPDATE SET
            updated_at = EXCLUDED.updated_at
        RETURNING id, email, name, avatar_url, google_id, apple_id, metadata, created_at, updated_at, updated_by, (xmax = 0) AS is_new
        "#,
    )
    .bind(id)
    .bind(&email)
    .bind(&default_name)
    .bind(now)
    .fetch_one(pool)
    .await?;

    let user = user_from_row(&row);
    let is_new: bool = row.get("is_new");
    Ok((user, is_new))
}

/// Get user by ID.
pub async fn get_user_by_id(pool: &PgPool, id: Uuid) -> AppResult<Option<User>> {
    let row = sqlx::query(
        r#"
        SELECT id, email, name, avatar_url, google_id, apple_id,
               COALESCE(metadata, '{}') as metadata,
               created_at, updated_at, updated_by
        FROM users WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.as_ref().map(user_from_row))
}

/// Get user by email.
pub async fn get_user_by_email(pool: &PgPool, email: &str) -> AppResult<Option<User>> {
    let email = normalize_email(email);
    let row = sqlx::query(
        r#"
        SELECT id, email, name, avatar_url, google_id, apple_id,
               COALESCE(metadata, '{}') as metadata,
               created_at, updated_at, updated_by
        FROM users WHERE email = $1
        "#,
    )
    .bind(&email)
    .fetch_optional(pool)
    .await?;

    Ok(row.as_ref().map(user_from_row))
}

/// Get users by email list (batch lookup).
pub async fn get_users_by_emails(pool: &PgPool, emails: &[String]) -> AppResult<Vec<User>> {
    if emails.is_empty() {
        return Ok(vec![]);
    }

    let emails: Vec<String> = emails.iter().map(|e| normalize_email(e)).collect();
    let rows = sqlx::query(
        r#"
        SELECT id, email, name, avatar_url, google_id, apple_id,
               COALESCE(metadata, '{}') as metadata,
               created_at, updated_at, updated_by
        FROM users WHERE email = ANY($1)
        "#,
    )
    .bind(&emails)
    .fetch_all(pool)
    .await?;

    Ok(rows.iter().map(user_from_row).collect())
}

/// Upsert user profile.
///
/// Creates user if not exists, updates if exists.
/// This enables re-registration when DB is lost but client has valid token.
pub async fn upsert_user(
    pool: &PgPool,
    id: Uuid,
    email: &str,
    name: Option<String>,
    avatar_url: Option<String>,
    metadata: Option<serde_json::Value>,
) -> AppResult<User> {
    let now = epoch_ms();
    let email = normalize_email(email);
    let default_name = crate::id::email_to_name(&email);

    // Normalize: trim whitespace, treat whitespace-only as empty
    let name = name.map(|s| s.trim().to_string());
    let avatar_url = avatar_url.map(|s| s.trim().to_string());

    let row = sqlx::query(
        r#"
        INSERT INTO users (id, email, name, avatar_url, metadata, created_at, updated_at, updated_by)
        VALUES ($1, $2, COALESCE($3, $6), $4, COALESCE($5, '{}'), $7, $7, $1)
        ON CONFLICT (id) DO UPDATE SET
            name = COALESCE(EXCLUDED.name, users.name),
            avatar_url = COALESCE(EXCLUDED.avatar_url, users.avatar_url),
            metadata = COALESCE(EXCLUDED.metadata, users.metadata),
            updated_at = EXCLUDED.updated_at,
            updated_by = EXCLUDED.updated_by
        RETURNING id, email, name, avatar_url, google_id, apple_id,
                  COALESCE(metadata, '{}') as metadata,
                  created_at, updated_at, updated_by
        "#,
    )
    .bind(id)
    .bind(&email)
    .bind(&name)
    .bind(&avatar_url)
    .bind(&metadata)
    .bind(&default_name)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(user_from_row(&row))
}

/// Delete a user by ID.
///
/// Sessions are automatically deleted via `ON DELETE CASCADE` FK constraint.
/// Returns `AppError::NotFound` if user doesn't exist.
pub async fn delete_user(pool: &PgPool, user_id: Uuid) -> AppResult<()> {
    let result = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    Ok(())
}

// ============================================================================
// OTP Repository
// ============================================================================

/// Create a new OTP code.
pub async fn create_otp_code(pool: &PgPool, email: &str, code: &str, ttl_ms: i64) -> AppResult<OtpCode> {
    let email = normalize_email(email);
    let now = epoch_ms();
    let expires_at = now + ttl_ms;

    let row = sqlx::query(
        r#"
        INSERT INTO otp_codes (email, code, expires_at, created_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id, email, code, expires_at, used, created_at
        "#,
    )
    .bind(&email)
    .bind(code)
    .bind(expires_at)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(OtpCode {
        id: row.get("id"),
        email: row.get("email"),
        code: row.get("code"),
        expires_at: row.get("expires_at"),
        used: row.get("used"),
        created_at: row.get("created_at"),
    })
}

/// Verify and consume an OTP code.
///
/// Returns true if code was valid and consumed, false otherwise.
pub async fn verify_otp_code(pool: &PgPool, email: &str, code: &str) -> AppResult<bool> {
    let email = normalize_email(email);
    let now = epoch_ms();

    let result = sqlx::query(
        r#"
        UPDATE otp_codes
        SET used = TRUE
        WHERE email = $1 AND code = $2 AND expires_at > $3 AND used = FALSE
        RETURNING id
        "#,
    )
    .bind(&email)
    .bind(code)
    .bind(now)
    .fetch_optional(pool)
    .await?;

    Ok(result.is_some())
}

/// Clean up expired OTP codes.
pub async fn cleanup_expired_otps(pool: &PgPool) -> AppResult<u64> {
    let now = epoch_ms();
    let result = sqlx::query("DELETE FROM otp_codes WHERE expires_at < $1 OR used = TRUE")
        .bind(now)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

// ============================================================================
// Session Repository
// ============================================================================

/// Create a new session.
pub async fn create_session(pool: &PgPool, user_id: Uuid, token_hash: &str, ttl_ms: i64) -> AppResult<Session> {
    let now = epoch_ms();
    let expires_at = now + ttl_ms;

    let row = sqlx::query(
        r#"
        INSERT INTO sessions (user_id, token_hash, expires_at, created_at, last_used_at)
        VALUES ($1, $2, $3, $4, $4)
        RETURNING id, user_id, token_hash, expires_at, created_at, last_used_at
        "#,
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(session_from_row(&row))
}

/// Get session by token hash.
pub async fn get_session_by_token(pool: &PgPool, token_hash: &str) -> AppResult<Option<Session>> {
    let now = epoch_ms();
    let row = sqlx::query(
        r#"
        SELECT id, user_id, token_hash, expires_at, created_at, last_used_at
        FROM sessions
        WHERE token_hash = $1 AND expires_at > $2
        "#,
    )
    .bind(token_hash)
    .bind(now)
    .fetch_optional(pool)
    .await?;

    Ok(row.as_ref().map(session_from_row))
}

/// Get all sessions for a user.
pub async fn get_user_sessions(pool: &PgPool, user_id: Uuid) -> AppResult<Vec<Session>> {
    let now = epoch_ms();
    let rows = sqlx::query(
        r#"
        SELECT id, user_id, token_hash, expires_at, created_at, last_used_at
        FROM sessions
        WHERE user_id = $1 AND expires_at > $2
        ORDER BY last_used_at DESC
        "#,
    )
    .bind(user_id)
    .bind(now)
    .fetch_all(pool)
    .await?;

    Ok(rows.iter().map(session_from_row).collect())
}

/// Delete a session.
pub async fn delete_session(pool: &PgPool, id: Uuid, user_id: Uuid) -> AppResult<()> {
    let result = sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    Ok(())
}

/// Delete all sessions for a user.
pub async fn delete_all_sessions_for_user(pool: &PgPool, user_id: Uuid) -> AppResult<u64> {
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Delete all sessions for a user except the specified one.
pub async fn delete_other_sessions(pool: &PgPool, user_id: Uuid, except_id: Uuid) -> AppResult<u64> {
    let result = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id != $2")
        .bind(user_id)
        .bind(except_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Enforce maximum sessions per user by deleting oldest sessions.
///
/// Returns the number of sessions deleted.
pub async fn enforce_session_limit(pool: &PgPool, user_id: Uuid, max_sessions: i64) -> AppResult<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM sessions
        WHERE id IN (
            SELECT id FROM sessions
            WHERE user_id = $1
            ORDER BY last_used_at DESC
            OFFSET $2
        )
        "#,
    )
    .bind(user_id)
    .bind(max_sessions)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Clean up expired sessions.
pub async fn cleanup_expired_sessions(pool: &PgPool) -> AppResult<u64> {
    let now = epoch_ms();
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at < $1")
        .bind(now)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    //! Database repository integration tests.
    //!
    //! These tests require a PostgreSQL database. They use testcontainers to spin up
    //! a temporary database for testing.
    //!
    //! Run with: cargo test db::repo::tests -- --test-threads=1

    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use sqlx::PgPool;
    use testcontainers::{runners::AsyncRunner, ContainerAsync};
    use testcontainers_modules::postgres::Postgres;

    /// Setup a test database with migrations applied.
    async fn setup_test_db() -> (PgPool, ContainerAsync<Postgres>) {
        let container = Postgres::default().start().await.unwrap();

        let connection_string = format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            container.get_host_port_ipv4(5432).await.unwrap()
        );

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&connection_string)
            .await
            .expect("Failed to connect to test database");

        // Run migrations
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to run migrations");

        (pool, container)
    }

    // =========================================================================
    // User Repository Tests
    // =========================================================================

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_upsert_google_user_creates_new_user() {
        let (pool, _container) = setup_test_db().await;

        let info = GoogleUserInfo {
            email: "new@example.com".to_string(),
            name: Some("New User".to_string()),
            avatar_url: Some("https://example.com/avatar.jpg".to_string()),
            google_id: "google-id-123".to_string(),
        };

        let (user, is_new) = upsert_google_user(&pool, info).await.unwrap();

        assert!(is_new);
        assert_eq!(user.email, "new@example.com");
        assert_eq!(user.name, Some("New User".to_string()));
        assert_eq!(user.google_id, Some("google-id-123".to_string()));
        assert_eq!(user.id, user_id("new@example.com"));
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_upsert_google_user_updates_existing() {
        let (pool, _container) = setup_test_db().await;

        // Create user first
        let info1 = GoogleUserInfo {
            email: "existing@example.com".to_string(),
            name: Some("Original Name".to_string()),
            avatar_url: None,
            google_id: "google-id-456".to_string(),
        };
        let (user1, is_new1) = upsert_google_user(&pool, info1).await.unwrap();
        assert!(is_new1);

        // Update user
        let info2 = GoogleUserInfo {
            email: "existing@example.com".to_string(),
            name: Some("Updated Name".to_string()),
            avatar_url: Some("https://new-avatar.com/pic.jpg".to_string()),
            google_id: "google-id-456".to_string(),
        };
        let (user2, is_new2) = upsert_google_user(&pool, info2).await.unwrap();

        assert!(!is_new2);
        assert_eq!(user2.id, user1.id);
        assert_eq!(user2.name, Some("Updated Name".to_string()));
        assert_eq!(user2.avatar_url, Some("https://new-avatar.com/pic.jpg".to_string()));
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_upsert_google_user_email_case_insensitive() {
        let (pool, _container) = setup_test_db().await;

        let info1 = GoogleUserInfo {
            email: "Test@Example.COM".to_string(),
            name: Some("Test User".to_string()),
            avatar_url: None,
            google_id: "google-id-789".to_string(),
        };
        let (user1, _) = upsert_google_user(&pool, info1).await.unwrap();

        let info2 = GoogleUserInfo {
            email: "test@example.com".to_string(),
            name: Some("Same User".to_string()),
            avatar_url: None,
            google_id: "google-id-789".to_string(),
        };
        let (user2, is_new) = upsert_google_user(&pool, info2).await.unwrap();

        assert!(!is_new);
        assert_eq!(user1.id, user2.id);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_upsert_otp_user_creates_new() {
        let (pool, _container) = setup_test_db().await;

        let (user, is_new) = upsert_otp_user(&pool, "otp@example.com").await.unwrap();

        assert!(is_new);
        assert_eq!(user.email, "otp@example.com");
        assert_eq!(user.name, Some("otp".to_string())); // Derived from email
        assert_eq!(user.google_id, None);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_upsert_otp_user_does_not_overwrite_name() {
        let (pool, _container) = setup_test_db().await;

        // Create via Google first with a proper name
        let info = GoogleUserInfo {
            email: "user@example.com".to_string(),
            name: Some("Proper Name".to_string()),
            avatar_url: None,
            google_id: "gid".to_string(),
        };
        upsert_google_user(&pool, info).await.unwrap();

        // Login via OTP - should not overwrite name
        let (user, is_new) = upsert_otp_user(&pool, "user@example.com").await.unwrap();

        assert!(!is_new);
        assert_eq!(user.name, Some("Proper Name".to_string()));
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_get_user_by_id() {
        let (pool, _container) = setup_test_db().await;

        let info = GoogleUserInfo {
            email: "findme@example.com".to_string(),
            name: Some("Find Me".to_string()),
            avatar_url: None,
            google_id: "gid-findme".to_string(),
        };
        let (created, _) = upsert_google_user(&pool, info).await.unwrap();

        let found = get_user_by_id(&pool, created.id).await.unwrap();

        assert!(found.is_some());
        let user = found.unwrap();
        assert_eq!(user.id, created.id);
        assert_eq!(user.email, "findme@example.com");
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_get_user_by_id_not_found() {
        let (pool, _container) = setup_test_db().await;

        let random_id = Uuid::new_v4();
        let found = get_user_by_id(&pool, random_id).await.unwrap();

        assert!(found.is_none());
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_get_user_by_email() {
        let (pool, _container) = setup_test_db().await;

        let info = GoogleUserInfo {
            email: "byemail@example.com".to_string(),
            name: Some("By Email".to_string()),
            avatar_url: None,
            google_id: "gid-byemail".to_string(),
        };
        upsert_google_user(&pool, info).await.unwrap();

        let found = get_user_by_email(&pool, "byemail@example.com").await.unwrap();

        assert!(found.is_some());
        assert_eq!(found.unwrap().email, "byemail@example.com");
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_get_user_by_email_case_insensitive() {
        let (pool, _container) = setup_test_db().await;

        let info = GoogleUserInfo {
            email: "casetest@example.com".to_string(),
            name: Some("Case Test".to_string()),
            avatar_url: None,
            google_id: "gid-case".to_string(),
        };
        upsert_google_user(&pool, info).await.unwrap();

        let found = get_user_by_email(&pool, "CASETEST@EXAMPLE.COM").await.unwrap();

        assert!(found.is_some());
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_upsert_user_updates_existing() {
        let (pool, _container) = setup_test_db().await;

        let info = GoogleUserInfo {
            email: "update@example.com".to_string(),
            name: Some("Original".to_string()),
            avatar_url: None,
            google_id: "gid-update".to_string(),
        };
        let (created, _) = upsert_google_user(&pool, info).await.unwrap();

        let updated = upsert_user(
            &pool,
            created.id,
            "update@example.com",
            Some("Updated Name".to_string()),
            Some("https://new-avatar.com/pic.jpg".to_string()),
            Some(serde_json::json!({"theme": "dark"})),
        )
        .await
        .unwrap();

        assert_eq!(updated.name, Some("Updated Name".to_string()));
        assert_eq!(updated.avatar_url, Some("https://new-avatar.com/pic.jpg".to_string()));
        assert_eq!(updated.metadata["theme"], "dark");
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_upsert_user_creates_new() {
        let (pool, _container) = setup_test_db().await;

        let id = user_id("newuser@example.com");

        // User doesn't exist yet - upsert should create them
        let user = upsert_user(
            &pool,
            id,
            "newuser@example.com",
            Some("New User".to_string()),
            Some("https://avatar.com/new.jpg".to_string()),
            None,
        )
        .await
        .unwrap();

        assert_eq!(user.id, id);
        assert_eq!(user.email, "newuser@example.com");
        assert_eq!(user.name, Some("New User".to_string()));
        assert_eq!(user.avatar_url, Some("https://avatar.com/new.jpg".to_string()));
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_upsert_user_uses_default_name() {
        let (pool, _container) = setup_test_db().await;

        let id = user_id("defaultname@example.com");

        // No name provided - should derive from email
        let user = upsert_user(
            &pool,
            id,
            "defaultname@example.com",
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert_eq!(user.name, Some("defaultname".to_string()));
    }

    // =========================================================================
    // OTP Repository Tests
    // =========================================================================

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_create_otp_code() {
        let (pool, _container) = setup_test_db().await;

        let otp = create_otp_code(&pool, "otp@example.com", "123456", 300_000).await.unwrap();

        assert_eq!(otp.email, "otp@example.com");
        assert_eq!(otp.code, "123456");
        assert!(!otp.used);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_verify_otp_code_valid() {
        let (pool, _container) = setup_test_db().await;

        create_otp_code(&pool, "verify@example.com", "654321", 300_000).await.unwrap();

        let valid = verify_otp_code(&pool, "verify@example.com", "654321").await.unwrap();
        assert!(valid);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_verify_otp_code_wrong_code() {
        let (pool, _container) = setup_test_db().await;

        create_otp_code(&pool, "wrong@example.com", "111111", 300_000).await.unwrap();

        let valid = verify_otp_code(&pool, "wrong@example.com", "222222").await.unwrap();
        assert!(!valid);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_verify_otp_code_wrong_email() {
        let (pool, _container) = setup_test_db().await;

        create_otp_code(&pool, "right@example.com", "333333", 300_000).await.unwrap();

        let valid = verify_otp_code(&pool, "other@example.com", "333333").await.unwrap();
        assert!(!valid);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_verify_otp_code_already_used() {
        let (pool, _container) = setup_test_db().await;

        create_otp_code(&pool, "used@example.com", "444444", 300_000).await.unwrap();

        // First verification should succeed
        let first = verify_otp_code(&pool, "used@example.com", "444444").await.unwrap();
        assert!(first);

        // Second verification should fail (already used)
        let second = verify_otp_code(&pool, "used@example.com", "444444").await.unwrap();
        assert!(!second);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_verify_otp_code_expired() {
        let (pool, _container) = setup_test_db().await;

        // Create OTP with negative TTL (already expired)
        create_otp_code(&pool, "expired@example.com", "555555", -1000).await.unwrap();

        let valid = verify_otp_code(&pool, "expired@example.com", "555555").await.unwrap();
        assert!(!valid);
    }

    // =========================================================================
    // Session Repository Tests
    // =========================================================================

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_create_session() {
        let (pool, _container) = setup_test_db().await;

        let (user, _) = upsert_otp_user(&pool, "session@example.com").await.unwrap();

        let session = create_session(&pool, user.id, "token-hash-123", 604800_000).await.unwrap();

        assert_eq!(session.user_id, user.id);
        assert_eq!(session.token_hash, "token-hash-123");
        assert!(session.expires_at > epoch_ms());
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_get_session_by_token() {
        let (pool, _container) = setup_test_db().await;

        let (user, _) = upsert_otp_user(&pool, "getsession@example.com").await.unwrap();
        create_session(&pool, user.id, "find-me-hash", 604800_000).await.unwrap();

        let found = get_session_by_token(&pool, "find-me-hash").await.unwrap();

        assert!(found.is_some());
        assert_eq!(found.unwrap().token_hash, "find-me-hash");
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_get_session_by_token_expired() {
        let (pool, _container) = setup_test_db().await;

        let (user, _) = upsert_otp_user(&pool, "expsession@example.com").await.unwrap();
        // Create expired session
        create_session(&pool, user.id, "expired-hash", -1000).await.unwrap();

        let found = get_session_by_token(&pool, "expired-hash").await.unwrap();

        assert!(found.is_none());
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_get_user_sessions() {
        let (pool, _container) = setup_test_db().await;

        let (user, _) = upsert_otp_user(&pool, "multisession@example.com").await.unwrap();

        // Create multiple sessions
        create_session(&pool, user.id, "hash-1", 604800_000).await.unwrap();
        create_session(&pool, user.id, "hash-2", 604800_000).await.unwrap();
        create_session(&pool, user.id, "hash-3", 604800_000).await.unwrap();

        let sessions = get_user_sessions(&pool, user.id).await.unwrap();

        assert_eq!(sessions.len(), 3);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_delete_session() {
        let (pool, _container) = setup_test_db().await;

        let (user, _) = upsert_otp_user(&pool, "delsession@example.com").await.unwrap();
        let session = create_session(&pool, user.id, "del-hash", 604800_000).await.unwrap();

        delete_session(&pool, session.id, user.id).await.unwrap();

        let found = get_session_by_token(&pool, "del-hash").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_delete_session_wrong_user() {
        let (pool, _container) = setup_test_db().await;

        let (user1, _) = upsert_otp_user(&pool, "user1session@example.com").await.unwrap();
        let (user2, _) = upsert_otp_user(&pool, "user2session@example.com").await.unwrap();
        let session = create_session(&pool, user1.id, "user1-hash", 604800_000).await.unwrap();

        // User2 should not be able to delete user1's session
        let result = delete_session(&pool, session.id, user2.id).await;
        assert!(result.is_err());
    }

}
