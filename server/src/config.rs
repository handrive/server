//! Application configuration loaded from environment variables.

use std::time::Duration;

use crate::env_utils::{get_env_bool, get_env_or_default, get_env_required, get_env_string_or_default};
use crate::logging::LogConfig;

/// Minimum required length for JWT secret.
const MIN_JWT_SECRET_LENGTH: usize = 32;

/// Application configuration.
#[derive(Debug, Clone)]
pub struct Config {
    // Server
    pub host: String,
    pub port: u16,

    /// Test mode: disables real email sending, returns OTP in response.
    pub test_mode: bool,

    /// Demo account email for App Store review (optional).
    /// When set with demo_otp, allows login with static OTP code.
    pub demo_email: Option<String>,

    /// Demo account OTP code (optional).
    /// Static OTP that never expires for the demo_email account.
    pub demo_otp: Option<String>,

    /// Allowed CORS origins (comma-separated in env var).
    pub cors_origins: Vec<String>,

    // Database
    pub database_url: String,
    pub db_pool_size: u32,

    // Google OAuth
    pub google_client_id: String,
    pub google_client_secret: String,
    pub google_redirect_uri: String,

    // Apple Sign In (optional - only required if using Sign in with Apple)
    pub apple_client_id: Option<String>,
    pub apple_team_id: Option<String>,
    pub apple_key_id: Option<String>,
    pub apple_private_key: Option<String>,
    pub apple_redirect_uri: Option<String>,

    // JWT
    pub jwt_secret: String,
    pub jwt_access_ttl: Duration,
    pub jwt_refresh_ttl: Duration,

    // Resend (email API)
    pub resend_api_key: String,
    pub resend_from: String,

    // NATS
    pub nats_url: String,
    /// Public-facing NATS URL returned to clients (may differ from internal nats_url).
    pub nats_public_url: String,
    pub nats_account_signing_key: String,
    pub nats_account_public_key: String,

    // Identity credentials (Ed25519 signing for NATS message authentication)
    /// Ed25519 signing key for identity credentials (base64, 32 bytes).
    /// If not set, generates ephemeral keypair on startup (not recommended for production).
    pub identity_signing_key: Option<String>,

    // Logging
    pub log: LogConfig,

    // Cleanup
    /// Interval in seconds for background cleanup of expired OTPs and sessions.
    pub cleanup_interval_secs: u64,

}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Call `dotenvy::dotenv().ok()` before this to load from .env file.
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            // Server
            host: get_env_string_or_default("HOST", "0.0.0.0"),
            port: get_env_or_default("PORT", 8080),

            // Test mode
            test_mode: get_env_bool("TEST_MODE"),

            // Demo account for App Store review
            demo_email: std::env::var("DEMO_EMAIL").ok().map(|s| s.trim().to_lowercase()),
            demo_otp: std::env::var("DEMO_OTP").ok(),

            // CORS origins (comma-separated, with defaults for development)
            cors_origins: std::env::var("CORS_ORIGINS")
                .map(|s| s.split(',').map(|o| o.trim().to_string()).collect())
                .unwrap_or_else(|_| vec![
                    "http://localhost:3000".to_string(),
                    "http://localhost:1420".to_string(),
                    "tauri://localhost".to_string(),
                ]),

            // Database
            database_url: get_env_required("DATABASE_URL")
                .map_err(ConfigError::Missing)?,
            db_pool_size: get_env_or_default("DB_POOL_SIZE", 20),

            // Google OAuth
            google_client_id: get_env_required("GOOGLE_CLIENT_ID")
                .map_err(ConfigError::Missing)?,
            google_client_secret: get_env_required("GOOGLE_CLIENT_SECRET")
                .map_err(ConfigError::Missing)?,
            google_redirect_uri: get_env_required("GOOGLE_REDIRECT_URI")
                .map_err(ConfigError::Missing)?,

            // Apple Sign In (optional)
            // Private key can be provided via APPLE_PRIVATE_KEY_FILE (path) or APPLE_PRIVATE_KEY (inline)
            apple_client_id: std::env::var("APPLE_CLIENT_ID").ok(),
            apple_team_id: std::env::var("APPLE_TEAM_ID").ok(),
            apple_key_id: std::env::var("APPLE_KEY_ID").ok(),
            apple_private_key: std::env::var("APPLE_PRIVATE_KEY_FILE")
                .ok()
                .and_then(|path| std::fs::read_to_string(&path).ok())
                .or_else(|| std::env::var("APPLE_PRIVATE_KEY").ok()),
            apple_redirect_uri: std::env::var("APPLE_REDIRECT_URI").ok(),

            // JWT
            jwt_secret: {
                let secret = get_env_required("JWT_SECRET")
                    .map_err(ConfigError::Missing)?;
                if secret.len() < MIN_JWT_SECRET_LENGTH {
                    return Err(ConfigError::ValidationFailed(format!(
                        "JWT_SECRET must be at least {} characters",
                        MIN_JWT_SECRET_LENGTH
                    )));
                }
                secret
            },
            jwt_access_ttl: Duration::from_secs(get_env_or_default("JWT_ACCESS_TTL_SECS", 86400)), // 24 hours
            jwt_refresh_ttl: Duration::from_secs(get_env_or_default("JWT_REFRESH_TTL_SECS", 604800)),

            // Resend (email API)
            resend_api_key: get_env_required("RESEND_API_KEY")
                .map_err(ConfigError::Missing)?,
            resend_from: get_env_string_or_default("RESEND_FROM", "Handrive <noreply@handrive.ai>"),

            // NATS
            nats_url: get_env_string_or_default("NATS_URL", "nats://localhost:4222"),
            nats_public_url: get_env_string_or_default("NATS_PUBLIC_URL", "tls://api.handrive.ai:4222"),
            nats_account_signing_key: get_env_required("NATS_ACCOUNT_SIGNING_KEY")
                .map_err(ConfigError::Missing)?,
            nats_account_public_key: get_env_required("NATS_ACCOUNT_PUBLIC_KEY")
                .map_err(ConfigError::Missing)?,

            // Identity credentials
            identity_signing_key: std::env::var("IDENTITY_SIGNING_KEY").ok(),

            // Logging
            log: LogConfig {
                log_dir: get_env_string_or_default("LOG_DIR", "/var/log/handrive"),
                log_file_prefix: get_env_string_or_default("LOG_FILE_PREFIX", "handrive-server"),
                log_level: get_env_string_or_default("LOG_LEVEL", "info"),
                log_retention_days: get_env_or_default("LOG_RETENTION_DAYS", 7),
            },

            // Cleanup (default: 12 hours)
            cleanup_interval_secs: get_env_or_default("CLEANUP_INTERVAL_SECS", 43200),

        })
    }
}

/// Configuration loading errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    Missing(&'static str),

    #[error("Invalid value for environment variable: {0}")]
    InvalidValue(&'static str),

    #[error("Configuration validation failed: {0}")]
    ValidationFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    /// Set the minimum required env vars for Config::from_env() to succeed.
    fn set_required_env_vars() {
        env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
        env::set_var("GOOGLE_CLIENT_ID", "test-client-id");
        env::set_var("GOOGLE_CLIENT_SECRET", "test-client-secret");
        env::set_var("GOOGLE_REDIRECT_URI", "http://localhost/callback");
        env::set_var("JWT_SECRET", "a]test-jwt-secret-that-is-at-least-32-characters");
        env::set_var("RESEND_API_KEY", "test-resend-key");
        env::set_var("NATS_ACCOUNT_SIGNING_KEY", "SATEST");
        env::set_var("NATS_ACCOUNT_PUBLIC_KEY", "ATEST");
    }

    /// Clear all env vars set by set_required_env_vars and optional overrides.
    fn clear_env_vars() {
        let keys = [
            "DATABASE_URL", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
            "GOOGLE_REDIRECT_URI", "JWT_SECRET", "RESEND_API_KEY",
            "NATS_ACCOUNT_SIGNING_KEY", "NATS_ACCOUNT_PUBLIC_KEY",
            "HOST", "PORT", "DB_POOL_SIZE", "TEST_MODE",
            "CLEANUP_INTERVAL_SECS", "LOG_LEVEL", "CORS_ORIGINS",
            "DEMO_EMAIL", "DEMO_OTP",
            "JWT_ACCESS_TTL_SECS", "JWT_REFRESH_TTL_SECS",
        ];
        for key in keys {
            env::remove_var(key);
        }
    }

    // =========================================================================
    // Validation tests
    // =========================================================================

    #[test]
    fn test_jwt_secret_too_short() {
        set_required_env_vars();
        env::set_var("JWT_SECRET", "short");
        let result = Config::from_env();
        clear_env_vars();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("JWT_SECRET"));
    }

    #[test]
    fn test_missing_database_url() {
        set_required_env_vars();
        env::remove_var("DATABASE_URL");
        let result = Config::from_env();
        clear_env_vars();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("DATABASE_URL"));
    }

    #[test]
    fn test_missing_google_client_id() {
        set_required_env_vars();
        env::remove_var("GOOGLE_CLIENT_ID");
        let result = Config::from_env();
        clear_env_vars();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("GOOGLE_CLIENT_ID"));
    }

    // =========================================================================
    // Default value tests
    // =========================================================================

    #[test]
    fn test_default_host() {
        set_required_env_vars();
        env::remove_var("HOST");
        let config = Config::from_env().unwrap();
        clear_env_vars();
        assert_eq!(config.host, "0.0.0.0");
    }

    #[test]
    fn test_default_port() {
        set_required_env_vars();
        env::remove_var("PORT");
        let config = Config::from_env().unwrap();
        clear_env_vars();
        assert_eq!(config.port, 8080);
    }

    #[test]
    fn test_default_pool_size() {
        set_required_env_vars();
        env::remove_var("DB_POOL_SIZE");
        let config = Config::from_env().unwrap();
        clear_env_vars();
        assert_eq!(config.db_pool_size, 20);
    }

    #[test]
    fn test_default_test_mode() {
        set_required_env_vars();
        env::remove_var("TEST_MODE");
        let config = Config::from_env().unwrap();
        clear_env_vars();
        assert!(!config.test_mode);
    }

    #[test]
    fn test_default_cleanup_interval() {
        set_required_env_vars();
        env::remove_var("CLEANUP_INTERVAL_SECS");
        let config = Config::from_env().unwrap();
        clear_env_vars();
        assert_eq!(config.cleanup_interval_secs, 43200);
    }

    #[test]
    fn test_default_log_level() {
        set_required_env_vars();
        env::remove_var("LOG_LEVEL");
        let config = Config::from_env().unwrap();
        clear_env_vars();
        assert_eq!(config.log.log_level, "info");
    }

    // =========================================================================
    // CORS, demo, JWT TTL tests
    // =========================================================================

    #[test]
    fn test_cors_custom_plus_defaults() {
        set_required_env_vars();
        env::set_var("CORS_ORIGINS", "https://app.example.com,https://other.com");
        let config = Config::from_env().unwrap();
        clear_env_vars();
        assert_eq!(config.cors_origins.len(), 2);
        assert!(config.cors_origins.contains(&"https://app.example.com".to_string()));
        assert!(config.cors_origins.contains(&"https://other.com".to_string()));
    }

    #[test]
    fn test_demo_email_normalization() {
        set_required_env_vars();
        env::set_var("DEMO_EMAIL", "  Demo@Example.COM  ");
        env::set_var("DEMO_OTP", "123456");
        let config = Config::from_env().unwrap();
        clear_env_vars();
        assert_eq!(config.demo_email.as_deref(), Some("demo@example.com"));
    }

    #[test]
    fn test_demo_absent() {
        set_required_env_vars();
        env::remove_var("DEMO_EMAIL");
        env::remove_var("DEMO_OTP");
        let config = Config::from_env().unwrap();
        clear_env_vars();
        assert!(config.demo_email.is_none());
        assert!(config.demo_otp.is_none());
    }

    #[test]
    fn test_jwt_ttl_defaults() {
        set_required_env_vars();
        env::remove_var("JWT_ACCESS_TTL_SECS");
        env::remove_var("JWT_REFRESH_TTL_SECS");
        let config = Config::from_env().unwrap();
        clear_env_vars();
        assert_eq!(config.jwt_access_ttl, std::time::Duration::from_secs(86400));
        assert_eq!(config.jwt_refresh_ttl, std::time::Duration::from_secs(604800));
    }

    #[test]
    fn test_jwt_ttl_custom() {
        set_required_env_vars();
        env::set_var("JWT_ACCESS_TTL_SECS", "3600");
        env::set_var("JWT_REFRESH_TTL_SECS", "86400");
        let config = Config::from_env().unwrap();
        clear_env_vars();
        assert_eq!(config.jwt_access_ttl, std::time::Duration::from_secs(3600));
        assert_eq!(config.jwt_refresh_ttl, std::time::Duration::from_secs(86400));
    }
}
