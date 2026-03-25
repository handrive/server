//! Handrive Server
//!
//! Backend service for the Handrive P2P file sharing system.
//! Handles user authentication and NATS credential provisioning.

use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::middleware;
use sqlx::postgres::PgPoolOptions;
use tokio::signal;
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use axum::Router;

use handrive_server::api;
use handrive_server::auth::{apple::AppleOAuth, google::GoogleOAuth, otp::OtpManager, IdentityGenerator, JwtManager};
use handrive_server::config::Config;
use handrive_server::db;
use handrive_server::logging::{init_logging, cleanup_old_logs, LogConfig};
use handrive_server::middleware::{rate_limit_middleware, RateLimitConfig};
use handrive_server::nats::NatsJwtGenerator;
use handrive_server::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install rustls crypto provider (required for rustls 0.23+)
    // Must be done before any TLS operations (NATS, etc.)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Load .env file
    dotenvy::dotenv().ok();

    // Load configuration first (before logging, to get log config)
    let config = Config::from_env()?;

    // Initialize structured logging with JSON format and daily rotation
    // The guard must be kept alive for the duration of the program
    let _log_guard = init_logging(&config.log)?;

    tracing::info!(
        host = %config.host,
        port = %config.port,
        "Starting Handrive server"
    );

    // Create database pool
    let pool = PgPoolOptions::new()
        .max_connections(config.db_pool_size)
        .connect(&config.database_url)
        .await?;

    tracing::info!(
        database = "connected",
        pool_size = config.db_pool_size,
        "Database connection established"
    );

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!(migrations = "complete", "Database migrations applied");

    // Initialize components
    let jwt_manager = JwtManager::new(
        &config.jwt_secret,
        config.jwt_access_ttl,
        config.jwt_refresh_ttl,
    );
    let google_oauth = GoogleOAuth::new(&config)?;
    let otp_manager = OtpManager::new(&config)?;
    let nats_jwt = NatsJwtGenerator::new(&config)?;
    let identity_generator = IdentityGenerator::new(
        config.identity_signing_key.as_deref(),
    )?;

    // Initialize Apple OAuth (optional - only if configured)
    let apple_oauth = if AppleOAuth::is_configured(&config) {
        match AppleOAuth::new(&config) {
            Ok(oauth) => {
                tracing::info!("Apple Sign In enabled");
                Some(oauth)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Apple Sign In not available (configuration error)");
                None
            }
        }
    } else {
        tracing::info!("Apple Sign In not configured (optional)");
        None
    };

    // Create application state
    let state = AppState {
        pool,
        jwt_manager,
        google_oauth,
        apple_oauth,
        otp_manager,
        nats_jwt,
        identity_generator,
        nats_url: config.nats_url.clone(),
        nats_public_url: config.nats_public_url.clone(),
        test_mode: config.test_mode,
        demo_email: config.demo_email.clone(),
        demo_otp: config.demo_otp.clone(),
        otp_attempts: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        invite_rate: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
    };

    if config.test_mode {
        // Refuse test mode if running on a non-localhost/non-test port (likely production)
        if config.host != "127.0.0.1" && config.host != "localhost" {
            if std::env::var("TEST_MODE_ACKNOWLEDGE").ok().as_deref() != Some("yes") {
                tracing::error!(
                    "TEST_MODE is enabled on a non-localhost host ({}). \
                     This is dangerous in production as OTP codes are returned in API responses. \
                     Set TEST_MODE_ACKNOWLEDGE=yes to override this safety check.",
                    config.host
                );
                anyhow::bail!(
                    "Refusing to start: TEST_MODE enabled on non-localhost host. \
                     Set TEST_MODE_ACKNOWLEDGE=yes to override."
                );
            }
        }
        tracing::warn!(
            "Running in TEST MODE - OTP codes will be returned in responses. \
             DO NOT use in production!"
        );
    }

    if config.demo_email.is_some() && config.demo_otp.is_some() {
        tracing::info!(
            demo_email = config.demo_email.as_deref().unwrap(),
            "Demo account enabled for App Store review"
        );
    }

    // Initialize rate limiters (global + per-IP)
    let rate_limit_config = RateLimitConfig::from_env();
    let rate_limiters = rate_limit_config.create_limiters();
    tracing::info!(
        global_rps = rate_limit_config.global_rps,
        global_burst = rate_limit_config.global_burst,
        per_ip_rps = rate_limit_config.per_ip_rps,
        per_ip_burst = rate_limit_config.per_ip_burst,
        "Rate limiting enabled (global + per-IP)"
    );

    // Clone pool for background tasks (before state is moved)
    let cleanup_pool = state.pool.clone();

    // Build router with CORS configured for credentials
    let allowed_origins: Vec<HeaderValue> = config
        .cors_origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();

    tracing::info!(
        origins = ?config.cors_origins,
        "CORS configured"
    );

    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::COOKIE])
        .allow_credentials(true);

    // Build API routes
    let api_routes = api::routes::create_router()
        .with_state(state.clone());

    let app = Router::new()
        .merge(api_routes)
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            rate_limiters,
            rate_limit_middleware,
        ))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        // Security headers
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ));

    // Spawn background cleanup task for expired OTPs, sessions, and old logs
    let cleanup_interval = std::time::Duration::from_secs(config.cleanup_interval_secs);
    let cleanup_log_config = config.log.clone();
    tokio::spawn(async move {
        cleanup_task(cleanup_pool, cleanup_interval, cleanup_log_config).await;
    });
    tracing::info!(
        interval_secs = config.cleanup_interval_secs,
        log_retention_days = config.log.log_retention_days,
        "Background cleanup task started"
    );

    // Start server with connection info for per-IP rate limiting
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!(addr = %addr, "Server listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("Server shutdown complete");
    Ok(())
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, starting graceful shutdown");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, starting graceful shutdown");
        }
    }
}

/// Background task to periodically clean up expired OTPs, sessions, and old logs.
async fn cleanup_task(pool: sqlx::PgPool, interval: std::time::Duration, log_config: LogConfig) {
    let mut interval_timer = tokio::time::interval(interval);

    loop {
        interval_timer.tick().await;

        // Clean up expired OTP codes
        match db::repo::cleanup_expired_otps(&pool).await {
            Ok(count) if count > 0 => {
                tracing::info!(deleted = count, "Cleaned up expired OTP codes");
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to clean up expired OTP codes");
            }
            _ => {}
        }

        // Clean up expired sessions
        match db::repo::cleanup_expired_sessions(&pool).await {
            Ok(count) if count > 0 => {
                tracing::info!(deleted = count, "Cleaned up expired sessions");
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to clean up expired sessions");
            }
            _ => {}
        }

        // Clean up old log files
        match cleanup_old_logs(
            &log_config.log_dir,
            &log_config.log_file_prefix,
            log_config.log_retention_days,
        ) {
            Ok(count) if count > 0 => {
                tracing::info!(deleted = count, "Cleaned up old log files");
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to clean up old log files");
            }
            _ => {}
        }
    }
}
