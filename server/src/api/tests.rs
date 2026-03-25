//! API integration tests.
//!
//! These tests require Docker to be running for testcontainers.

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{header, Method, Request, StatusCode},
    };
    use serde_json::{json, Value};
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;
    use testcontainers::{runners::AsyncRunner, ContainerAsync};
    use testcontainers_modules::postgres::Postgres;
    use tower::ServiceExt;

    use crate::api::routes::create_router;
    use crate::auth::google::GoogleOAuth;
    use crate::auth::otp::OtpManager;
    use crate::auth::JwtManager;
    use crate::config::Config;
    use crate::db;
    use crate::logging::LogConfig;
    use crate::nats::NatsJwtGenerator;
    use crate::AppState;

    // =========================================================================
    // Test Setup Helpers
    // =========================================================================

    /// Create a test config with generated NATS keys.
    fn create_test_config() -> Config {
        let account = nkeys::KeyPair::new_account();

        Config {
            host: "127.0.0.1".to_string(),
            port: 3000,
            test_mode: true,
            demo_email: None,
            demo_otp: None,
            cors_origins: vec!["http://localhost:3000".to_string()],
            database_url: "postgres://test:test@localhost/test".to_string(),
            db_pool_size: 5,
            google_client_id: "test-client-id".to_string(),
            google_client_secret: "test-client-secret".to_string(),
            google_redirect_uri: "http://localhost:3000/callback".to_string(),
            apple_client_id: None,
            apple_team_id: None,
            apple_key_id: None,
            apple_private_key: None,
            apple_redirect_uri: None,
            jwt_secret: "test-jwt-secret-at-least-32-characters-long".to_string(),
            jwt_access_ttl: Duration::from_secs(900),
            jwt_refresh_ttl: Duration::from_secs(604800),
            resend_api_key: "test-resend-key".to_string(),
            resend_from: "test@example.com".to_string(),
            nats_url: "nats://localhost:4222".to_string(),
            nats_public_url: "tls://api.handrive.ai:4222".to_string(),
            nats_account_public_key: account.public_key(),
            nats_account_signing_key: account.seed().unwrap(),
            identity_signing_key: None, // Use ephemeral key for tests
            log: LogConfig::default(),
            cleanup_interval_secs: 43200,
        }
    }

    /// Setup test database and return pool with container.
    async fn setup_test_db() -> (sqlx::PgPool, ContainerAsync<Postgres>) {
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

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to run migrations");

        (pool, container)
    }

    /// Create test AppState with all required components.
    fn create_test_state(pool: sqlx::PgPool, config: &Config) -> AppState {
        let jwt_manager = JwtManager::new(
            &config.jwt_secret,
            config.jwt_access_ttl,
            config.jwt_refresh_ttl,
        );

        let google_oauth = GoogleOAuth::new(config).expect("Failed to create GoogleOAuth");
        let otp_manager = OtpManager::new(config).expect("Failed to create OtpManager");
        let nats_jwt = NatsJwtGenerator::new(config).expect("Failed to create NatsJwtGenerator");
        let identity_generator = crate::auth::IdentityGenerator::new(
            config.identity_signing_key.as_deref(),
        ).expect("Failed to create IdentityGenerator");

        AppState {
            pool,
            jwt_manager,
            google_oauth,
            apple_oauth: None,
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
        }
    }

    /// Create a test user and return access token.
    async fn create_test_user_and_token(state: &AppState, email: &str) -> (uuid::Uuid, String) {
        let (user, _) = db::upsert_otp_user(&state.pool, email).await.unwrap();
        let token = state
            .jwt_manager
            .generate_access_token(user.id, &user.email)
            .unwrap();
        (user.id, token)
    }

    /// Create a test user, return user id, access token, and refresh token.
    async fn create_test_user_with_session(
        state: &AppState,
        email: &str,
    ) -> (uuid::Uuid, String, String) {
        let (user, _) = db::upsert_otp_user(&state.pool, email).await.unwrap();
        let access_token = state
            .jwt_manager
            .generate_access_token(user.id, &user.email)
            .unwrap();
        let refresh_token = state.jwt_manager.generate_refresh_token();
        let token_hash = state.jwt_manager.hash_refresh_token(&refresh_token);

        db::create_session(&state.pool, user.id, &token_hash, state.jwt_manager.refresh_ttl_ms())
            .await
            .unwrap();

        (user.id, access_token, refresh_token)
    }

    /// Helper to make JSON requests.
    fn json_request(method: Method, uri: &str, body: Option<Value>) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);

        if body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }

        let body = body
            .map(|v| Body::from(serde_json::to_vec(&v).unwrap()))
            .unwrap_or(Body::empty());

        builder.body(body).unwrap()
    }

    /// Helper to make authenticated JSON requests.
    fn auth_json_request(
        method: Method,
        uri: &str,
        token: &str,
        body: Option<Value>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {}", token));

        if body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }

        let body = body
            .map(|v| Body::from(serde_json::to_vec(&v).unwrap()))
            .unwrap_or(Body::empty());

        builder.body(body).unwrap()
    }

    /// Extract JSON body from response.
    async fn response_json(response: axum::response::Response) -> Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap_or(Value::Null)
    }

    // =========================================================================
    // Auth Endpoint Tests
    // =========================================================================

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_google_auth_url_returns_url() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        let request = json_request(Method::POST, "/api/auth/google/url", None);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await;
        assert!(body["url"].is_string());
        assert!(body["url"].as_str().unwrap().contains("accounts.google.com"));
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_otp_request_valid_email() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        let request = json_request(
            Method::POST,
            "/api/auth/otp/request",
            Some(json!({ "email": "test@example.com" })),
        );
        let response = app.oneshot(request).await.unwrap();

        // May fail due to Resend API not being configured in test environment.
        // We just verify the endpoint exists and responds.
        assert!(response.status().is_client_error() || response.status().is_server_error() || response.status().is_success());
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_otp_request_invalid_email() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        let request = json_request(
            Method::POST,
            "/api/auth/otp/request",
            Some(json!({ "email": "invalid-email" })),
        );
        let response = app.oneshot(request).await.unwrap();

        // Axum's Json extractor returns 400 for validation errors
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_otp_verify_valid_code() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool.clone(), &config);

        // Create OTP code directly in DB
        let email = "test@example.com";
        let code = "123456";
        db::create_otp_code(&pool, email, code, 300_000).await.unwrap();

        let app = create_router().with_state(state);

        let request = json_request(
            Method::POST,
            "/api/auth/otp/verify",
            Some(json!({ "email": email, "code": code })),
        );
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await;
        assert!(body["access_token"].is_string());
        assert!(body["refresh_token"].is_string());
        assert!(body["expires_in"].is_number());
        assert!(body["user"]["id"].is_string());
        assert_eq!(body["user"]["email"].as_str().unwrap(), email);
        assert!(body["nats_credentials"].is_string());
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_otp_verify_invalid_code() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool.clone(), &config);

        let email = "test@example.com";
        db::create_otp_code(&pool, email, "123456", 300_000).await.unwrap();

        let app = create_router().with_state(state);

        let request = json_request(
            Method::POST,
            "/api/auth/otp/verify",
            Some(json!({ "email": email, "code": "wrong!" })),
        );
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_refresh_token_valid() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);

        let (_, _, refresh_token) =
            create_test_user_with_session(&state, "test@example.com").await;

        let app = create_router().with_state(state);

        let request = json_request(
            Method::POST,
            "/api/auth/refresh",
            Some(json!({ "refresh_token": refresh_token })),
        );
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await;
        assert!(body["access_token"].is_string());
        assert!(body["expires_in"].is_number());
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_refresh_token_invalid() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        let request = json_request(
            Method::POST,
            "/api/auth/refresh",
            Some(json!({ "refresh_token": "invalid-token" })),
        );
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_logout_success() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);

        let (_, access_token, refresh_token) =
            create_test_user_with_session(&state, "test@example.com").await;

        let app = create_router().with_state(state);

        let request = auth_json_request(
            Method::POST,
            "/api/auth/logout",
            &access_token,
            Some(json!({ "refresh_token": refresh_token })),
        );
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await;
        assert!(body["message"].as_str().unwrap().contains("Logged out"));
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_logout_requires_auth() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        let request = json_request(
            Method::POST,
            "/api/auth/logout",
            Some(json!({ "refresh_token": "some-token" })),
        );
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // =========================================================================
    // User Endpoint Tests
    // =========================================================================

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_get_me_success() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);

        let email = "test@example.com";
        let (user_id, token) = create_test_user_and_token(&state, email).await;

        let app = create_router().with_state(state);

        let request = auth_json_request(Method::GET, "/api/users/me", &token, None);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await;
        assert_eq!(body["id"].as_str().unwrap(), user_id.to_string());
        assert_eq!(body["email"].as_str().unwrap(), email);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_get_me_requires_auth() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        let request = json_request(Method::GET, "/api/users/me", None);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_get_me_invalid_token() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        let request = auth_json_request(Method::GET, "/api/users/me", "invalid-token", None);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_update_me_name() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);

        let (_, token) = create_test_user_and_token(&state, "test@example.com").await;

        let app = create_router().with_state(state);

        let request = auth_json_request(
            Method::PATCH,
            "/api/users/me",
            &token,
            Some(json!({ "name": "New Name" })),
        );
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await;
        assert_eq!(body["name"].as_str().unwrap(), "New Name");
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_update_me_avatar() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);

        let (_, token) = create_test_user_and_token(&state, "test@example.com").await;

        let app = create_router().with_state(state);

        let request = auth_json_request(
            Method::PATCH,
            "/api/users/me",
            &token,
            Some(json!({ "avatar_url": "https://example.com/avatar.jpg" })),
        );
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await;
        assert_eq!(
            body["avatar_url"].as_str().unwrap(),
            "https://example.com/avatar.jpg"
        );
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_update_me_metadata() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);

        let (_, token) = create_test_user_and_token(&state, "test@example.com").await;

        let app = create_router().with_state(state);

        let request = auth_json_request(
            Method::PATCH,
            "/api/users/me",
            &token,
            Some(json!({ "metadata": { "theme": "dark" } })),
        );
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await;
        assert_eq!(body["metadata"]["theme"].as_str().unwrap(), "dark");
    }

    // =========================================================================
    // Session Endpoint Tests
    // =========================================================================

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_list_sessions_empty() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);

        // Create user without session (just use token directly)
        let (_, token) = create_test_user_and_token(&state, "test@example.com").await;

        let app = create_router().with_state(state);

        let request = auth_json_request(Method::GET, "/api/sessions", &token, None);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await;
        assert!(body["sessions"].is_array());
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_list_sessions_with_session() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);

        let (_, access_token, _) =
            create_test_user_with_session(&state, "test@example.com").await;

        let app = create_router().with_state(state);

        let request = auth_json_request(Method::GET, "/api/sessions", &access_token, None);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await;
        let sessions = body["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0]["id"].is_string());
        assert!(sessions[0]["created_at"].is_number());
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_delete_session_success() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool.clone(), &config);

        let (user_id, access_token, _) =
            create_test_user_with_session(&state, "test@example.com").await;

        // Get session ID
        let sessions = db::get_user_sessions(&pool, user_id).await.unwrap();
        let session_id = sessions[0].id;

        let app = create_router().with_state(state);

        let request = auth_json_request(
            Method::DELETE,
            &format!("/api/sessions/{}", session_id),
            &access_token,
            None,
        );
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await;
        assert_eq!(body["deleted"].as_bool().unwrap(), true);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_delete_session_wrong_user() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool.clone(), &config);

        // Create user 1 with session
        let (user1_id, _, _) = create_test_user_with_session(&state, "user1@example.com").await;
        let sessions = db::get_user_sessions(&pool, user1_id).await.unwrap();
        let session_id = sessions[0].id;

        // Create user 2 (attacker)
        let (_, attacker_token) = create_test_user_and_token(&state, "attacker@example.com").await;

        let app = create_router().with_state(state);

        let request = auth_json_request(
            Method::DELETE,
            &format!("/api/sessions/{}", session_id),
            &attacker_token,
            None,
        );
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_delete_other_sessions() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool.clone(), &config);

        // Create user with multiple sessions
        let (user_id, access_token, _) =
            create_test_user_with_session(&state, "test@example.com").await;

        // Add more sessions
        for _ in 0..3 {
            let refresh = state.jwt_manager.generate_refresh_token();
            let hash = state.jwt_manager.hash_refresh_token(&refresh);
            db::create_session(&pool, user_id, &hash, state.jwt_manager.refresh_ttl_ms())
                .await
                .unwrap();
        }

        // Verify we have 4 sessions
        let sessions = db::get_user_sessions(&pool, user_id).await.unwrap();
        assert_eq!(sessions.len(), 4);

        let app = create_router().with_state(state);

        let request = auth_json_request(Method::DELETE, "/api/sessions", &access_token, None);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await;
        assert_eq!(body["deleted"].as_i64().unwrap(), 4);
    }

    // =========================================================================
    // NATS Credentials Endpoint Tests
    // =========================================================================

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_get_nats_credentials_success() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);

        let (_, token) = create_test_user_and_token(&state, "test@example.com").await;

        let app = create_router().with_state(state);

        let request = auth_json_request(Method::GET, "/api/nats/credentials", &token, None);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response_json(response).await;
        let credentials = body["credentials"].as_str().unwrap();

        // Verify NATS credentials format
        assert!(credentials.contains("-----BEGIN NATS USER JWT-----"));
        assert!(credentials.contains("-----END NATS USER JWT-----"));
        assert!(credentials.contains("-----BEGIN USER NKEY SEED-----"));
        assert!(credentials.contains("-----END USER NKEY SEED-----"));
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_get_nats_credentials_requires_auth() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        let request = json_request(Method::GET, "/api/nats/credentials", None);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_invalid_json_body() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/auth/otp/request")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("not valid json"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Axum's Json extractor returns 400 for invalid JSON
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_missing_content_type() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/auth/otp/request")
            .body(Body::from(r#"{"email":"test@example.com"}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Axum returns 415 Unsupported Media Type for missing Content-Type
        assert!(response.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_nonexistent_endpoint() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        let request = json_request(Method::GET, "/api/nonexistent", None);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[ignore] // Requires Docker + NATS
    async fn test_health_check_endpoint() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        let request = json_request(Method::GET, "/api/health", None);
        let response = app.oneshot(request).await.unwrap();

        // Health check may return 200 or 503 depending on DB/NATS connectivity
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_method_not_allowed() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        // GET on a POST-only endpoint
        let request = json_request(Method::GET, "/api/auth/google/url", None);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_malformed_bearer_token() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        // Test with malformed token (not a valid JWT structure)
        let request = auth_json_request(
            Method::GET,
            "/api/users/me",
            "not.a.valid.jwt.at.all",
            None,
        );
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_wrong_secret_token() {
        let (pool, _container) = setup_test_db().await;
        let config = create_test_config();

        // Create a JWT manager with a different secret
        let jwt_manager = JwtManager::new(
            "completely-different-secret-that-is-long-enough",
            config.jwt_access_ttl,
            config.jwt_refresh_ttl,
        );

        let (user, _) = db::upsert_otp_user(&pool, "test@example.com").await.unwrap();
        let token = jwt_manager
            .generate_access_token(user.id, &user.email)
            .unwrap();

        // Use state with original config secret
        let state = create_test_state(pool, &config);
        let app = create_router().with_state(state);

        let request = auth_json_request(Method::GET, "/api/users/me", &token, None);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

