//! Authentication middleware for extracting and validating JWT tokens.

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
};
use uuid::Uuid;

use crate::auth::JwtManager;
use crate::error::AppError;

/// Authenticated user extracted from JWT.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub email: String,
}

/// Extractor for authenticated users.
///
/// Extracts and validates the JWT from the Authorization header.
#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    JwtManager: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jwt_manager = JwtManager::from_ref(state);

        // Get Authorization header
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;

        // Extract Bearer token
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AppError::Unauthorized)?;

        // Validate token
        let claims = jwt_manager.validate_access_token(token)?;

        // Parse user ID
        let user_id = claims
            .sub
            .parse::<Uuid>()
            .map_err(|_| AppError::Unauthorized)?;

        Ok(AuthUser {
            user_id,
            email: claims.email,
        })
    }
}

/// Optional authentication extractor.
///
/// Returns None if no valid token is present, instead of failing.
#[derive(Debug, Clone)]
pub struct OptionalAuthUser(pub Option<AuthUser>);

#[async_trait]
impl<S> FromRequestParts<S> for OptionalAuthUser
where
    JwtManager: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match AuthUser::from_request_parts(parts, state).await {
            Ok(user) => Ok(OptionalAuthUser(Some(user))),
            Err(_) => Ok(OptionalAuthUser(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::FromRef;
    use axum::http::Request;
    use std::time::Duration;

    /// Minimal test state that provides a JwtManager via FromRef.
    #[derive(Clone)]
    struct TestState {
        jwt_manager: JwtManager,
    }

    impl FromRef<TestState> for JwtManager {
        fn from_ref(state: &TestState) -> Self {
            state.jwt_manager.clone()
        }
    }

    fn test_state() -> TestState {
        TestState {
            jwt_manager: JwtManager::new(
                "test-secret-key-at-least-32-chars",
                Duration::from_secs(900),
                Duration::from_secs(604800),
            ),
        }
    }

    /// Helper: build a request and split into Parts for the extractor.
    fn parts_from_request(req: Request<()>) -> Parts {
        let (parts, _body) = req.into_parts();
        parts
    }

    // =========================================================================
    // AuthUser extractor tests
    // =========================================================================

    #[tokio::test]
    async fn test_auth_user_missing_header() {
        let state = test_state();
        let req = Request::builder().uri("/").body(()).unwrap();
        let mut parts = parts_from_request(req);

        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_user_no_bearer_prefix() {
        let state = test_state();
        let req = Request::builder()
            .uri("/")
            .header(AUTHORIZATION, "Token abc123")
            .body(())
            .unwrap();
        let mut parts = parts_from_request(req);

        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_user_empty_token() {
        let state = test_state();
        let req = Request::builder()
            .uri("/")
            .header(AUTHORIZATION, "Bearer ")
            .body(())
            .unwrap();
        let mut parts = parts_from_request(req);

        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_user_invalid_jwt() {
        let state = test_state();
        let req = Request::builder()
            .uri("/")
            .header(AUTHORIZATION, "Bearer not-a-jwt")
            .body(())
            .unwrap();
        let mut parts = parts_from_request(req);

        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_user_wrong_secret() {
        let state = test_state();
        // Generate token with a different secret
        let other_manager = JwtManager::new(
            "different-secret-at-least-32-chars-long",
            Duration::from_secs(900),
            Duration::from_secs(604800),
        );
        let user_id = Uuid::new_v4();
        let token = other_manager
            .generate_access_token(user_id, "test@example.com")
            .unwrap();

        let req = Request::builder()
            .uri("/")
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap();
        let mut parts = parts_from_request(req);

        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auth_user_valid_jwt() {
        let state = test_state();
        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let token = state
            .jwt_manager
            .generate_access_token(user_id, email)
            .unwrap();

        let req = Request::builder()
            .uri("/")
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap();
        let mut parts = parts_from_request(req);

        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        let auth_user = result.unwrap();
        assert_eq!(auth_user.user_id, user_id);
        assert_eq!(auth_user.email, email);
    }

    // =========================================================================
    // OptionalAuthUser extractor tests
    // =========================================================================

    #[tokio::test]
    async fn test_optional_auth_user_missing_header_returns_none() {
        let state = test_state();
        let req = Request::builder().uri("/").body(()).unwrap();
        let mut parts = parts_from_request(req);

        let result = OptionalAuthUser::from_request_parts(&mut parts, &state).await;
        let optional = result.unwrap();
        assert!(optional.0.is_none());
    }

    #[tokio::test]
    async fn test_optional_auth_user_valid_token_returns_some() {
        let state = test_state();
        let user_id = Uuid::new_v4();
        let token = state
            .jwt_manager
            .generate_access_token(user_id, "test@example.com")
            .unwrap();

        let req = Request::builder()
            .uri("/")
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .body(())
            .unwrap();
        let mut parts = parts_from_request(req);

        let result = OptionalAuthUser::from_request_parts(&mut parts, &state).await;
        let optional = result.unwrap();
        assert!(optional.0.is_some());
        assert_eq!(optional.0.unwrap().user_id, user_id);
    }
}
