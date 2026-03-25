//! Application error types and HTTP response conversion.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Application error type that converts to HTTP responses.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Authentication required")]
    Unauthorized,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Resource not found")]
    NotFound,

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("Database error")]
    Database(#[from] sqlx::Error),

    #[error("Internal error")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            AppError::Database(e) => {
                tracing::error!(error = ?e, "Database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            AppError::Internal(e) => {
                tracing::error!(error = ?e, "Internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

/// Result type alias using AppError.
pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn get_response_body(response: Response) -> serde_json::Value {
        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    // =========================================================================
    // Status Code Tests
    // =========================================================================

    #[tokio::test]
    async fn test_unauthorized_status_code() {
        let error = AppError::Unauthorized;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invalid_credentials_status_code() {
        let error = AppError::InvalidCredentials;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_not_found_status_code() {
        let error = AppError::NotFound;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_conflict_status_code() {
        let error = AppError::Conflict("Resource already exists".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_validation_status_code() {
        let error = AppError::Validation("Invalid email format".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_rate_limited_status_code() {
        let error = AppError::RateLimited;
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_internal_error_status_code() {
        let error = AppError::Internal(anyhow::anyhow!("Something went wrong"));
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // =========================================================================
    // Response Body Tests
    // =========================================================================

    #[tokio::test]
    async fn test_unauthorized_response_body() {
        let error = AppError::Unauthorized;
        let response = error.into_response();
        let body = get_response_body(response).await;

        assert_eq!(body["error"], "Authentication required");
    }

    #[tokio::test]
    async fn test_invalid_credentials_response_body() {
        let error = AppError::InvalidCredentials;
        let response = error.into_response();
        let body = get_response_body(response).await;

        assert_eq!(body["error"], "Invalid credentials");
    }

    #[tokio::test]
    async fn test_not_found_response_body() {
        let error = AppError::NotFound;
        let response = error.into_response();
        let body = get_response_body(response).await;

        assert_eq!(body["error"], "Resource not found");
    }

    #[tokio::test]
    async fn test_conflict_response_body() {
        let error = AppError::Conflict("Email already registered".to_string());
        let response = error.into_response();
        let body = get_response_body(response).await;

        assert_eq!(body["error"], "Email already registered");
    }

    #[tokio::test]
    async fn test_validation_response_body() {
        let error = AppError::Validation("Name is required".to_string());
        let response = error.into_response();
        let body = get_response_body(response).await;

        assert_eq!(body["error"], "Name is required");
    }

    #[tokio::test]
    async fn test_rate_limited_response_body() {
        let error = AppError::RateLimited;
        let response = error.into_response();
        let body = get_response_body(response).await;

        assert_eq!(body["error"], "Rate limit exceeded");
    }

    #[tokio::test]
    async fn test_internal_error_hides_details() {
        let error = AppError::Internal(anyhow::anyhow!("Sensitive database connection string"));
        let response = error.into_response();
        let body = get_response_body(response).await;

        // Should NOT expose internal error details
        assert_eq!(body["error"], "Internal server error");
        assert!(!body["error"].to_string().contains("database"));
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_unauthorized_display() {
        let error = AppError::Unauthorized;
        assert_eq!(error.to_string(), "Authentication required");
    }

    #[test]
    fn test_invalid_credentials_display() {
        let error = AppError::InvalidCredentials;
        assert_eq!(error.to_string(), "Invalid credentials");
    }

    #[test]
    fn test_not_found_display() {
        let error = AppError::NotFound;
        assert_eq!(error.to_string(), "Resource not found");
    }

    #[test]
    fn test_conflict_display() {
        let error = AppError::Conflict("Duplicate entry".to_string());
        assert_eq!(error.to_string(), "Conflict: Duplicate entry");
    }

    #[test]
    fn test_validation_display() {
        let error = AppError::Validation("Invalid input".to_string());
        assert_eq!(error.to_string(), "Validation error: Invalid input");
    }

    #[test]
    fn test_rate_limited_display() {
        let error = AppError::RateLimited;
        assert_eq!(error.to_string(), "Rate limit exceeded");
    }

    #[test]
    fn test_internal_display() {
        let error = AppError::Internal(anyhow::anyhow!("Test error"));
        assert_eq!(error.to_string(), "Internal error");
    }

    // =========================================================================
    // Error Conversion Tests
    // =========================================================================

    #[test]
    fn test_anyhow_error_conversion() {
        let anyhow_error = anyhow::anyhow!("Something went wrong");
        let app_error: AppError = anyhow_error.into();

        matches!(app_error, AppError::Internal(_));
    }

    // =========================================================================
    // AppResult Tests
    // =========================================================================

    #[test]
    fn test_app_result_ok() {
        let result: AppResult<i32> = Ok(42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_app_result_err() {
        let result: AppResult<i32> = Err(AppError::NotFound);
        assert!(result.is_err());
    }

    #[test]
    fn test_app_result_with_question_mark() {
        fn inner() -> AppResult<i32> {
            Err(AppError::Unauthorized)
        }

        fn outer() -> AppResult<i32> {
            let value = inner()?;
            Ok(value + 1)
        }

        assert!(outer().is_err());
    }

    // =========================================================================
    // Debug Tests
    // =========================================================================

    #[test]
    fn test_error_debug() {
        let error = AppError::Validation("test".to_string());
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("Validation"));
        assert!(debug_str.contains("test"));
    }
}
