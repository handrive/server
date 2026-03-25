//! Input validation utilities.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::error::AppError;

/// Maximum email length (RFC 5321).
pub const MAX_EMAIL_LENGTH: usize = 254;

/// Maximum name length.
pub const MAX_NAME_LENGTH: usize = 255;

/// Maximum URL length.
pub const MAX_URL_LENGTH: usize = 2048;

/// Maximum OTP code length.
pub const MAX_OTP_CODE_LENGTH: usize = 10;

/// Email validation regex (simplified RFC 5322).
static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    ).expect("Invalid email regex")
});

/// Validate an email address.
pub fn validate_email(email: &str) -> Result<(), AppError> {
    if email.is_empty() {
        return Err(AppError::Validation("Email is required".to_string()));
    }

    if email.len() > MAX_EMAIL_LENGTH {
        return Err(AppError::Validation(format!(
            "Email must be at most {} characters",
            MAX_EMAIL_LENGTH
        )));
    }

    if !EMAIL_REGEX.is_match(email) {
        return Err(AppError::Validation("Invalid email address".to_string()));
    }

    Ok(())
}

/// Validate a string field length.
pub fn validate_length(field: &str, value: &str, max_length: usize) -> Result<(), AppError> {
    if value.len() > max_length {
        return Err(AppError::Validation(format!(
            "{} must be at most {} characters",
            field, max_length
        )));
    }
    Ok(())
}

/// Validate an optional string field length.
pub fn validate_optional_length(
    field: &str,
    value: &Option<String>,
    max_length: usize,
) -> Result<(), AppError> {
    if let Some(v) = value {
        validate_length(field, v, max_length)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        assert!(validate_email("test@example.com").is_ok());
        assert!(validate_email("user.name@example.com").is_ok());
        assert!(validate_email("user+tag@example.com").is_ok());
        assert!(validate_email("user@subdomain.example.com").is_ok());
    }

    #[test]
    fn test_invalid_emails() {
        assert!(validate_email("").is_err());
        assert!(validate_email("notanemail").is_err());
        assert!(validate_email("missing@").is_err());
        assert!(validate_email("@nodomain.com").is_err());
        assert!(validate_email("spaces in@email.com").is_err());
        assert!(validate_email("double@@at.com").is_err());
    }

    #[test]
    fn test_email_too_long() {
        let long_email = format!("{}@example.com", "a".repeat(250));
        assert!(validate_email(&long_email).is_err());
    }

    #[test]
    fn test_validate_length() {
        assert!(validate_length("name", "short", 10).is_ok());
        assert!(validate_length("name", "exactly10!", 10).is_ok());
        assert!(validate_length("name", "this is too long", 10).is_err());
    }

    #[test]
    fn test_validate_optional_length() {
        assert!(validate_optional_length("url", &None, 100).is_ok());
        assert!(validate_optional_length("url", &Some("short".to_string()), 100).is_ok());
        assert!(validate_optional_length("url", &Some("x".repeat(101)), 100).is_err());
    }
}
