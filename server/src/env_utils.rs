//! Environment variable utilities for consistent configuration parsing.

use std::str::FromStr;

/// Get an environment variable with a default value.
///
/// Parses the value into the target type, using the default if the variable
/// is not set or cannot be parsed.
pub fn get_env_or_default<T>(key: &str, default: T) -> T
where
    T: FromStr,
{
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Get a required environment variable as a string.
///
/// Returns None if the variable is not set.
pub fn get_env_required(key: &'static str) -> Result<String, &'static str> {
    std::env::var(key).map_err(|_| key)
}

/// Get an environment variable as a string with a default value.
pub fn get_env_string_or_default(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Get an environment variable as a boolean.
///
/// Recognizes "1", "true" (case-insensitive) as true, everything else as false.
pub fn get_env_bool(key: &str) -> bool {
    std::env::var(key)
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_get_env_or_default_missing() {
        let result: u32 = get_env_or_default("NONEXISTENT_TEST_VAR_12345", 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_get_env_string_or_default() {
        let result = get_env_string_or_default("NONEXISTENT_TEST_VAR_12345", "default");
        assert_eq!(result, "default");
    }

    #[test]
    fn test_get_env_bool_false() {
        let result = get_env_bool("NONEXISTENT_TEST_VAR_12345");
        assert!(!result);
    }

    #[test]
    fn test_get_env_bool_true() {
        env::set_var("TEST_BOOL_VAR", "true");
        let result = get_env_bool("TEST_BOOL_VAR");
        env::remove_var("TEST_BOOL_VAR");
        assert!(result);
    }

    #[test]
    fn test_get_env_bool_one() {
        env::set_var("TEST_BOOL_VAR_ONE", "1");
        let result = get_env_bool("TEST_BOOL_VAR_ONE");
        env::remove_var("TEST_BOOL_VAR_ONE");
        assert!(result);
    }
}
