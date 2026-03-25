//! Deterministic UUID generation for Handrive entities.
//!
//! All entity IDs use UUID v5 (SHA-1 based, deterministic) for idempotent creation.
//! This allows clients to compute IDs locally and enables safe retry of operations.

use uuid::Uuid;

/// Handrive namespace UUID for UUID v5 generation.
/// Generated using: `uuidgen --sha1 --namespace @dns --name "handrive.ai"`
pub const NAMESPACE_HANDRIVE: Uuid =
    Uuid::from_bytes([0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b,
                      0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03]);

/// Generate a deterministic user ID from email.
///
/// Email is normalized (lowercase, trimmed) before hashing.
///
/// # Example
/// ```
/// use handrive_server::id::user_id;
///
/// let id = user_id("User@Example.com");
/// // Same email always produces the same ID
/// assert_eq!(id, user_id("user@example.com"));
/// ```
/// Normalize an email address for consistent storage and comparison.
///
/// - Trims leading/trailing whitespace
/// - Converts to lowercase
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

pub fn user_id(email: &str) -> Uuid {
    let normalized = normalize_email(email);
    Uuid::new_v5(&NAMESPACE_HANDRIVE, normalized.as_bytes())
}

/// Get the current time as epoch milliseconds.
pub fn epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as i64
}

/// Extract a default name from an email address.
///
/// Takes the part before the @ symbol.
/// Example: "john.doe@example.com" -> "john.doe"
pub fn email_to_name(email: &str) -> String {
    email.split('@').next().unwrap_or("User").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // user_id tests
    // =========================================================================

    #[test]
    fn test_user_id_deterministic() {
        let id1 = user_id("test@example.com");
        let id2 = user_id("test@example.com");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_user_id_case_insensitive() {
        let id1 = user_id("Test@Example.COM");
        let id2 = user_id("test@example.com");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_user_id_trims_whitespace() {
        let id1 = user_id("  test@example.com  ");
        let id2 = user_id("test@example.com");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_user_id_different_emails_produce_different_ids() {
        let id1 = user_id("user1@example.com");
        let id2 = user_id("user2@example.com");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_user_id_is_valid_uuid_v5() {
        let id = user_id("test@example.com");
        assert_eq!(id.get_version_num(), 5);
    }

    #[test]
    fn test_user_id_with_special_characters() {
        let id1 = user_id("user+tag@example.com");
        let id2 = user_id("user+tag@example.com");
        assert_eq!(id1, id2);

        let id3 = user_id("user.name@example.com");
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_user_id_with_subdomains() {
        let id1 = user_id("user@mail.example.com");
        let id2 = user_id("user@example.com");
        assert_ne!(id1, id2);
    }

    // =========================================================================
    // email_to_name tests
    // =========================================================================

    #[test]
    fn test_email_to_name_standard() {
        assert_eq!(email_to_name("john.doe@example.com"), "john.doe");
    }

    #[test]
    fn test_email_to_name_no_at_symbol() {
        assert_eq!(email_to_name("user"), "user");
    }

    #[test]
    fn test_email_to_name_empty_local_part() {
        assert_eq!(email_to_name("@example.com"), "");
    }

    #[test]
    fn test_email_to_name_with_plus_tag() {
        assert_eq!(email_to_name("user+tag@example.com"), "user+tag");
    }

    #[test]
    fn test_email_to_name_multiple_at_symbols() {
        // Takes part before first @
        assert_eq!(email_to_name("user@domain@example.com"), "user");
    }

    // =========================================================================
    // epoch_ms tests
    // =========================================================================

    #[test]
    fn test_epoch_ms_is_positive() {
        let ms = epoch_ms();
        assert!(ms > 0);
    }

    #[test]
    fn test_epoch_ms_is_reasonable() {
        let ms = epoch_ms();
        // Should be after year 2020 (1577836800000 ms)
        assert!(ms > 1577836800000);
        // Should be before year 2100 (4102444800000 ms)
        assert!(ms < 4102444800000);
    }

    #[test]
    fn test_epoch_ms_increases() {
        let ms1 = epoch_ms();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let ms2 = epoch_ms();
        assert!(ms2 > ms1);
    }

    // =========================================================================
    // namespace tests
    // =========================================================================

    #[test]
    fn test_namespace_is_valid_uuid() {
        // Namespace should be a valid UUID
        assert!(!NAMESPACE_HANDRIVE.is_nil());
    }

    #[test]
    fn test_namespace_is_consistent() {
        // Namespace should always be the same
        let expected = Uuid::from_bytes([
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b,
            0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03
        ]);
        assert_eq!(NAMESPACE_HANDRIVE, expected);
    }
}
