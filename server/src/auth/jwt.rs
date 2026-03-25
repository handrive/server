//! JWT token generation and validation.

use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::id::epoch_ms;

/// CSRF state token validity window in seconds (10 minutes).
const CSRF_STATE_TTL_SECS: i64 = 600;

type HmacSha256 = Hmac<Sha256>;

/// JWT claims for access tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    /// Subject (user ID)
    pub sub: String,
    /// User email
    pub email: String,
    /// Issued at (epoch seconds)
    pub iat: i64,
    /// Expiration (epoch seconds)
    pub exp: i64,
}

/// JWT manager for generating and validating tokens.
#[derive(Clone)]
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    /// Raw secret bytes for HMAC-based CSRF state tokens.
    secret_bytes: Vec<u8>,
    access_ttl: Duration,
    refresh_ttl: Duration,
}

impl JwtManager {
    /// Create a new JWT manager.
    pub fn new(secret: &str, access_ttl: Duration, refresh_ttl: Duration) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            secret_bytes: secret.as_bytes().to_vec(),
            access_ttl,
            refresh_ttl,
        }
    }

    /// Generate an access token.
    pub fn generate_access_token(&self, user_id: Uuid, email: &str) -> AppResult<String> {
        let now = epoch_ms() / 1000; // Convert to seconds
        let exp = now + self.access_ttl.as_secs() as i64;

        let claims = AccessClaims {
            sub: user_id.to_string(),
            email: email.to_string(),
            iat: now,
            exp,
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("JWT encoding error: {}", e)))
    }

    /// Validate an access token and return claims.
    pub fn validate_access_token(&self, token: &str) -> AppResult<AccessClaims> {
        let mut validation = Validation::default();
        validation.validate_exp = true;

        decode::<AccessClaims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                tracing::debug!(error = %e, "JWT validation failed");
                AppError::Unauthorized
            })
    }

    /// Generate a refresh token (random, not JWT).
    pub fn generate_refresh_token(&self) -> String {
        // Generate 32 random bytes and encode as hex
        let mut bytes = [0u8; 32];
        getrandom(&mut bytes);
        hex::encode(bytes)
    }

    /// Hash a refresh token for storage.
    pub fn hash_refresh_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Get the refresh token TTL in milliseconds.
    pub fn refresh_ttl_ms(&self) -> i64 {
        self.refresh_ttl.as_millis() as i64
    }

    /// Get the access token TTL in seconds.
    pub fn access_ttl_secs(&self) -> u64 {
        self.access_ttl.as_secs()
    }

    /// Get the refresh token TTL in seconds.
    pub fn refresh_ttl_secs(&self) -> u64 {
        self.refresh_ttl.as_secs()
    }

    /// Generate an HMAC-signed CSRF state token for OAuth flows.
    ///
    /// Format: `{timestamp_secs}.{hex_hmac}` — stateless and verifiable.
    pub fn generate_csrf_state(&self) -> String {
        let timestamp = epoch_ms() / 1000;
        let mut mac = HmacSha256::new_from_slice(&self.secret_bytes)
            .expect("HMAC can take any key size");
        mac.update(format!("csrf:{}", timestamp).as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        format!("{}.{}", timestamp, signature)
    }

    /// Verify a CSRF state token. Returns true if valid and not expired.
    pub fn verify_csrf_state(&self, state: &str) -> bool {
        let parts: Vec<&str> = state.splitn(2, '.').collect();
        if parts.len() != 2 {
            return false;
        }

        let timestamp: i64 = match parts[0].parse() {
            Ok(t) => t,
            Err(_) => return false,
        };

        // Check expiration
        let now = epoch_ms() / 1000;
        if (now - timestamp) > CSRF_STATE_TTL_SECS || timestamp > now + 60 {
            return false;
        }

        // Verify HMAC
        let mut mac = HmacSha256::new_from_slice(&self.secret_bytes)
            .expect("HMAC can take any key size");
        mac.update(format!("csrf:{}", timestamp).as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        expected == parts[1]
    }
}

/// Generate random bytes using getrandom.
fn getrandom(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manager() -> JwtManager {
        JwtManager::new(
            "test-secret-key-at-least-32-chars",
            Duration::from_secs(900),
            Duration::from_secs(604800),
        )
    }

    // =========================================================================
    // Access Token Tests
    // =========================================================================

    #[test]
    fn test_access_token_roundtrip() {
        let manager = test_manager();
        let user_id = Uuid::new_v4();
        let email = "test@example.com";

        let token = manager.generate_access_token(user_id, email).unwrap();
        let claims = manager.validate_access_token(&token).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
    }

    #[test]
    fn test_access_token_contains_all_claims() {
        let manager = test_manager();
        let user_id = Uuid::new_v4();
        let email = "test@example.com";

        let token = manager.generate_access_token(user_id, email).unwrap();
        let claims = manager.validate_access_token(&token).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
        assert!(claims.iat > 0);
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn test_access_token_expiration_is_correct() {
        let ttl_secs = 900u64;
        let manager = JwtManager::new(
            "test-secret-key-at-least-32-chars",
            Duration::from_secs(ttl_secs),
            Duration::from_secs(604800),
        );
        let user_id = Uuid::new_v4();

        let token = manager.generate_access_token(user_id, "test@example.com").unwrap();
        let claims = manager.validate_access_token(&token).unwrap();

        // exp should be approximately iat + ttl (allow 5 second tolerance)
        let expected_exp = claims.iat + ttl_secs as i64;
        assert!((claims.exp - expected_exp).abs() <= 5);
    }

    #[test]
    fn test_access_token_invalid_signature() {
        let manager1 = JwtManager::new(
            "secret-key-1-at-least-32-chars",
            Duration::from_secs(900),
            Duration::from_secs(604800),
        );
        let manager2 = JwtManager::new(
            "secret-key-2-at-least-32-chars",
            Duration::from_secs(900),
            Duration::from_secs(604800),
        );

        let user_id = Uuid::new_v4();
        let token = manager1.generate_access_token(user_id, "test@example.com").unwrap();

        // Token signed with manager1 should not validate with manager2
        let result = manager2.validate_access_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_access_token_malformed() {
        let manager = test_manager();

        // Empty token
        assert!(manager.validate_access_token("").is_err());

        // Random string
        assert!(manager.validate_access_token("not-a-valid-jwt").is_err());

        // Partially valid format
        assert!(manager.validate_access_token("header.payload.signature").is_err());
    }

    #[test]
    fn test_access_token_tampered() {
        let manager = test_manager();
        let user_id = Uuid::new_v4();

        let token = manager.generate_access_token(user_id, "test@example.com").unwrap();

        // Tamper with the token by changing a character
        let mut tampered = token.clone();
        let bytes = unsafe { tampered.as_bytes_mut() };
        if !bytes.is_empty() {
            bytes[bytes.len() / 2] = b'X';
        }

        assert!(manager.validate_access_token(&tampered).is_err());
    }

    #[test]
    fn test_access_token_different_users() {
        let manager = test_manager();
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        let token1 = manager.generate_access_token(user1, "user1@example.com").unwrap();
        let token2 = manager.generate_access_token(user2, "user2@example.com").unwrap();

        assert_ne!(token1, token2);

        let claims1 = manager.validate_access_token(&token1).unwrap();
        let claims2 = manager.validate_access_token(&token2).unwrap();

        assert_eq!(claims1.sub, user1.to_string());
        assert_eq!(claims2.sub, user2.to_string());
    }

    #[test]
    fn test_access_token_same_user_different_times() {
        let manager = test_manager();
        let user_id = Uuid::new_v4();

        let token1 = manager.generate_access_token(user_id, "test@example.com").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let token2 = manager.generate_access_token(user_id, "test@example.com").unwrap();

        // Tokens might be different due to different iat values
        // But both should validate to the same user
        let claims1 = manager.validate_access_token(&token1).unwrap();
        let claims2 = manager.validate_access_token(&token2).unwrap();

        assert_eq!(claims1.sub, claims2.sub);
        assert_eq!(claims1.email, claims2.email);
    }

    // =========================================================================
    // Refresh Token Tests
    // =========================================================================

    #[test]
    fn test_refresh_token_generation() {
        let manager = test_manager();
        let token = manager.generate_refresh_token();

        // Should be 64 characters (32 bytes hex encoded)
        assert_eq!(token.len(), 64);

        // Should be valid hex
        assert!(hex::decode(&token).is_ok());
    }

    #[test]
    fn test_refresh_token_uniqueness() {
        let manager = test_manager();

        let tokens: Vec<String> = (0..100)
            .map(|_| manager.generate_refresh_token())
            .collect();

        // All tokens should be unique
        let mut unique_tokens = tokens.clone();
        unique_tokens.sort();
        unique_tokens.dedup();
        assert_eq!(tokens.len(), unique_tokens.len());
    }

    #[test]
    fn test_refresh_token_hash_deterministic() {
        let manager = test_manager();
        let token = manager.generate_refresh_token();

        let hash1 = manager.hash_refresh_token(&token);
        let hash2 = manager.hash_refresh_token(&token);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_refresh_token_hash_different_tokens() {
        let manager = test_manager();
        let token1 = manager.generate_refresh_token();
        let token2 = manager.generate_refresh_token();

        let hash1 = manager.hash_refresh_token(&token1);
        let hash2 = manager.hash_refresh_token(&token2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_refresh_token_hash_length() {
        let manager = test_manager();
        let token = manager.generate_refresh_token();
        let hash = manager.hash_refresh_token(&token);

        // SHA256 produces 32 bytes = 64 hex characters
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_refresh_token_hash_is_valid_hex() {
        let manager = test_manager();
        let token = manager.generate_refresh_token();
        let hash = manager.hash_refresh_token(&token);

        assert!(hex::decode(&hash).is_ok());
    }

    // =========================================================================
    // TTL Tests
    // =========================================================================

    #[test]
    fn test_access_ttl_secs() {
        let manager = JwtManager::new(
            "test-secret-key-at-least-32-chars",
            Duration::from_secs(900),
            Duration::from_secs(604800),
        );

        assert_eq!(manager.access_ttl_secs(), 900);
    }

    #[test]
    fn test_refresh_ttl_ms() {
        let manager = JwtManager::new(
            "test-secret-key-at-least-32-chars",
            Duration::from_secs(900),
            Duration::from_secs(604800),
        );

        assert_eq!(manager.refresh_ttl_ms(), 604800 * 1000);
    }

    #[test]
    fn test_custom_ttl_values() {
        let access_ttl = 300u64;  // 5 minutes
        let refresh_ttl = 86400u64;  // 1 day

        let manager = JwtManager::new(
            "test-secret-key-at-least-32-chars",
            Duration::from_secs(access_ttl),
            Duration::from_secs(refresh_ttl),
        );

        assert_eq!(manager.access_ttl_secs(), access_ttl);
        assert_eq!(manager.refresh_ttl_ms(), (refresh_ttl * 1000) as i64);
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_access_token_with_special_email() {
        let manager = test_manager();
        let user_id = Uuid::new_v4();

        // Email with special characters
        let emails = [
            "user+tag@example.com",
            "user.name@example.com",
            "user@subdomain.example.com",
            "user@example.co.uk",
        ];

        for email in emails {
            let token = manager.generate_access_token(user_id, email).unwrap();
            let claims = manager.validate_access_token(&token).unwrap();
            assert_eq!(claims.email, email);
        }
    }

    #[test]
    fn test_access_token_with_empty_email() {
        let manager = test_manager();
        let user_id = Uuid::new_v4();

        // Empty email should still work (validation is not JWT's job)
        let token = manager.generate_access_token(user_id, "").unwrap();
        let claims = manager.validate_access_token(&token).unwrap();
        assert_eq!(claims.email, "");
    }

    #[test]
    fn test_refresh_token_hash_empty_string() {
        let manager = test_manager();
        let hash = manager.hash_refresh_token("");

        // Should still produce a valid hash
        assert_eq!(hash.len(), 64);
        assert!(hex::decode(&hash).is_ok());
    }

    #[test]
    fn test_manager_clone() {
        let manager1 = test_manager();
        let manager2 = manager1.clone();

        let user_id = Uuid::new_v4();
        let token = manager1.generate_access_token(user_id, "test@example.com").unwrap();

        // Cloned manager should be able to validate tokens from original
        let claims = manager2.validate_access_token(&token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
    }
}
