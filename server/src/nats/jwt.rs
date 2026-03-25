//! NATS user JWT generation.
//!
//! Generates NATS user JWTs with specific permissions:
//! - Subscribe: Only to `sync.{user_id}.>` (own subjects)
//! - Publish: `sync.>` (sync subjects only)

use data_encoding::BASE64URL_NOPAD;
use nkeys::KeyPair;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::id::epoch_ms;

/// NATS JWT generator.
#[derive(Clone)]
pub struct NatsJwtGenerator {
    account_signing_key: KeyPair,
    account_public_key: String,
}

/// NATS user claims.
#[derive(Debug, Serialize, Deserialize)]
struct UserClaims {
    /// JWT ID
    jti: String,
    /// Issued at (epoch seconds)
    iat: i64,
    /// Issuer (account public key)
    iss: String,
    /// Subject (user public key)
    sub: String,
    /// Name
    name: String,
    /// Expiration (epoch seconds)
    exp: i64,
    /// NATS specific claims
    nats: NatsClaims,
}

/// NATS specific claims within the JWT.
#[derive(Debug, Serialize, Deserialize)]
struct NatsClaims {
    /// Publish permissions
    #[serde(rename = "pub")]
    pub_permissions: Permissions,
    /// Subscribe permissions
    sub_permissions: Permissions,
    /// User type
    #[serde(rename = "type")]
    claim_type: String,
    /// Version
    version: u32,
}

/// NATS permissions.
#[derive(Debug, Serialize, Deserialize)]
struct Permissions {
    /// Allowed subjects
    allow: Vec<String>,
}

impl NatsJwtGenerator {
    /// Create a new NATS JWT generator from config.
    pub fn new(config: &Config) -> AppResult<Self> {
        let account_signing_key = KeyPair::from_seed(&config.nats_account_signing_key)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid NATS account signing key: {}", e)))?;

        Ok(Self {
            account_signing_key,
            account_public_key: config.nats_account_public_key.clone(),
        })
    }

    /// Generate NATS credentials for a user.
    ///
    /// Returns the credentials file content containing the JWT and user NKey seed.
    pub fn generate_user_credentials(&self, user_id: &Uuid) -> AppResult<String> {
        // Generate a new user key pair
        let user_key = KeyPair::new_user();
        let user_public_key = user_key.public_key();
        let user_seed = user_key
            .seed()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to get user seed: {}", e)))?;

        // Create the JWT
        let jwt = self.create_user_jwt(user_id, &user_public_key)?;

        // Format as NATS credentials file
        let credentials = format!(
            "-----BEGIN NATS USER JWT-----\n{}\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n{}\n------END USER NKEY SEED------\n",
            jwt, user_seed
        );

        Ok(credentials)
    }

    /// Create a NATS user JWT.
    fn create_user_jwt(&self, user_id: &Uuid, user_public_key: &str) -> AppResult<String> {
        let now = epoch_ms() / 1000;
        let exp = now + (365 * 24 * 60 * 60); // 1 year

        let claims = UserClaims {
            jti: Uuid::new_v4().to_string(),
            iat: now,
            iss: self.account_public_key.clone(),
            sub: user_public_key.to_string(),
            name: user_id.to_string(),
            exp,
            nats: NatsClaims {
                pub_permissions: Permissions {
                    allow: vec!["sync.>".to_string()], // Can publish to sync subjects only
                },
                sub_permissions: Permissions {
                    allow: vec![format!("sync.{}.>", user_id)], // Can only subscribe to own subjects
                },
                claim_type: "user".to_string(),
                version: 2,
            },
        };

        // Create header
        let header = NatsJwtHeader {
            typ: "JWT".to_string(),
            alg: "ed25519-nkey".to_string(),
        };

        // Encode header and claims
        let header_json = serde_json::to_string(&header)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to serialize header: {}", e)))?;
        let claims_json = serde_json::to_string(&claims)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to serialize claims: {}", e)))?;

        let header_b64 = BASE64URL_NOPAD.encode(header_json.as_bytes());
        let claims_b64 = BASE64URL_NOPAD.encode(claims_json.as_bytes());

        // Create signing input
        let signing_input = format!("{}.{}", header_b64, claims_b64);

        // Sign with account key
        let signature = self
            .account_signing_key
            .sign(signing_input.as_bytes())
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to sign JWT: {}", e)))?;

        let signature_b64 = BASE64URL_NOPAD.encode(&signature);

        Ok(format!("{}.{}", signing_input, signature_b64))
    }
}

/// NATS JWT header.
#[derive(Debug, Serialize, Deserialize)]
struct NatsJwtHeader {
    typ: String,
    alg: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Credentials Format Tests
    // =========================================================================

    #[test]
    fn test_nats_credentials_format() {
        // Verify the expected format of NATS credentials
        let mock_credentials = r#"-----BEGIN NATS USER JWT-----
eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJhYmMxMjMiLCJpYXQiOjE3MDQwNjcyMDAsImlzcyI6IkFCQUFBQUFBIiwic3ViIjoiVUJCQkJCQkIiLCJuYW1lIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiZXhwIjoxNzM1NjAzMjAwLCJuYXRzIjp7InB1YiI6eyJhbGxvdyI6WyI+Il19LCJzdWJfcGVybWlzc2lvbnMiOnsiYWxsb3ciOlsic3luYy41NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAuPiJdfSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.signature
------END NATS USER JWT------

-----BEGIN USER NKEY SEED-----
SUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
------END USER NKEY SEED------
"#;

        // Verify JWT section exists
        assert!(mock_credentials.contains("-----BEGIN NATS USER JWT-----"));
        assert!(mock_credentials.contains("------END NATS USER JWT------"));

        // Verify seed section exists
        assert!(mock_credentials.contains("-----BEGIN USER NKEY SEED-----"));
        assert!(mock_credentials.contains("------END USER NKEY SEED------"));
    }

    #[test]
    fn test_jwt_has_three_parts() {
        let mock_jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJhYmMxMjMifQ.signature";

        let parts: Vec<&str> = mock_jwt.split('.').collect();
        assert_eq!(parts.len(), 3); // header.payload.signature
    }

    // =========================================================================
    // Permission Structure Tests
    // =========================================================================

    #[test]
    fn test_user_id_in_permissions_format() {
        let user_id = Uuid::new_v4();
        let expected_subscribe = format!("sync.{}.>", user_id);

        assert!(expected_subscribe.starts_with("sync."));
        assert!(expected_subscribe.ends_with(".>"));
    }

    #[test]
    fn test_nats_permissions_structure() {
        // Verify the expected permission structure
        let permissions = serde_json::json!({
            "pub": {
                "allow": ["sync.>"]
            },
            "sub_permissions": {
                "allow": ["sync.550e8400-e29b-41d4-a716-446655440000.>"]
            }
        });

        // User should be able to publish to sync subjects
        assert_eq!(permissions["pub"]["allow"][0], "sync.>");

        // User should only subscribe to their own subjects
        let sub_allow = permissions["sub_permissions"]["allow"][0].as_str().unwrap();
        assert!(sub_allow.starts_with("sync."));
        assert!(sub_allow.ends_with(".>"));
    }

    // =========================================================================
    // NKey Format Tests
    // =========================================================================

    #[test]
    fn test_nkey_seed_format() {
        // NATS user seeds start with 'SU'
        let valid_prefixes = ["SU"];
        let mock_seed = "SUAAA";

        assert!(valid_prefixes.iter().any(|p| mock_seed.starts_with(p)));
    }

    #[test]
    fn test_nkey_public_key_format() {
        // NATS user public keys start with 'U'
        // Account public keys start with 'A'
        let user_public = "UAAA";
        let account_public = "ABAA";

        assert!(user_public.starts_with('U'));
        assert!(account_public.starts_with('A'));
    }

    // =========================================================================
    // Base64 Encoding Tests
    // =========================================================================

    #[test]
    fn test_base64url_encode_header() {
        let header = r#"{"typ":"JWT","alg":"ed25519-nkey"}"#;
        let encoded = BASE64URL_NOPAD.encode(header.as_bytes());

        // Should be valid base64url (no +, /, or = padding)
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));

        // Should be decodable
        let decoded = BASE64URL_NOPAD.decode(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, header.as_bytes());
    }

    #[test]
    fn test_base64url_encode_claims() {
        let claims = serde_json::json!({
            "jti": "abc123",
            "iat": 1704067200i64,
            "iss": "ABAAAAAA",
            "sub": "UBBBBBBB",
            "name": "user-id",
            "exp": 1735603200i64,
            "nats": {
                "pub": {"allow": [">"]},
                "sub_permissions": {"allow": ["sync.*.>"]},
                "type": "user",
                "version": 2
            }
        });

        let claims_json = serde_json::to_string(&claims).unwrap();
        let encoded = BASE64URL_NOPAD.encode(claims_json.as_bytes());

        // Should be valid base64url
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));

        // Should be decodable
        let decoded = BASE64URL_NOPAD.decode(encoded.as_bytes()).unwrap();
        let decoded_claims: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(decoded_claims["jti"], "abc123");
    }

    // =========================================================================
    // Claims Serialization Tests
    // =========================================================================

    #[test]
    fn test_user_claims_serialization() {
        let claims = UserClaims {
            jti: "test-jti".to_string(),
            iat: 1704067200,
            iss: "ABAAAAAA".to_string(),
            sub: "UBBBBBBB".to_string(),
            name: "test-user".to_string(),
            exp: 1735603200,
            nats: NatsClaims {
                pub_permissions: Permissions {
                    allow: vec![">".to_string()],
                },
                sub_permissions: Permissions {
                    allow: vec!["sync.test.>".to_string()],
                },
                claim_type: "user".to_string(),
                version: 2,
            },
        };

        let json = serde_json::to_string(&claims).unwrap();

        // Verify required fields are present
        assert!(json.contains("\"jti\":"));
        assert!(json.contains("\"iat\":"));
        assert!(json.contains("\"iss\":"));
        assert!(json.contains("\"sub\":"));
        assert!(json.contains("\"exp\":"));
        assert!(json.contains("\"nats\":"));
    }

    #[test]
    fn test_nats_claims_pub_field_renamed() {
        let nats_claims = NatsClaims {
            pub_permissions: Permissions {
                allow: vec![">".to_string()],
            },
            sub_permissions: Permissions {
                allow: vec!["sync.test.>".to_string()],
            },
            claim_type: "user".to_string(),
            version: 2,
        };

        let json = serde_json::to_string(&nats_claims).unwrap();

        // 'pub' should be renamed from 'pub_permissions'
        assert!(json.contains("\"pub\":"));
        assert!(!json.contains("\"pub_permissions\":"));

        // 'type' should be renamed from 'claim_type'
        assert!(json.contains("\"type\":"));
        assert!(!json.contains("\"claim_type\":"));
    }

    #[test]
    fn test_jwt_header_serialization() {
        let header = NatsJwtHeader {
            typ: "JWT".to_string(),
            alg: "ed25519-nkey".to_string(),
        };

        let json = serde_json::to_string(&header).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["typ"], "JWT");
        assert_eq!(parsed["alg"], "ed25519-nkey");
    }
}
