//! Identity credential generator for NATS message authentication.
//!
//! This module provides server-side Ed25519 signing of identity credentials.
//! Clients include these credentials in NATS messages to prove their identity.

use base64::Engine;
use ed25519_dalek::{SigningKey, Signer};
use serde::{Deserialize, Serialize};

use crate::error::AppResult;
use crate::id::epoch_ms;

/// Identity credential signed by the server.
///
/// The server creates this at login/refresh. The client includes it
/// in NATS messages to prove their identity. User ID is computed from
/// email using `user_id(&email)` on the client side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityCredential {
    /// User email (user_id is computed from this on the client).
    pub email: String,
    /// When issued (Unix seconds).
    pub issued_at: i64,
    /// When it expires (Unix seconds).
    pub expires_at: i64,
    /// Ed25519 signature over the claims (base64 encoded).
    pub signature: String,
}

/// Generator for identity credentials.
///
/// Stores the Ed25519 signing key and generates credentials for users.
#[derive(Clone)]
pub struct IdentityGenerator {
    signing_key: SigningKey,
    public_key_b64: String,
}

impl IdentityGenerator {
    /// Create from base64-encoded seed, or generate new keypair.
    ///
    /// # Arguments
    /// * `seed_b64` - Optional base64-encoded 32-byte seed. If None, generates ephemeral keypair.
    pub fn new(seed_b64: Option<&str>) -> AppResult<Self> {
        let signing_key = match seed_b64 {
            Some(seed) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(seed)
                    .map_err(|e| anyhow::anyhow!("Invalid identity signing key encoding: {}", e))?;

                let seed_bytes: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Identity signing key must be 32 bytes"))?;

                SigningKey::from_bytes(&seed_bytes)
            }
            None => {
                tracing::warn!(
                    "No IDENTITY_SIGNING_KEY set, generating ephemeral keypair. \
                     This is not recommended for production as credentials will be \
                     invalidated on server restart."
                );
                SigningKey::generate(&mut rand::rngs::OsRng)
            }
        };

        let verifying_key = signing_key.verifying_key();
        let public_key_b64 = base64::engine::general_purpose::STANDARD
            .encode(verifying_key.as_bytes());

        tracing::info!(
            public_key = %public_key_b64,
            "Identity generator initialized"
        );

        Ok(Self {
            signing_key,
            public_key_b64,
        })
    }

    /// Get the server's public key (base64 encoded).
    ///
    /// Clients use this to verify credentials.
    pub fn public_key(&self) -> &str {
        &self.public_key_b64
    }

    /// Create an identity credential for a user.
    ///
    /// # Arguments
    /// * `email` - User's email address
    /// * `ttl_secs` - Time-to-live in seconds (typically matches access token TTL)
    pub fn create_credential(&self, email: &str, ttl_secs: i64) -> IdentityCredential {
        let now_secs = epoch_ms() / 1000;
        let issued_at = now_secs;
        let expires_at = now_secs + ttl_secs;

        // Sign: email|issued_at|expires_at
        let signing_bytes = format!("{}|{}|{}", email, issued_at, expires_at);
        let signature = self.signing_key.sign(signing_bytes.as_bytes());

        IdentityCredential {
            email: email.to_string(),
            issued_at,
            expires_at,
            signature: base64::engine::general_purpose::STANDARD
                .encode(signature.to_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generator_ephemeral() {
        let gen = IdentityGenerator::new(None).unwrap();
        assert!(!gen.public_key().is_empty());
    }

    #[test]
    fn test_identity_generator_from_seed() {
        // Generate a valid 32-byte seed
        let seed = base64::engine::general_purpose::STANDARD
            .encode([0u8; 32]);

        let gen = IdentityGenerator::new(Some(&seed)).unwrap();
        assert!(!gen.public_key().is_empty());
    }

    #[test]
    fn test_create_credential() {
        let gen = IdentityGenerator::new(None).unwrap();
        let cred = gen.create_credential("test@example.com", 3600);

        assert_eq!(cred.email, "test@example.com");
        assert!(cred.expires_at > cred.issued_at);
        assert_eq!(cred.expires_at - cred.issued_at, 3600);
        assert!(!cred.signature.is_empty());
    }

    #[test]
    fn test_invalid_seed() {
        // Too short
        let result = IdentityGenerator::new(Some("dG9vIHNob3J0"));
        assert!(result.is_err());

        // Invalid base64
        let result = IdentityGenerator::new(Some("not valid base64!!!"));
        assert!(result.is_err());
    }
}
