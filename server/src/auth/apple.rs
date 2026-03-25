//! Apple Sign In OAuth2 authentication flow.
//!
//! Apple Sign In uses JWT client assertions for token exchange,
//! which is different from Google's simpler OAuth flow.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, CsrfToken, RedirectUrl, Scope,
    TokenUrl,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::error::{AppError, AppResult};

/// Apple's JWKS endpoint.
const APPLE_JWKS_URL: &str = "https://appleid.apple.com/auth/keys";

/// Apple JWKS cache TTL in seconds (1 hour).
const JWKS_CACHE_TTL_SECS: u64 = 3600;

/// Apple JSON Web Key Set response.
#[derive(Debug, Clone, Deserialize)]
struct AppleJwks {
    keys: Vec<AppleJwk>,
}

/// Individual Apple JSON Web Key.
#[derive(Debug, Clone, Deserialize)]
struct AppleJwk {
    /// Key ID.
    kid: String,
    /// RSA modulus (base64url).
    n: String,
    /// RSA exponent (base64url).
    e: String,
}

/// Cached Apple JWKS with expiration.
#[derive(Clone)]
struct CachedJwks {
    keys: Vec<AppleJwk>,
    fetched_at: u64,
}

/// Shared JWKS cache.
type JwksCache = Arc<RwLock<Option<CachedJwks>>>;

/// Apple user info extracted from the ID token.
#[derive(Debug, Clone, Deserialize)]
pub struct AppleUserInfo {
    /// Apple's unique user identifier (sub claim from ID token).
    pub id: String,
    /// User's email address.
    pub email: String,
    /// User's name (only provided on first sign-in, may be None).
    pub name: Option<String>,
}

/// Claims for Apple's client secret JWT.
#[derive(Debug, Serialize)]
struct AppleClientSecretClaims {
    iss: String,
    iat: i64,
    exp: i64,
    aud: String,
    sub: String,
}

/// Claims from Apple's ID token.
#[derive(Debug, Deserialize)]
struct AppleIdTokenClaims {
    /// Subject - Apple's unique user identifier.
    sub: String,
    /// User's email.
    email: Option<String>,
    /// Whether email is verified.
    /// Apple may send this as a string ("true"/"false") or a boolean — handle both.
    #[serde(default, deserialize_with = "deserialize_bool_or_string")]
    email_verified: Option<bool>,
}

/// Deserialize a value that may be a boolean or a string representation of a boolean.
fn deserialize_bool_or_string<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct BoolOrStringVisitor;

    impl<'de> de::Visitor<'de> for BoolOrStringVisitor {
        type Value = Option<bool>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a boolean or a string")
        }

        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
            Ok(Some(v))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(Some(v.eq_ignore_ascii_case("true")))
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    }

    deserializer.deserialize_any(BoolOrStringVisitor)
}

/// Apple token response.
#[derive(Debug, Deserialize)]
struct AppleTokenResponse {
    // access_token: String,
    // token_type: String,
    // expires_in: u64,
    // refresh_token: Option<String>,
    id_token: String,
}

/// Apple OAuth client wrapper.
#[derive(Clone)]
pub struct AppleOAuth {
    client_id: String,       // Service ID (e.g., app.handrive.signin)
    team_id: String,         // Apple Developer Team ID
    key_id: String,          // Key ID from Apple Developer Console
    private_key: String,     // .p8 private key contents
    default_redirect_uri: String,
    http_client: reqwest::Client,
    /// Cached Apple JWKS for ID token verification.
    jwks_cache: JwksCache,
}

/// Response from the authorization URL request.
#[derive(Debug, Serialize)]
pub struct AuthUrlResponse {
    pub url: String,
}

impl AppleOAuth {
    /// Create a new Apple OAuth client from config.
    pub fn new(config: &Config) -> AppResult<Self> {
        let client_id = config
            .apple_client_id
            .clone()
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("APPLE_CLIENT_ID not configured")))?;
        let team_id = config
            .apple_team_id
            .clone()
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("APPLE_TEAM_ID not configured")))?;
        let key_id = config
            .apple_key_id
            .clone()
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("APPLE_KEY_ID not configured")))?;
        let private_key = config.apple_private_key.clone().ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!("APPLE_PRIVATE_KEY not configured"))
        })?;
        let redirect_uri = config.apple_redirect_uri.clone().ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!("APPLE_REDIRECT_URI not configured"))
        })?;

        Ok(Self {
            client_id,
            team_id,
            key_id,
            private_key,
            default_redirect_uri: redirect_uri,
            http_client: reqwest::Client::new(),
            jwks_cache: Arc::new(RwLock::new(None)),
        })
    }

    /// Check if Apple OAuth is configured.
    pub fn is_configured(config: &Config) -> bool {
        config.apple_client_id.is_some()
            && config.apple_team_id.is_some()
            && config.apple_key_id.is_some()
            && config.apple_private_key.is_some()
            && config.apple_redirect_uri.is_some()
    }

    /// Generate the client secret JWT for Apple.
    ///
    /// Apple requires a signed JWT instead of a simple client_secret.
    fn generate_client_secret(&self) -> AppResult<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("System time error: {}", e)))?
            .as_secs() as i64;
        let exp = now + 86400 * 180; // 180 days max

        let claims = AppleClientSecretClaims {
            iss: self.team_id.clone(),
            iat: now,
            exp,
            aud: "https://appleid.apple.com".to_string(),
            sub: self.client_id.clone(),
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());

        let key = EncodingKey::from_ec_pem(self.private_key.as_bytes()).map_err(|e| {
            tracing::error!(error = ?e, "Failed to parse Apple private key");
            AppError::Internal(anyhow::anyhow!("Failed to parse Apple private key"))
        })?;

        encode(&header, &claims, &key).map_err(|e| {
            tracing::error!(error = ?e, "Failed to generate Apple client secret");
            AppError::Internal(anyhow::anyhow!("Failed to generate Apple client secret"))
        })
    }

    /// Create an OAuth client with the specified redirect URI.
    fn create_client(&self, redirect_uri: &str) -> AppResult<BasicClient> {
        let auth_url = AuthUrl::new("https://appleid.apple.com/auth/authorize".to_string())
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid auth URL: {}", e)))?;

        let token_url = TokenUrl::new("https://appleid.apple.com/auth/token".to_string())
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid token URL: {}", e)))?;

        let redirect_url = RedirectUrl::new(redirect_uri.to_string())
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid redirect URL: {}", e)))?;

        let client = BasicClient::new(
            ClientId::new(self.client_id.clone()),
            None, // Client secret is generated dynamically as JWT
            auth_url,
            Some(token_url),
        )
        .set_redirect_uri(redirect_url);

        Ok(client)
    }

    /// Generate the authorization URL for Apple Sign In.
    /// If redirect_uri is None, uses the default from config.
    /// The csrf_state parameter is an HMAC-signed token for CSRF protection.
    pub fn get_auth_url(&self, redirect_uri: Option<&str>, csrf_state: &str) -> AppResult<AuthUrlResponse> {
        let redirect = redirect_uri.unwrap_or(&self.default_redirect_uri);
        let client = self.create_client(redirect)?;

        let state = csrf_state.to_string();
        let (auth_url, _csrf_token) = client
            .authorize_url(|| CsrfToken::new(state))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("name".to_string()))
            .add_extra_param("response_mode", "form_post")
            .url();

        Ok(AuthUrlResponse {
            url: auth_url.to_string(),
        })
    }

    /// Exchange the authorization code for tokens and extract user info.
    /// If redirect_uri is None, uses the default from config.
    pub async fn exchange_code(
        &self,
        code: &str,
        _id_token: Option<&str>,
        redirect_uri: Option<&str>,
    ) -> AppResult<AppleUserInfo> {
        let redirect = redirect_uri.unwrap_or(&self.default_redirect_uri);
        let client_secret = self.generate_client_secret()?;

        // Exchange code for tokens using direct HTTP request
        // (oauth2 crate doesn't support dynamic client_secret well)
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect),
            ("client_id", &self.client_id),
            ("client_secret", &client_secret),
        ];

        let response = self
            .http_client
            .post("https://appleid.apple.com/auth/token")
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to exchange Apple code");
                AppError::InvalidCredentials
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            tracing::error!(status = %status, body = %body, "Apple token exchange failed");
            return Err(AppError::InvalidCredentials);
        }

        let token_response: AppleTokenResponse = response.json().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to parse Apple token response");
            AppError::Internal(anyhow::anyhow!("Failed to parse token response"))
        })?;

        // Verify and decode ID token using Apple's public keys
        let claims = self.verify_id_token(&token_response.id_token).await?;

        // Apple emails are always verified, but log if unexpected
        if claims.email_verified != Some(true) {
            tracing::warn!(verified = ?claims.email_verified, "Apple email_verified claim unexpected");
        }

        let email = claims.email.ok_or_else(|| {
            tracing::error!("Apple ID token missing email claim");
            AppError::Internal(anyhow::anyhow!("Email not provided by Apple"))
        })?;

        Ok(AppleUserInfo {
            id: claims.sub,
            email,
            name: None, // Apple only provides name on first sign-in via form_post
        })
    }

    /// Verify an Apple ID token signature and claims using Apple's public keys.
    async fn verify_id_token(&self, id_token: &str) -> AppResult<AppleIdTokenClaims> {
        // Decode header to get kid (key ID)
        let header = jsonwebtoken::decode_header(id_token).map_err(|e| {
            tracing::error!(error = %e, "Failed to decode Apple ID token header");
            AppError::Internal(anyhow::anyhow!("Invalid ID token header"))
        })?;

        let kid = header.kid.ok_or_else(|| {
            tracing::error!("Apple ID token header missing kid");
            AppError::Internal(anyhow::anyhow!("ID token missing key ID"))
        })?;

        // Get Apple's public keys (cached)
        let jwks = self.get_apple_jwks().await?;

        // Find the matching key
        let jwk = jwks
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| {
                tracing::error!(kid = %kid, "No matching Apple public key found");
                AppError::Internal(anyhow::anyhow!("No matching Apple public key"))
            })?;

        // Build decoding key from RSA components
        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| {
            tracing::error!(error = %e, "Failed to build decoding key from Apple JWK");
            AppError::Internal(anyhow::anyhow!("Invalid Apple public key"))
        })?;

        // Validate token: signature, expiration, issuer, audience
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["https://appleid.apple.com"]);
        validation.set_audience(&[&self.client_id]);
        validation.validate_exp = true;

        let token_data = decode::<AppleIdTokenClaims>(id_token, &decoding_key, &validation)
            .map_err(|e| {
                tracing::error!(error = %e, "Apple ID token verification failed");
                AppError::InvalidCredentials
            })?;

        Ok(token_data.claims)
    }

    /// Fetch Apple's JWKS (JSON Web Key Set), using a cache with TTL.
    async fn get_apple_jwks(&self) -> AppResult<Vec<AppleJwk>> {
        // Check cache first
        {
            let cache = self.jwks_cache.read().await;
            if let Some(ref cached) = *cache {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if (now - cached.fetched_at) < JWKS_CACHE_TTL_SECS {
                    return Ok(cached.keys.clone());
                }
            }
        }

        // Fetch fresh JWKS
        let jwks: AppleJwks = self
            .http_client
            .get(APPLE_JWKS_URL)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to fetch Apple JWKS");
                AppError::Internal(anyhow::anyhow!("Failed to fetch Apple public keys"))
            })?
            .json()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to parse Apple JWKS");
                AppError::Internal(anyhow::anyhow!("Failed to parse Apple public keys"))
            })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Update cache
        let keys = jwks.keys.clone();
        {
            let mut cache = self.jwks_cache.write().await;
            *cache = Some(CachedJwks {
                keys: jwks.keys,
                fetched_at: now,
            });
        }

        Ok(keys)
    }
}
