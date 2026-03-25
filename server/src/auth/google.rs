//! Google OAuth2 authentication flow.

use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::{AppError, AppResult};

/// Google user info from the userinfo endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct GoogleUserInfo {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    #[serde(rename = "picture")]
    pub avatar_url: Option<String>,
    pub verified_email: Option<bool>,
}

/// Google OAuth client wrapper.
#[derive(Clone)]
pub struct GoogleOAuth {
    client_id: String,
    client_secret: String,
    default_redirect_uri: String,
    http_client: reqwest::Client,
}

/// Response from the authorization URL request.
#[derive(Debug, Serialize)]
pub struct AuthUrlResponse {
    pub url: String,
}

impl GoogleOAuth {
    /// Create a new Google OAuth client from config.
    pub fn new(config: &Config) -> AppResult<Self> {
        Ok(Self {
            client_id: config.google_client_id.clone(),
            client_secret: config.google_client_secret.clone(),
            default_redirect_uri: config.google_redirect_uri.clone(),
            http_client: reqwest::Client::new(),
        })
    }

    /// Create an OAuth client with the specified redirect URI.
    fn create_client(&self, redirect_uri: &str) -> AppResult<BasicClient> {
        let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid auth URL: {}", e)))?;

        let token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid token URL: {}", e)))?;

        let redirect_url = RedirectUrl::new(redirect_uri.to_string())
            .map_err(|e| AppError::Internal(anyhow::anyhow!("Invalid redirect URL: {}", e)))?;

        let client = BasicClient::new(
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
            auth_url,
            Some(token_url),
        )
        .set_redirect_uri(redirect_url);

        Ok(client)
    }

    /// Generate the authorization URL for Google OAuth.
    /// If redirect_uri is None, uses the default from config.
    /// The csrf_state parameter is an HMAC-signed token for CSRF protection.
    pub fn get_auth_url(&self, redirect_uri: Option<&str>, csrf_state: &str) -> AppResult<AuthUrlResponse> {
        let redirect = redirect_uri.unwrap_or(&self.default_redirect_uri);
        let client = self.create_client(redirect)?;

        let state = csrf_state.to_string();
        let (auth_url, _csrf_token) = client
            .authorize_url(|| CsrfToken::new(state))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            // Force account selection to prevent auto-completing OAuth flow
            // when user has previously authenticated (fixes Windows/Linux re-login)
            .add_extra_param("prompt", "select_account")
            .url();

        Ok(AuthUrlResponse {
            url: auth_url.to_string(),
        })
    }

    /// Exchange the authorization code for tokens and fetch user info.
    /// If redirect_uri is None, uses the default from config.
    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: Option<&str>,
    ) -> AppResult<GoogleUserInfo> {
        let redirect = redirect_uri.unwrap_or(&self.default_redirect_uri);
        let client = self.create_client(redirect)?;

        // Exchange the code for an access token using reqwest
        let token_result = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "OAuth token exchange failed");
                AppError::InvalidCredentials
            })?;

        let access_token = token_result.access_token().secret();

        // Fetch user info using the access token
        let user_info = self
            .http_client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to fetch Google user info");
                AppError::Internal(anyhow::anyhow!("Failed to fetch user info"))
            })?
            .json::<GoogleUserInfo>()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to parse Google user info");
                AppError::Internal(anyhow::anyhow!("Failed to parse user info"))
            })?;

        Ok(user_info)
    }
}
