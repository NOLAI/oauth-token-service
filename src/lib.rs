use log::{error};
use std::error::Error;
use std::fmt::{Debug};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::{reqwest, AccessToken, AuthUrl, ClientId, ClientSecret, HttpClientError, RequestTokenError, Scope, TokenResponse, TokenUrl};
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum OauthError {
    #[error(transparent)]
    TokenError(#[from] Box<dyn Error>),
    #[error(transparent)]
    NetworkError(#[from] HttpClientError<reqwest::Error>),
}

/// Information about a token, including the token itself and when it expires
#[derive(Clone, Debug)]
pub struct TokenInfo {
    pub access_token: AccessToken,
    pub expires_at: SystemTime,
}

/// A connector to the identity service that auto-renews its token when expired
#[derive(Debug, Clone)]
pub struct OauthTokenConnector {
    token_info: Arc<Mutex<TokenInfo>>,
}

pub struct AuthentikConfig {
    pub base_identity_url: String,
    pub identity_username: String,
    pub identity_token: String,
    pub client_id: String,
}

impl OauthTokenConnector {
    fn get_config() -> AuthentikConfig {
        AuthentikConfig {
            base_identity_url: std::env::var("IDENTITY_URL").expect("IDENTITY_URL not set"),
            identity_username: std::env::var("IDENTITY_USERNAME").expect("IDENTITY_USERNAME not set"),
            identity_token: std::env::var("IDENTITY_TOKEN").expect("IDENTITY_TOKEN not set"),
            client_id: std::env::var("IDENTITY_CLIENT_ID").expect("IDENTITY_CLIENT_ID not set"),
        }
    }
    pub async fn new() -> Result<Self, OauthError> {
        let token_info = Self::initialize_service().await?;
        Ok(Self {
            token_info: Arc::new(Mutex::new(token_info))
        })
    }

    async fn initialize_service() -> Result<TokenInfo, OauthError> {
        let token = Self::perform_login().await?;

        let expires_at = SystemTime::now() +
            Duration::from_secs(token.expires_in()
                .ok_or_else(|| OauthError::TokenError("Token has no duration".to_string().into()))?
                .as_secs());

        Ok(TokenInfo {
            access_token: token.access_token().clone(),
            expires_at,
        })
    }

    async fn perform_login() -> Result<BasicTokenResponse, OauthError> {
        let config = Self::get_config();
        let client_secret = URL_SAFE.encode(format!("{}:{}", config.identity_username, config.identity_token));

        let client = BasicClient::new(ClientId::new(config.client_id.clone()))
            .set_client_secret(ClientSecret::new(client_secret))
            .set_auth_uri(AuthUrl::new(format!("{}/authorize/", config.base_identity_url)).expect("Auth URL should be valid"))
            .set_token_uri(TokenUrl::new(format!("{}/token/", config.base_identity_url)).expect("Token URL should be valid"));

        let http_client = reqwest::blocking::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");

        let result = client
            .exchange_client_credentials()
            .add_scope(Scope::new("profile".to_string()))
            .request(&http_client);

        result.map_err(|e| match e {
            RequestTokenError::Request(e) => OauthError::NetworkError(e),
            RequestTokenError::ServerResponse(e) => OauthError::TokenError(e.to_string().into()),
            _ => {
                error!("Unexpected error: {:?}", e);
                OauthError::TokenError("Unexpected error".to_string().into())
            }
        })

    }

    async fn renew_token(&self) -> Result<(), OauthError> {
        let new_token_info = Self::initialize_service().await?;
        *self.token_info.lock().await = new_token_info;
        Ok(())
    }

    async fn get_token(&self) -> Result<String, OauthError> {
        let token_info = self.token_info.lock().await;

        if token_info.expires_at < SystemTime::now() {
            drop(token_info);
            self.renew_token().await?;
        }

        Ok(self.token_info.lock().await.access_token.secret().clone())
    }
}
