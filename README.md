# OAuth token service

A lightweight Rust library for managing OAuth access tokens with automatic renewal support.
Implements the client credentials flow using base64-encoded credentials.
Built specifically for [Authentik](https://goauthentik.io) but designed to work with any OAuth2-compatible identity provider.

### Features

- Automatic token renewal when expired
- Thread-safe token management using `Arc<Mutex<>>`
- Client credentials OAuth2 flow
- Configurable identity provider URL
- Built on top of the [`oauth2`](https://crates.io/crates/oauth2) crate
- Safe redirect policy to prevent SSRF
- Async/await support

### Installation
Add this to your Cargo.toml:

```toml
[dependencies]
oauth_token_service = "0.1.0"
```

### Quick start
```rust
use oauth_token_service::{TokenService, TokenServiceConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the token service
    let config = TokenServiceConfig {
        identity_service_base_url: "https://identity.example.com".to_string(),
        username: "your_username".to_string(),
        token: "your_token".to_string(),
        client_id: "your_client_id".to_string(),
    };

    // Create a new token service instance
    let token_service = TokenService::new(config);

    // Get a valid token - will automatically fetch or renew as needed
    let token = token_service.get_token().await.expect("failed to get token");
    println!("Access token: {}", token.secret().as_str());
}
```

### Configuration
The `TokenServiceConfig` requires the following fields:

- `identity_service_base_url`: Base URL of your identity provider (e.g., "https://identity.example.com")
- `username`: Username for client credentials
- `token`: Token/password for client credentials
- `client_id`: Your OAuth client ID

The service will automatically construct the necessary OAuth endpoints by appending `/authorize/` and `/token/` to the base URL.

### Error Handling
The service provides a `TokenServiceError` `enum` with two variants:

- `TokenError`: When no valid token was returned from the identity provider
- `NetworkError`: Specifically handles HTTP client errors