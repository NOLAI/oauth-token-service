use oauth_token_service::{TokenService, TokenServiceConfig};

#[tokio::test]
async fn test_example() {
    let mut mock_server = mockito::Server::new_async().await;

    let _m_auth = mock_server
        .mock("POST", "/authorize/")
        .with_status(200)
        .with_header("content-type", "application/json")
        .expect(1)
        .create();

    // First token request mock
    let _m1 = mock_server
        .mock("POST", "/token/")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "access_token": "mock_access_token",
            "token_type": "Bearer",
            "expires_in": 3600
        }"#,
        )
        .expect(1)
        .create();

    let config = TokenServiceConfig {
        identity_service_base_url: mock_server.url(),
        username: "your_username".to_string(),
        token: "your_token".to_string(),
        client_id: "your_client_id".to_string(),
    };

    let token_service = TokenService::new(config);
    let token = token_service
        .get_token()
        .await
        .expect("Failed to get token");
    assert_eq!(token.secret().as_str(), "mock_access_token");
}

#[tokio::test]
async fn test_token_renewal() {
    let mut mock_server = mockito::Server::new_async().await;

    // Mock authorize endpoint - will be called twice
    let _m_auth = mock_server
        .mock("POST", "/authorize/")
        .with_status(200)
        .with_header("content-type", "application/json")
        .expect(2)
        .create();

    // First token request mock
    let _m1 = mock_server
        .mock("POST", "/token/")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "access_token": "first_token",
            "token_type": "Bearer",
            "expires_in": 0
        }"#,
        )
        .expect(1)
        .create();

    // Second token request mock (for renewal)
    let _m2 = mock_server
        .mock("POST", "/token/")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
            "access_token": "renewed_token",
            "token_type": "Bearer",
            "expires_in": 3600
        }"#,
        )
        .expect(1)
        .create();

    let config = TokenServiceConfig {
        identity_service_base_url: mock_server.url(),
        username: "your_username".to_string(),
        token: "your_token".to_string(),
        client_id: "your_client_id".to_string(),
    };

    let token_service = TokenService::new(config);

    let token1 = token_service
        .get_token()
        .await
        .expect("Failed to get first token");
    assert_eq!(token1.secret().as_str(), "first_token");

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let token2 = token_service
        .get_token()
        .await
        .expect("Failed to get renewed token");
    assert_eq!(token2.secret().as_str(), "renewed_token");
}
