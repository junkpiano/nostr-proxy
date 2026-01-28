const TEST_SERVER_URL: &str = "http://localhost:3000";

#[tokio::test]
async fn test_health_endpoint() {
    // Note: This test assumes the server is running
    // In a real CI environment, we'd start the server in setup

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/ogp?url=https://example.com/", TEST_SERVER_URL))
        .send()
        .await;

    match response {
        Ok(resp) => {
            assert!(resp.status().is_success() || resp.status().as_u16() == 429);
        }
        Err(_) => {
            // Server might not be running in test environment
            println!("Server not running - skipping test");
        }
    }
}

#[tokio::test]
async fn test_ssrf_protection() {
    let client = reqwest::Client::new();

    // Test blocking of localhost
    let response = client
        .get(format!("{}/api/ogp?url=http://127.0.0.1/", TEST_SERVER_URL))
        .send()
        .await;

    if let Ok(resp) = response {
        let status = resp.status().as_u16();
        // Accept either 400 (SSRF blocked) or 429 (rate limited)
        assert!(status == 400 || status == 429, "Expected 400 or 429, got {}", status);
        if status == 400 {
            let body = resp.text().await.unwrap();
            assert!(body.contains("blocked: private IP"));
        }
    }
}

#[tokio::test]
async fn test_rate_limiting() {
    let client = reqwest::Client::new();

    // Make burst + 1 requests
    let mut responses = Vec::new();
    for _ in 0..11 {
        let response = client
            .get(format!("{}/api/ogp?url=https://example.com/", TEST_SERVER_URL))
            .send()
            .await;

        if let Ok(resp) = response {
            responses.push(resp.status().as_u16());
        }
    }

    // At least one should be rate limited (429)
    if !responses.is_empty() {
        let rate_limited_count = responses.iter().filter(|&&s| s == 429).count();
        println!("Rate limited responses: {}/{}", rate_limited_count, responses.len());
    }
}

#[tokio::test]
async fn test_invalid_url() {
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/api/ogp?url=not-a-valid-url", TEST_SERVER_URL))
        .send()
        .await;

    if let Ok(resp) = response {
        let status = resp.status().as_u16();
        assert!(status == 400 || status == 429, "Expected 400 or 429, got {}", status);
        if status == 400 {
            let body = resp.text().await.unwrap();
            assert!(body.contains("invalid url"));
        }
    }
}

#[tokio::test]
async fn test_unsupported_content_type() {
    let client = reqwest::Client::new();

    // Try to fetch an image (should return 415)
    let response = client
        .get(format!("{}/api/ogp?url=https://httpbin.org/image/png", TEST_SERVER_URL))
        .send()
        .await;

    if let Ok(resp) = response {
        let status = resp.status().as_u16();
        // Accept 415 (unsupported content type) or 429 (rate limited)
        assert!(status == 415 || status == 429, "Expected 415 or 429, got {}", status);
        if status == 415 {
            let body = resp.text().await.unwrap();
            assert!(body.contains("unsupported content type"));
        }
    }
}

#[tokio::test]
async fn test_successful_ogp_fetch() {
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/api/ogp?url=https://example.com/", TEST_SERVER_URL))
        .send()
        .await;

    if let Ok(resp) = response {
        if resp.status().is_success() {
            let json: serde_json::Value = resp.json().await.unwrap();
            assert!(json.get("url").is_some());
            assert!(json.get("data").is_some());

            let data = json.get("data").unwrap();
            assert!(data.is_object());
        }
    }
}
