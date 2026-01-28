use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use futures::StreamExt;
use hickory_resolver::TokioAsyncResolver;
use reqwest::{
    header::{CONTENT_LENGTH, CONTENT_TYPE, LOCATION},
    Client,
};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tower::ServiceBuilder;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};
use url::Url;

#[derive(Debug, Deserialize)]
struct OgpQuery {
    url: String,
}

#[derive(Debug, Serialize)]
struct OgpResponse {
    url: String,
    data: BTreeMap<String, String>,
}

#[derive(Clone)]
struct AppState {
    client: Client,
    resolver: Arc<TokioAsyncResolver>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let user_agent = std::env::var("USER_AGENT").unwrap_or_else(|_| {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".to_string()
    });

    // Create HTTP client with redirect disabled (we handle redirects manually for SSRF protection)
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client");

    // Create DNS resolver for SSRF protection
    // Using tokio_from_system_conf() to properly initialize from system DNS settings
    let resolver =
        TokioAsyncResolver::tokio_from_system_conf().expect("failed to create DNS resolver");

    let state = AppState {
        client,
        resolver: Arc::new(resolver),
    };

    // Rate limiting: 30 requests per minute per IP, with burst of 10
    // 30 req/min = 1 req per 2 seconds, with burst of 10
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(10)
            .finish()
            .unwrap(),
    );

    let governor_layer = GovernorLayer {
        config: governor_conf,
    };

    // CORS configuration: Allow all GET requests from any origin
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([axum::http::Method::GET])
        .allow_headers(Any)
        .expose_headers(Any)
        .max_age(Duration::from_secs(3600));

    let app = Router::new()
        .route("/api/ogp", get(ogp_handler))
        .layer(ServiceBuilder::new().layer(governor_layer).layer(cors))
        .with_state(state);

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let addr: SocketAddr = bind_addr.parse().expect("BIND_ADDR must be host:port");

    info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("server");
}

async fn ogp_handler(
    Query(params): Query<OgpQuery>,
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl IntoResponse {
    match fetch_ogp(&state.client, &state.resolver, &params.url).await {
        Ok(data) => {
            let resp = OgpResponse {
                url: params.url,
                data,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => {
            let (status, msg) = match &err {
                OgpError::InvalidUrl(_) => {
                    error!("invalid url: {:?}", err);
                    (StatusCode::BAD_REQUEST, "invalid url")
                }
                OgpError::SsrfBlocked { reason, ip } => {
                    warn!(
                        ssrf_blocked = true,
                        resolved_ip = %ip,
                        reason = %reason,
                        "SSRF attempt blocked"
                    );
                    (StatusCode::BAD_REQUEST, "blocked: private IP")
                }
                OgpError::DnsResolution(_) => {
                    error!("dns resolution error: {:?}", err);
                    (StatusCode::BAD_REQUEST, "dns resolution failed")
                }
                OgpError::TooManyRedirects => {
                    warn!("too many redirects");
                    (StatusCode::BAD_REQUEST, "too many redirects")
                }
                OgpError::RedirectLoop => {
                    warn!("redirect loop detected");
                    (StatusCode::BAD_REQUEST, "redirect loop detected")
                }
                OgpError::PayloadTooLarge { size, limit } => {
                    warn!(
                        payload_too_large = true,
                        size = size,
                        limit = limit,
                        "Response size exceeds limit"
                    );
                    (StatusCode::PAYLOAD_TOO_LARGE, "payload too large")
                }
                OgpError::UnsupportedContentType { content_type } => {
                    warn!(
                        unsupported_content_type = true,
                        content_type = %content_type,
                        "Content-Type not supported"
                    );
                    (
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "unsupported content type",
                    )
                }
                OgpError::Request(_) => {
                    error!("request error: {:?}", err);
                    (StatusCode::BAD_GATEWAY, "fetch failed")
                }
                OgpError::Parse => {
                    error!("parse error");
                    (StatusCode::BAD_GATEWAY, "parse failed")
                }
            };
            (status, msg).into_response()
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)] // Fields are used via Debug trait for logging
enum OgpError {
    InvalidUrl(String),
    SsrfBlocked { reason: String, ip: IpAddr },
    DnsResolution(String),
    TooManyRedirects,
    RedirectLoop,
    PayloadTooLarge { size: usize, limit: usize },
    UnsupportedContentType { content_type: String },
    Request(reqwest::Error),
    Parse,
}

async fn fetch_ogp(
    client: &Client,
    resolver: &TokioAsyncResolver,
    target: &str,
) -> Result<BTreeMap<String, String>, OgpError> {
    let url = validate_url(target)?;
    let body = fetch_with_redirect_protection(client, resolver, url).await?;
    parse_ogp(&body)
}

/// Fetch URL with manual redirect following and SSRF protection
async fn fetch_with_redirect_protection(
    client: &Client,
    resolver: &TokioAsyncResolver,
    initial_url: Url,
) -> Result<String, OgpError> {
    const MAX_REDIRECTS: usize = 3;
    const MAX_RESPONSE_SIZE: usize = 1_048_576; // 1MB

    let mut current_url = initial_url;
    let mut visited_urls = HashSet::new();

    for redirect_count in 0..=MAX_REDIRECTS {
        // Check for redirect loop
        if !visited_urls.insert(current_url.to_string()) {
            return Err(OgpError::RedirectLoop);
        }

        // Validate URL before making request (SSRF protection)
        resolve_and_validate_url(resolver, &current_url).await?;

        // Make request with redirect disabled
        let response = client
            .get(current_url.clone())
            .send()
            .await
            .map_err(OgpError::Request)?;

        let status = response.status();

        // Check if it's a redirect
        if status.is_redirection() {
            if redirect_count >= MAX_REDIRECTS {
                return Err(OgpError::TooManyRedirects);
            }

            // Get redirect location
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    OgpError::InvalidUrl("missing Location header in redirect".to_string())
                })?;

            // Parse redirect URL (may be relative)
            current_url = current_url
                .join(location)
                .map_err(|_| OgpError::InvalidUrl(location.to_string()))?;

            info!("Following redirect to: {}", current_url);
            continue;
        }

        // Not a redirect, check status and return body with size limit
        let response = response.error_for_status().map_err(OgpError::Request)?;
        return read_response_with_limit(response, MAX_RESPONSE_SIZE).await;
    }

    // Should not reach here
    Err(OgpError::TooManyRedirects)
}

fn validate_url(input: &str) -> Result<Url, OgpError> {
    let url = Url::parse(input).map_err(|_| OgpError::InvalidUrl(input.to_string()))?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        _ => Err(OgpError::InvalidUrl(input.to_string())),
    }
}

/// Safely truncate a string to a maximum byte length at a valid UTF-8 character boundary
fn truncate_utf8_safe(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }

    // Find the last character boundary at or before max_bytes
    let mut boundary = max_bytes;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }

    &s[..boundary]
}

fn parse_ogp(html: &str) -> Result<BTreeMap<String, String>, OgpError> {
    const MAX_META_TAGS: usize = 64;
    const MAX_CONTENT_LENGTH: usize = 2048;
    const MAX_KEY_LENGTH: usize = 128;

    let doc = Html::parse_document(html);
    let meta_selector = Selector::parse("meta").map_err(|_| OgpError::Parse)?;
    let title_selector = Selector::parse("title").map_err(|_| OgpError::Parse)?;

    let mut data = BTreeMap::new();

    for element in doc.select(&meta_selector) {
        // Stop if we've collected enough meta tags (DoS protection)
        if data.len() >= MAX_META_TAGS {
            warn!(
                meta_tags_limit_reached = true,
                limit = MAX_META_TAGS,
                "Meta tags limit reached, stopping parsing"
            );
            break;
        }

        let value = element.value();
        let content = value.attr("content");
        if content.is_none() {
            continue;
        }
        let content = content.unwrap().trim();
        if content.is_empty() {
            continue;
        }

        // Limit content length (DoS protection)
        let content = if content.len() > MAX_CONTENT_LENGTH {
            warn!(
                content_truncated = true,
                original_length = content.len(),
                limit = MAX_CONTENT_LENGTH,
                "Content value truncated"
            );
            // Safe UTF-8 truncation: find last valid char boundary at or before limit
            truncate_utf8_safe(content, MAX_CONTENT_LENGTH)
        } else {
            content
        };

        if let Some(prop) = value.attr("property") {
            let key = prop.trim();
            // Skip if key is too long (DoS protection)
            if key.len() > MAX_KEY_LENGTH {
                warn!(
                    key_too_long = true,
                    key_length = key.len(),
                    limit = MAX_KEY_LENGTH,
                    "Skipping meta tag with too long key"
                );
                continue;
            }
            if key.starts_with("og:") || key.starts_with("twitter:") {
                data.entry(key.to_string())
                    .or_insert_with(|| content.to_string());
            }
        } else if let Some(name) = value.attr("name") {
            let key = name.trim();
            // Skip if key is too long (DoS protection)
            if key.len() > MAX_KEY_LENGTH {
                warn!(
                    key_too_long = true,
                    key_length = key.len(),
                    limit = MAX_KEY_LENGTH,
                    "Skipping meta tag with too long key"
                );
                continue;
            }
            if key == "description" || key == "title" {
                data.entry(key.to_string())
                    .or_insert_with(|| content.to_string());
            }
        }
    }

    if !data.contains_key("title") {
        if let Some(title_node) = doc.select(&title_selector).next() {
            let title = title_node.text().collect::<String>().trim().to_string();
            if !title.is_empty() {
                data.insert("title".to_string(), title);
            }
        }
    }

    Ok(data)
}

/// Check if an IP address is private or reserved (SSRF protection)
fn is_private_or_reserved_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            // Loopback: 127.0.0.0/8
            if v4.is_loopback() {
                return Some("loopback");
            }
            // Private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if v4.is_private() {
                return Some("private");
            }
            // Link-local: 169.254.0.0/16 (including 169.254.169.254 metadata endpoint)
            if v4.is_link_local() {
                return Some("link-local");
            }
            // 0.0.0.0/8
            if v4.octets()[0] == 0 {
                return Some("0.0.0.0/8");
            }
            // Multicast: 224.0.0.0/4
            if v4.is_multicast() {
                return Some("multicast");
            }
            // Reserved: 240.0.0.0/4
            if v4.octets()[0] >= 240 {
                return Some("reserved");
            }
            // Broadcast
            if v4.is_broadcast() {
                return Some("broadcast");
            }
            None
        }
        IpAddr::V6(v6) => {
            // Loopback: ::1
            if v6.is_loopback() {
                return Some("loopback");
            }
            // ULA (Unique Local Address): fc00::/7
            if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                return Some("ULA");
            }
            // Link-local: fe80::/10
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return Some("link-local");
            }
            // Multicast
            if v6.is_multicast() {
                return Some("multicast");
            }
            None
        }
    }
}

/// Resolve hostname and validate all resolved IPs are not private/reserved
async fn resolve_and_validate_url(
    resolver: &TokioAsyncResolver,
    url: &Url,
) -> Result<(), OgpError> {
    let host = url
        .host_str()
        .ok_or_else(|| OgpError::InvalidUrl("no host".to_string()))?;

    // If it's already an IP address, validate it directly
    if let Ok(ip) = host.parse::<IpAddr>() {
        if let Some(reason) = is_private_or_reserved_ip(ip) {
            return Err(OgpError::SsrfBlocked {
                reason: reason.to_string(),
                ip,
            });
        }
        return Ok(());
    }

    // Resolve hostname to IP addresses
    let lookup = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| OgpError::DnsResolution(format!("DNS lookup failed: {}", e)))?;

    // Validate all resolved IPs
    for ip in lookup.iter() {
        if let Some(reason) = is_private_or_reserved_ip(ip) {
            return Err(OgpError::SsrfBlocked {
                reason: reason.to_string(),
                ip,
            });
        }
    }

    Ok(())
}

/// Read response body with size limit (protection against memory exhaustion)
async fn read_response_with_limit(
    response: reqwest::Response,
    max_size: usize,
) -> Result<String, OgpError> {
    // Validate Content-Type (only accept HTML)
    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        if let Ok(content_type_str) = content_type.to_str() {
            // Extract MIME type (before semicolon for charset)
            let mime_type = content_type_str
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase();

            // Only accept text/html and application/xhtml+xml
            if mime_type != "text/html" && mime_type != "application/xhtml+xml" {
                warn!(
                    unsupported_content_type = true,
                    content_type = %content_type_str,
                    "Rejecting non-HTML content type"
                );
                return Err(OgpError::UnsupportedContentType {
                    content_type: content_type_str.to_string(),
                });
            }
        }
    }

    // Check Content-Length header first
    if let Some(content_length) = response.headers().get(CONTENT_LENGTH) {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<usize>() {
                info!(
                    "Content-Length: {} bytes (limit: {} bytes)",
                    length, max_size
                );
                if length > max_size {
                    warn!(
                        "Content-Length {} exceeds limit {}, rejecting before download",
                        length, max_size
                    );
                    return Err(OgpError::PayloadTooLarge {
                        size: length,
                        limit: max_size,
                    });
                }
            }
        }
    }

    // Read body in chunks with size limit
    let mut stream = response.bytes_stream();
    let mut accumulated = Vec::new();
    let mut total_size = 0;

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(OgpError::Request)?;
        total_size += chunk.len();

        if total_size > max_size {
            warn!(
                "Response size {} exceeds limit {} during streaming, aborting",
                total_size, max_size
            );
            return Err(OgpError::PayloadTooLarge {
                size: total_size,
                limit: max_size,
            });
        }

        accumulated.extend_from_slice(&chunk);
    }

    info!("Successfully read {} bytes", total_size);
    // Convert bytes to String
    String::from_utf8(accumulated).map_err(|_| OgpError::Parse)
}
