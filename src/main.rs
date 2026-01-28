use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use reqwest::{header::LOCATION, Client};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
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
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .expect("failed to create DNS resolver");

    let state = AppState {
        client,
        resolver: Arc::new(resolver),
    };

    let app = Router::new()
        .route("/api/ogp", get(ogp_handler))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any))
        .with_state(state);

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let addr: SocketAddr = bind_addr.parse().expect("BIND_ADDR must be host:port");

    info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("server");
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
enum OgpError {
    InvalidUrl(String),
    SsrfBlocked { reason: String, ip: IpAddr },
    DnsResolution(String),
    TooManyRedirects,
    RedirectLoop,
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
                .ok_or_else(|| OgpError::InvalidUrl("missing Location header in redirect".to_string()))?;

            // Parse redirect URL (may be relative)
            current_url = current_url
                .join(location)
                .map_err(|_| OgpError::InvalidUrl(location.to_string()))?;

            info!("Following redirect to: {}", current_url);
            continue;
        }

        // Not a redirect, check status and return body
        let response = response.error_for_status().map_err(OgpError::Request)?;
        return response.text().await.map_err(OgpError::Request);
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

fn parse_ogp(html: &str) -> Result<BTreeMap<String, String>, OgpError> {
    let doc = Html::parse_document(html);
    let meta_selector = Selector::parse("meta").map_err(|_| OgpError::Parse)?;
    let title_selector = Selector::parse("title").map_err(|_| OgpError::Parse)?;

    let mut data = BTreeMap::new();

    for element in doc.select(&meta_selector) {
        let value = element.value();
        let content = value.attr("content");
        if content.is_none() {
            continue;
        }
        let content = content.unwrap().trim();
        if content.is_empty() {
            continue;
        }

        if let Some(prop) = value.attr("property") {
            let key = prop.trim();
            if key.starts_with("og:") || key.starts_with("twitter:") {
                data.entry(key.to_string()).or_insert_with(|| content.to_string());
            }
        } else if let Some(name) = value.attr("name") {
            let key = name.trim();
            if key == "description" || key == "title" {
                data.entry(key.to_string()).or_insert_with(|| content.to_string());
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
