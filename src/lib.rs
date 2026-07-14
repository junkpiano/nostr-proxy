use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
};
use url::Url;

pub const MAX_REDIRECTS: usize = 3;
pub const MAX_RESPONSE_SIZE: usize = 1_048_576;

#[derive(Debug, Deserialize)]
pub struct OgpQuery {
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct OgpResponse {
    pub url: String,
    pub data: BTreeMap<String, String>,
}

#[derive(Debug)]
pub enum OgpError {
    InvalidUrl(String),
    SsrfBlocked { reason: String, ip: IpAddr },
    DnsResolution(String),
    TooManyRedirects,
    RedirectLoop,
    PayloadTooLarge { size: usize, limit: usize },
    UnsupportedContentType { content_type: String },
    Request(String),
    Parse,
}

pub fn validate_url(input: &str) -> Result<Url, OgpError> {
    let url = Url::parse(input).map_err(|_| OgpError::InvalidUrl(input.to_string()))?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        _ => Err(OgpError::InvalidUrl(input.to_string())),
    }
}

pub fn validate_worker_target_url(url: &Url) -> Result<(), OgpError> {
    let host = url
        .host_str()
        .ok_or_else(|| OgpError::InvalidUrl("no host".to_string()))?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        if let Some(reason) = is_private_or_reserved_ip(ip) {
            return Err(OgpError::SsrfBlocked {
                reason: reason.to_string(),
                ip,
            });
        }
    }

    let hostname = host.trim_end_matches('.').to_ascii_lowercase();
    if matches!(hostname.as_str(), "localhost" | "metadata.google.internal")
        || hostname.ends_with(".localhost")
        || hostname.ends_with(".local")
        || hostname.ends_with(".internal")
        || hostname.ends_with(".lan")
    {
        return Err(OgpError::InvalidUrl("blocked hostname".to_string()));
    }

    if let Some(port) = url.port() {
        if port != 80 && port != 443 {
            return Err(OgpError::InvalidUrl("blocked port".to_string()));
        }
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(OgpError::InvalidUrl("userinfo is not allowed".to_string()));
    }

    Ok(())
}

pub fn is_allowed_origin(origin: &str) -> bool {
    let Ok(url) = Url::parse(origin) else {
        return false;
    };
    match url.host_str() {
        Some("nox.garden") => url.scheme() == "https",
        Some("localhost") | Some("127.0.0.1") | Some("[::1]") => {
            url.scheme() == "http" || url.scheme() == "https"
        }
        _ => false,
    }
}

pub fn truncate_utf8_safe(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }

    let mut boundary = max_bytes;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }

    &s[..boundary]
}

pub fn parse_ogp(html: &str) -> Result<BTreeMap<String, String>, OgpError> {
    const MAX_META_TAGS: usize = 64;
    const MAX_CONTENT_LENGTH: usize = 2048;
    const MAX_KEY_LENGTH: usize = 128;

    let doc = Html::parse_document(html);
    let meta_selector = Selector::parse("meta").map_err(|_| OgpError::Parse)?;
    let title_selector = Selector::parse("title").map_err(|_| OgpError::Parse)?;

    let mut data = BTreeMap::new();

    for element in doc.select(&meta_selector) {
        if data.len() >= MAX_META_TAGS {
            break;
        }

        let value = element.value();
        let Some(content) = value.attr("content").map(str::trim) else {
            continue;
        };
        if content.is_empty() {
            continue;
        }

        let content = if content.len() > MAX_CONTENT_LENGTH {
            truncate_utf8_safe(content, MAX_CONTENT_LENGTH)
        } else {
            content
        };

        if let Some(prop) = value.attr("property") {
            let key = prop.trim();
            if key.len() > MAX_KEY_LENGTH {
                continue;
            }
            if key.starts_with("og:") || key.starts_with("twitter:") {
                data.entry(key.to_string())
                    .or_insert_with(|| content.to_string());
            }
        } else if let Some(name) = value.attr("name") {
            let key = name.trim();
            if key.len() > MAX_KEY_LENGTH {
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

pub fn is_private_or_reserved_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => is_private_or_reserved_ipv4(v4),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return Some("loopback");
            }
            if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                return Some("ULA");
            }
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return Some("link-local");
            }
            if v6.is_multicast() {
                return Some("multicast");
            }
            None
        }
    }
}

fn is_private_or_reserved_ipv4(v4: Ipv4Addr) -> Option<&'static str> {
    if v4.is_loopback() {
        return Some("loopback");
    }
    if v4.is_private() {
        return Some("private");
    }
    if v4.is_link_local() {
        return Some("link-local");
    }
    if v4.octets()[0] == 0 {
        return Some("0.0.0.0/8");
    }
    if v4.is_multicast() {
        return Some("multicast");
    }
    if v4.octets()[0] >= 240 {
        return Some("reserved");
    }
    if v4.is_broadcast() {
        return Some("broadcast");
    }
    None
}

#[cfg(feature = "native")]
pub mod native {
    use super::{
        is_private_or_reserved_ip, parse_ogp, validate_url, OgpError, MAX_REDIRECTS,
        MAX_RESPONSE_SIZE,
    };
    use futures::StreamExt;
    use hickory_resolver::TokioResolver;
    use reqwest::{
        header::{CONTENT_LENGTH, CONTENT_TYPE, LOCATION},
        Client,
    };
    use std::{collections::BTreeMap, collections::HashSet, net::IpAddr};
    use tracing::{info, warn};
    use url::Url;

    pub async fn fetch_ogp(
        client: &Client,
        resolver: &TokioResolver,
        target: &str,
    ) -> Result<BTreeMap<String, String>, OgpError> {
        let url = validate_url(target)?;
        let body = fetch_with_redirect_protection(client, resolver, url).await?;
        parse_ogp(&body)
    }

    async fn fetch_with_redirect_protection(
        client: &Client,
        resolver: &TokioResolver,
        initial_url: Url,
    ) -> Result<String, OgpError> {
        let mut current_url = initial_url;
        let mut visited_urls = HashSet::new();

        for redirect_count in 0..=MAX_REDIRECTS {
            if !visited_urls.insert(current_url.to_string()) {
                return Err(OgpError::RedirectLoop);
            }

            resolve_and_validate_url(resolver, &current_url).await?;

            let response = client
                .get(current_url.clone())
                .send()
                .await
                .map_err(|e| OgpError::Request(e.to_string()))?;

            let status = response.status();

            if status.is_redirection() {
                if redirect_count >= MAX_REDIRECTS {
                    return Err(OgpError::TooManyRedirects);
                }

                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        OgpError::InvalidUrl("missing Location header in redirect".to_string())
                    })?;

                current_url = current_url
                    .join(location)
                    .map_err(|_| OgpError::InvalidUrl(location.to_string()))?;

                info!("Following redirect to: {}", current_url);
                continue;
            }

            let response = response
                .error_for_status()
                .map_err(|e| OgpError::Request(e.to_string()))?;
            return read_response_with_limit(response, MAX_RESPONSE_SIZE).await;
        }

        Err(OgpError::TooManyRedirects)
    }

    async fn resolve_and_validate_url(
        resolver: &TokioResolver,
        url: &Url,
    ) -> Result<(), OgpError> {
        let host = url
            .host_str()
            .ok_or_else(|| OgpError::InvalidUrl("no host".to_string()))?;

        if let Ok(ip) = host.parse::<IpAddr>() {
            if let Some(reason) = is_private_or_reserved_ip(ip) {
                return Err(OgpError::SsrfBlocked {
                    reason: reason.to_string(),
                    ip,
                });
            }
            return Ok(());
        }

        let lookup = resolver
            .lookup_ip(host)
            .await
            .map_err(|e| OgpError::DnsResolution(format!("DNS lookup failed: {}", e)))?;

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

    async fn read_response_with_limit(
        response: reqwest::Response,
        max_size: usize,
    ) -> Result<String, OgpError> {
        if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
            if let Ok(content_type_str) = content_type.to_str() {
                let mime_type = content_type_str
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_lowercase();

                if mime_type != "text/html" && mime_type != "application/xhtml+xml" {
                    return Err(OgpError::UnsupportedContentType {
                        content_type: content_type_str.to_string(),
                    });
                }
            }
        }

        if let Some(content_length) = response.headers().get(CONTENT_LENGTH) {
            if let Ok(length_str) = content_length.to_str() {
                if let Ok(length) = length_str.parse::<usize>() {
                    if length > max_size {
                        return Err(OgpError::PayloadTooLarge {
                            size: length,
                            limit: max_size,
                        });
                    }
                }
            }
        }

        let mut stream = response.bytes_stream();
        let mut accumulated = Vec::new();
        let mut total_size = 0;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| OgpError::Request(e.to_string()))?;
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

        String::from_utf8(accumulated).map_err(|_| OgpError::Parse)
    }
}
