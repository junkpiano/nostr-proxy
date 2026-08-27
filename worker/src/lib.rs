use nostr_proxy::{
    is_allowed_origin, parse_ogp, validate_url, validate_worker_target_url, OgpError, OgpResponse,
    DEFAULT_USER_AGENT, MAX_REDIRECTS, MAX_RESPONSE_SIZE,
};
use std::collections::{BTreeMap, HashSet};
use worker::{
    event, Cache, Fetch, Headers, Method, Request, RequestInit, RequestRedirect, Response, Result,
};

/// Successful lookups are cached for six hours; OGP metadata rarely changes.
const CACHE_CONTROL_SUCCESS: &str = "public, max-age=21600";

/// Failures are cached for five minutes only, so a recovering target is picked
/// up quickly.
const CACHE_CONTROL_FAILURE: &str = "public, max-age=300";

#[event(fetch)]
pub async fn fetch(req: Request, _env: worker::Env, _ctx: worker::Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    if req.method() == Method::Options {
        return with_cors(&req, Response::empty()?);
    }

    if req.method() != Method::Get {
        return with_cors(&req, Response::error("method not allowed", 405)?);
    }

    let request_url = req.url()?;
    if request_url.path() != "/api/ogp" {
        return with_cors(&req, Response::error("not found", 404)?);
    }

    let Some(target) = request_url
        .query_pairs()
        .find(|(key, _)| key == "url")
        .map(|(_, value)| value.to_string())
    else {
        return with_cors(&req, Response::error("invalid url", 400)?);
    };

    // The incoming URL already encodes the target, sits on this Worker's own
    // hostname, and is stable across callers, so it doubles as the cache key.
    let cache = Cache::default();
    let cache_key = request_url.to_string();

    // A cache fault must not become a Worker exception: Cloudflare would then
    // answer with an error page that carries no CORS headers at all. Degrade to
    // a miss instead.
    if let Some(hit) = cache.get(cache_key.as_str(), false).await.ok().flatten() {
        if let Ok(replayed) = replay_cached(hit).await {
            return with_cors(&req, replayed);
        }
    }

    let mut response = match fetch_ogp_worker(&target).await {
        Ok(data) => {
            let payload = OgpResponse { url: target, data };
            let mut ok = Response::from_json(&payload)?;
            ok.headers_mut()
                .set("Cache-Control", CACHE_CONTROL_SUCCESS)?;
            ok
        }
        Err(err) => {
            // Negative results are cached briefly too, so a target that answers
            // 403 or oversized HTML is not re-fetched on every card render.
            let mut failed = error_response(err)?;
            failed
                .headers_mut()
                .set("Cache-Control", CACHE_CONTROL_FAILURE)?;
            failed
        }
    };

    // Stored before the CORS headers go on: this cache ignores Vary, so an entry
    // carrying one caller's Allow-Origin would be replayed to every other caller.
    if let Ok(copy) = response.cloned() {
        let _ = cache.put(cache_key.as_str(), copy).await;
    }

    with_cors(&req, response)
}

async fn fetch_ogp_worker(target: &str) -> std::result::Result<BTreeMap<String, String>, OgpError> {
    let url = validate_url(target)?;
    let body = fetch_with_redirect_protection(url).await?;
    parse_ogp(&body)
}

async fn fetch_with_redirect_protection(
    initial_url: url::Url,
) -> std::result::Result<String, OgpError> {
    let mut current_url = initial_url;
    let mut visited_urls = HashSet::new();

    for redirect_count in 0..=MAX_REDIRECTS {
        if !visited_urls.insert(current_url.to_string()) {
            return Err(OgpError::RedirectLoop);
        }

        validate_worker_target_url(&current_url)?;

        // Without a User-Agent many origins answer 403, which surfaced here as a
        // generic 502. Match the header set the native target already sends.
        let headers = Headers::new();
        headers
            .set("User-Agent", DEFAULT_USER_AGENT)
            .map_err(|e| OgpError::Request(e.to_string()))?;
        headers
            .set("Accept", "text/html,application/xhtml+xml")
            .map_err(|e| OgpError::Request(e.to_string()))?;

        let mut init = RequestInit::new();
        init.with_method(Method::Get)
            .with_headers(headers)
            .with_redirect(RequestRedirect::Manual);
        let request = Request::new_with_init(current_url.as_str(), &init)
            .map_err(|e| OgpError::Request(e.to_string()))?;
        let mut response = Fetch::Request(request)
            .send()
            .await
            .map_err(|e| OgpError::Request(e.to_string()))?;

        let status = response.status_code();
        if (300..400).contains(&status) {
            if redirect_count >= MAX_REDIRECTS {
                return Err(OgpError::TooManyRedirects);
            }

            let location = response
                .headers()
                .get("location")
                .map_err(|e| OgpError::Request(e.to_string()))?
                .ok_or_else(|| {
                    OgpError::InvalidUrl("missing Location header in redirect".to_string())
                })?;

            current_url = current_url
                .join(&location)
                .map_err(|_| OgpError::InvalidUrl(location))?;
            continue;
        }

        if !(200..300).contains(&status) {
            return Err(OgpError::Request(format!("upstream status {}", status)));
        }

        return read_response_with_limit(&mut response, MAX_RESPONSE_SIZE).await;
    }

    Err(OgpError::TooManyRedirects)
}

async fn read_response_with_limit(
    response: &mut Response,
    max_size: usize,
) -> std::result::Result<String, OgpError> {
    if let Some(content_type) = response
        .headers()
        .get("content-type")
        .map_err(|e| OgpError::Request(e.to_string()))?
    {
        let mime_type = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_lowercase();

        if mime_type != "text/html" && mime_type != "application/xhtml+xml" {
            return Err(OgpError::UnsupportedContentType { content_type });
        }
    }

    if let Some(content_length) = response
        .headers()
        .get("content-length")
        .map_err(|e| OgpError::Request(e.to_string()))?
    {
        if let Ok(length) = content_length.parse::<usize>() {
            if length > max_size {
                return Err(OgpError::PayloadTooLarge {
                    size: length,
                    limit: max_size,
                });
            }
        }
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| OgpError::Request(e.to_string()))?;
    if bytes.len() > max_size {
        return Err(OgpError::PayloadTooLarge {
            size: bytes.len(),
            limit: max_size,
        });
    }

    String::from_utf8(bytes).map_err(|_| OgpError::Parse)
}

fn error_response(err: OgpError) -> Result<Response> {
    match err {
        OgpError::InvalidUrl(_) => Response::error("invalid url", 400),
        OgpError::SsrfBlocked { .. } => Response::error("blocked: private IP", 400),
        OgpError::DnsResolution(_) => Response::error("dns resolution failed", 400),
        OgpError::TooManyRedirects => Response::error("too many redirects", 400),
        OgpError::RedirectLoop => Response::error("redirect loop detected", 400),
        OgpError::PayloadTooLarge { .. } => Response::error("payload too large", 413),
        OgpError::UnsupportedContentType { .. } => Response::error("unsupported content type", 415),
        OgpError::Request(_) => Response::error("fetch failed", 502),
        OgpError::Parse => Response::error("parse failed", 502),
    }
}

/// Rebuilds a cache hit into a fresh response.
///
/// Responses handed back by the Cache API carry immutable headers, so the CORS
/// headers cannot be attached to one directly — attempting it throws and the
/// request dies as a Worker exception with no CORS headers at all.
async fn replay_cached(mut hit: Response) -> Result<Response> {
    let status = hit.status_code();
    let content_type = hit.headers().get("content-type")?;
    let cache_control = hit.headers().get("cache-control")?;
    let body = hit.bytes().await?;

    let mut fresh = Response::from_bytes(body)?.with_status(status);
    let headers = fresh.headers_mut();
    if let Some(value) = content_type {
        headers.set("Content-Type", &value)?;
    }
    if let Some(value) = cache_control {
        headers.set("Cache-Control", &value)?;
    }
    Ok(fresh)
}

fn with_cors(req: &Request, mut response: Response) -> Result<Response> {
    let headers = response.headers_mut();
    headers.set("Vary", "Origin")?;
    if let Some(origin) = req.headers().get("Origin")? {
        if is_allowed_origin(&origin) {
            headers.set("Access-Control-Allow-Origin", &origin)?;
            headers.set("Access-Control-Allow-Methods", "GET, OPTIONS")?;
            headers.set("Access-Control-Allow-Headers", "*")?;
        }
    }
    Ok(response)
}
