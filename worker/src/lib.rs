use nostr_proxy::{
    parse_ogp, validate_url, validate_worker_target_url, OgpError, OgpResponse, MAX_REDIRECTS,
    MAX_RESPONSE_SIZE,
};
use std::collections::{BTreeMap, HashSet};
use worker::{
    event, Fetch, Headers, Method, Request, RequestInit, RequestRedirect, Response, Result,
};

#[event(fetch)]
pub async fn fetch(req: Request, _env: worker::Env, _ctx: worker::Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    if req.method() == Method::Options {
        return with_cors(Response::empty()?);
    }

    if req.method() != Method::Get {
        return with_cors(Response::error("method not allowed", 405)?);
    }

    let request_url = req.url()?;
    if request_url.path() != "/api/ogp" {
        return with_cors(Response::error("not found", 404)?);
    }

    let Some(target) = request_url
        .query_pairs()
        .find(|(key, _)| key == "url")
        .map(|(_, value)| value.to_string())
    else {
        return with_cors(Response::error("invalid url", 400)?);
    };

    match fetch_ogp_worker(&target).await {
        Ok(data) => {
            let response = OgpResponse { url: target, data };
            with_cors(Response::from_json(&response)?)
        }
        Err(err) => with_cors(error_response(err)?),
    }
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

        let mut init = RequestInit::new();
        init.with_method(Method::Get)
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

fn with_cors(response: Response) -> Result<Response> {
    let headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set("Access-Control-Allow-Methods", "GET, OPTIONS")?;
    headers.set("Access-Control-Allow-Headers", "*")?;
    Ok(response.with_headers(headers))
}
