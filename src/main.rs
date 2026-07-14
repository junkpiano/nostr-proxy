use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use hickory_resolver::TokioResolver;
use nostr_proxy::{native::fetch_ogp, OgpError, OgpQuery, OgpResponse};
use reqwest::Client;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tower::ServiceBuilder;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tracing::{error, info, warn};

#[derive(Clone)]
struct AppState {
    client: Client,
    resolver: Arc<TokioResolver>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let user_agent = std::env::var("USER_AGENT").unwrap_or_else(|_| {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".to_string()
    });

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client");

    let resolver = TokioResolver::builder_tokio()
        .expect("failed to read system DNS config")
        .build()
        .expect("failed to create DNS resolver");

    let state = AppState {
        client,
        resolver: Arc::new(resolver),
    };

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

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin, _| {
            origin
                .to_str()
                .map(nostr_proxy::is_allowed_origin)
                .unwrap_or(false)
        }))
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
