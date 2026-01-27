use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::SocketAddr, time::Duration};
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info};
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
        .user_agent(user_agent)
        .build()
        .expect("reqwest client");

    let app = Router::new()
        .route("/api/ogp", get(ogp_handler))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any))
        .with_state(client);

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let addr: SocketAddr = bind_addr.parse().expect("BIND_ADDR must be host:port");

    info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("server");
}

async fn ogp_handler(
    Query(params): Query<OgpQuery>,
    axum::extract::State(client): axum::extract::State<Client>,
) -> impl IntoResponse {
    match fetch_ogp(&client, &params.url).await {
        Ok(data) => {
            let resp = OgpResponse {
                url: params.url,
                data,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => {
            error!("ogp fetch error: {:?}", err);
            let (status, msg) = match err {
                OgpError::InvalidUrl(_) => (StatusCode::BAD_REQUEST, "invalid url"),
                OgpError::Request(_) => (StatusCode::BAD_GATEWAY, "fetch failed"),
                OgpError::Parse => (StatusCode::BAD_GATEWAY, "parse failed"),
            };
            (status, msg).into_response()
        }
    }
}

#[derive(Debug)]
enum OgpError {
    InvalidUrl(String),
    Request(reqwest::Error),
    Parse,
}

async fn fetch_ogp(client: &Client, target: &str) -> Result<BTreeMap<String, String>, OgpError> {
    let url = validate_url(target)?;
    let body = client
        .get(url)
        .send()
        .await
        .map_err(OgpError::Request)?
        .error_for_status()
        .map_err(OgpError::Request)?
        .text()
        .await
        .map_err(OgpError::Request)?;

    parse_ogp(&body)
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
