use std::sync::Arc;

use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body_util::BodyExt;
use reqwest::Client;
use tokio::time::sleep;
use tracing::{debug, error, warn};

use super::upstream::UpstreamPool;

pub struct ProxyHandler {
    client: Client,
    pool: Arc<UpstreamPool>,
}

fn build_upstream_url(upstream_url: &str, uri: &axum::http::Uri) -> String {
    let path = uri.path();
    match uri.query() {
        Some(query) => format!("{}{}?{}", upstream_url, path, query),
        None => format!("{}{}", upstream_url, path),
    }
}

fn is_retryable_error(e: &reqwest::Error) -> bool {
    e.is_timeout() || e.is_connect() || e.is_request()
}

fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error()
}

fn build_forward_request(
    client: &Client,
    method: &axum::http::Method,
    upstream_url: &str,
    uri: &axum::http::Uri,
    headers: &axum::http::HeaderMap,
    body_bytes: &Bytes,
) -> reqwest::RequestBuilder {
    let reqwest_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);

    let backend_url = build_upstream_url(upstream_url, uri);

    let mut request_builder = client.request(reqwest_method, &backend_url);

    let hop_by_hop_headers = [
        "host",
        "connection",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
    ];

    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if !hop_by_hop_headers.contains(&name_str.as_str()) {
            request_builder = request_builder.header(name.clone(), value.clone());
        }
    }

    request_builder = request_builder
        .header("X-Forwarded-For", "client-ip")
        .header("X-Forwarded-Proto", "http")
        .header("X-Gateway", "RustGateway/1.0");

    if !body_bytes.is_empty() {
        request_builder = request_builder.body(body_bytes.to_vec());
    }

    request_builder
}

fn build_error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        [("Content-Type", "application/json")],
        format!(
            r#"{{"error": "{}", "message": "{}"}}"#,
            status.canonical_reason().unwrap_or("Unknown"),
            message
        ),
    )
        .into_response()
}

async fn build_forward_response(backend_response: reqwest::Response) -> Response {
    let status = backend_response.status();
    let response_headers = backend_response.headers().clone();

    let response_body = match backend_response.bytes().await {
        Ok(bytes) => bytes,
        Err(_) => {
            return build_error_response(
                StatusCode::BAD_GATEWAY,
                "Failed to read backend response",
            );
        }
    };

    let mut response_builder = axum::http::Response::builder().status(status.as_u16());

    if let Some(resp_headers) = response_builder.headers_mut() {
        for (name, value) in response_headers.iter() {
            let name_str = name.as_str().to_lowercase();
            if !["connection", "transfer-encoding", "keep-alive"].contains(&name_str.as_str()) {
                resp_headers.insert(name.clone(), value.clone());
            }
        }
        resp_headers.insert("X-Gateway", HeaderValue::from_static("RustGateway/1.0"));
    }

    response_builder
        .body(axum::body::Body::from(response_body))
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "Response build error").into_response()
        })
}

impl ProxyHandler {
    pub fn new(client: Client, pool: Arc<UpstreamPool>) -> Self {
        Self { client, pool }
    }

    pub async fn forward(&self, req: Request) -> Response {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let headers = req.headers().clone();

        let body_bytes = match collect_body(req).await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to read request body: {}", e);
                return (StatusCode::BAD_GATEWAY, "Failed to read request body").into_response();
            }
        };

        let retry_policy = self.pool.retry_policy();
        let max_retries = retry_policy.max_retries;
        let mut last_error: Option<Response> = None;

        for attempt in 0..=max_retries {
            let upstream = match self.pool.pick() {
                Some(u) => u,
                None => {
                    return build_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "No upstream servers available",
                    );
                }
            };

            let backend_url = build_upstream_url(&upstream.url, &uri);
            debug!(
                "Forwarding {} {} → {} (attempt {}/{})",
                method,
                uri,
                backend_url,
                attempt + 1,
                max_retries + 1
            );

            let request_builder = build_forward_request(
                &self.client,
                &method,
                &upstream.url,
                &uri,
                &headers,
                &body_bytes,
            );

            match request_builder.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if is_retryable_status(status) && attempt < max_retries {
                        warn!("Backend {} returned {} (retrying)", upstream.url, status);
                        upstream.record_failure();
                        last_error = Some(build_error_response(
                            StatusCode::BAD_GATEWAY,
                            &format!("Backend returned status {}", status.as_u16()),
                        ));
                        sleep(retry_policy.delay(attempt)).await;
                        continue;
                    }
                    upstream.record_success();
                    return build_forward_response(resp).await;
                }
                Err(e) => {
                    let is_retryable = is_retryable_error(&e) && attempt < max_retries;
                    upstream.record_failure();

                    if e.is_timeout() {
                        warn!(
                            "Backend timeout for: {} (attempt {})",
                            upstream.url,
                            attempt + 1
                        );
                        last_error = Some(build_error_response(
                            StatusCode::GATEWAY_TIMEOUT,
                            "The backend server did not respond in time.",
                        ));
                    } else if e.is_connect() {
                        error!(
                            "Cannot connect to backend: {} (attempt {})",
                            upstream.url,
                            attempt + 1
                        );
                        last_error = Some(build_error_response(
                            StatusCode::BAD_GATEWAY,
                            "Cannot connect to the backend server. It may be down.",
                        ));
                    } else {
                        error!("Backend request failed: {} (attempt {})", e, attempt + 1);
                        last_error = Some(build_error_response(
                            StatusCode::BAD_GATEWAY,
                            &format!("Backend request failed: {}", e),
                        ));
                    }

                    if is_retryable {
                        debug!("Retrying in {:?}...", retry_policy.delay(attempt));
                        sleep(retry_policy.delay(attempt)).await;
                    } else {
                        return last_error.unwrap();
                    }
                }
            }
        }

        last_error.unwrap_or_else(|| {
            build_error_response(StatusCode::BAD_GATEWAY, "All retry attempts failed")
        })
    }
}

async fn collect_body(req: Request) -> Result<Bytes, String> {
    let body = req.into_body();
    body.collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Uri;

    #[test]
    fn test_build_upstream_url_no_query() {
        let uri = Uri::from_static("/api/users");
        let url = build_upstream_url("http://backend:8080", &uri);
        assert_eq!(url, "http://backend:8080/api/users");
    }

    #[test]
    fn test_build_upstream_url_with_query() {
        let uri = Uri::from_static("/search?q=hello&page=2");
        let url = build_upstream_url("http://backend:8080", &uri);
        assert_eq!(url, "http://backend:8080/search?q=hello&page=2");
    }

    #[test]
    fn test_build_upstream_url_root() {
        let uri = Uri::from_static("/");
        let url = build_upstream_url("http://backend:8080", &uri);
        assert_eq!(url, "http://backend:8080/");
    }

    #[test]
    fn test_is_retryable_status_5xx() {
        assert!(is_retryable_status(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR
        ));
        assert!(is_retryable_status(reqwest::StatusCode::BAD_GATEWAY));
        assert!(is_retryable_status(
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        ));
        assert!(is_retryable_status(reqwest::StatusCode::GATEWAY_TIMEOUT));
    }

    #[test]
    fn test_is_retryable_status_4xx_not_retryable() {
        assert!(!is_retryable_status(reqwest::StatusCode::BAD_REQUEST));
        assert!(!is_retryable_status(reqwest::StatusCode::NOT_FOUND));
        assert!(!is_retryable_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
    }

    #[test]
    fn test_build_error_response_format() {
        let resp = build_error_response(StatusCode::BAD_GATEWAY, "Backend is down");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_build_error_response_gateway_timeout() {
        let resp = build_error_response(StatusCode::GATEWAY_TIMEOUT, "Backend timeout");
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    }
}
