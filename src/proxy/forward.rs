use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body_util::BodyExt;
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, error, warn};

pub struct ProxyHandler {
    /// The HTTP client used to make requests to the backend
    /// We keep one client and reuse it (connection pooling = faster!)
    client: Client,

    /// The base URL of the backend server
    /// Example: "http://localhost:8080"
    backend_url: String,
}

impl ProxyHandler {
    pub fn new(backend_url: String, timeout_seconds: u64) -> Self {
        // Build an HTTP client with:
        // - A timeout (so we don't wait forever if backend is down)
        // - Connection pooling (reuse TCP connections for speed)
        // - Disabled redirect following (we let the client handle redirects)
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .pool_max_idle_per_host(32) // Keep up to 32 idle connections per host
            .pool_idle_timeout(Duration::from_secs(90)) // Close idle connections after 90s
            .redirect(reqwest::redirect::Policy::none()) // Don't follow redirects automatically
            .user_agent("RustGateway/1.0") // Identify ourselves to the backend
            .build()
            .expect("Failed to build HTTP client");

        debug!("ProxyHandler created for backend: {}", backend_url);

        ProxyHandler {
            client,
            backend_url,
        }
    }

    pub async fn forward(&self, req: Request) -> Response {
        // -----------------------------------------------------------------------
        // STEP 1: Extract request components
        // -----------------------------------------------------------------------
        let method = req.method().clone();
        let uri = req.uri().clone();
        let headers = req.headers().clone();

        // Build the backend URL by combining:
        //   backend_url = "http://localhost:8080"
        //   path = "/api/users"
        //   query = "?page=2"
        //   result = "http://localhost:8080/api/users?page=2"
        let backend_url = self.build_backend_url(&uri);
        debug!("Forwarding {} {} → {}", method, uri, backend_url);

        // -----------------------------------------------------------------------
        // STEP 2: Read the request body
        // -----------------------------------------------------------------------
        let body_bytes = match collect_body(req).await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to read request body: {}", e);
                return (StatusCode::BAD_GATEWAY, "Failed to read request body").into_response();
            }
        };

        // -----------------------------------------------------------------------
        // STEP 3: Build the forwarding request
        // -----------------------------------------------------------------------
        // Convert axum's Method to reqwest's Method
        let reqwest_method =
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);

        // Start building the request to the backend
        let mut request_builder = self.client.request(reqwest_method, &backend_url);

        // -----------------------------------------------------------------------
        // STEP 4: Forward headers (with filtering)
        // -----------------------------------------------------------------------
        // We forward most headers from the client to the backend.
        // But we REMOVE some headers that should not be forwarded:
        //   - "Host" - backend has its own host
        //   - "Connection" - connection management should be fresh
        //   - "Transfer-Encoding" - let reqwest handle encoding
        //
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

        // Add an X-Forwarded-For header to tell the backend the real client IP
        // This is standard practice - the backend can use it for logging
        request_builder = request_builder
            .header("X-Forwarded-For", "client-ip") // Simplified
            .header("X-Forwarded-Proto", "http")
            .header("X-Gateway", "RustGateway/1.0");

        // Add the request body if there is one
        if !body_bytes.is_empty() {
            request_builder = request_builder.body(body_bytes.to_vec());
        }

        // -----------------------------------------------------------------------
        // STEP 5: Send the request to the backend
        // -----------------------------------------------------------------------
        let backend_response = match request_builder.send().await {
            Ok(resp) => resp,
            Err(e) => {
                // The backend is unreachable or returned an error
                if e.is_timeout() {
                    warn!("Backend timeout for: {}", backend_url);
                    return (
                           StatusCode::GATEWAY_TIMEOUT, // HTTP 504
                           [("Content-Type", "application/json")],
                           r#"{"error": "Gateway Timeout", "message": "The backend server did not respond in time."}"#,
                       ).into_response();
                } else if e.is_connect() {
                    error!("Cannot connect to backend: {}", backend_url);
                    return (
                           StatusCode::BAD_GATEWAY, // HTTP 502
                           [("Content-Type", "application/json")],
                           r#"{"error": "Bad Gateway", "message": "Cannot connect to the backend server. It may be down."}"#,
                       ).into_response();
                } else {
                    error!("Backend request failed: {}", e);
                    return (
                           StatusCode::BAD_GATEWAY,
                           [("Content-Type", "application/json")],
                           format!(r#"{{"error": "Bad Gateway", "message": "Backend request failed: {}"}}"#, e),
                       ).into_response();
                }
            }
        };

        // -----------------------------------------------------------------------
        // STEP 6: Build the response to send back to the client
        // -----------------------------------------------------------------------
        let status = backend_response.status();
        let response_headers = backend_response.headers().clone();

        debug!("Backend responded with status: {}", status);

        // Read the backend response body
        let response_body = match backend_response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to read backend response body: {}", e);
                return (StatusCode::BAD_GATEWAY, "Failed to read backend response")
                    .into_response();
            }
        };

        // Build our response to the client
        let mut response_builder = axum::http::Response::builder().status(status.as_u16());

        // Forward response headers from backend to client
        // Again, filter out hop-by-hop headers
        if let Some(resp_headers) = response_builder.headers_mut() {
            for (name, value) in response_headers.iter() {
                let name_str = name.as_str().to_lowercase();
                if !["connection", "transfer-encoding", "keep-alive"].contains(&name_str.as_str()) {
                    resp_headers.insert(name.clone(), value.clone());
                }
            }
            // Add our gateway identifier header
            resp_headers.insert("X-Gateway", HeaderValue::from_static("RustGateway/1.0"));
        }

        // Assemble the final response
        response_builder
            .body(axum::body::Body::from(response_body))
            .unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, "Response build error").into_response()
            })
    }

    fn build_backend_url(&self, uri: &axum::http::Uri) -> String {
        let path = uri.path();

        // Include query string if present
        match uri.query() {
            Some(query) => format!("{}{}?{}", self.backend_url, path, query),
            None => format!("{}{}", self.backend_url, path),
        }
    }
}

async fn collect_body(req: Request) -> Result<Bytes, String> {
    let body = req.into_body();
    body.collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|e| e.to_string())
}
