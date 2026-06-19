mod cache;
mod config;
mod middleware;
mod proxy;
mod security;
mod tls;

// Standard library imports
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

// Axum - our web framework
use axum::{
    Json, Router,
    extract::State,
    routing::{any, get},
};

use axum::http::StatusCode;

use serde::Serialize;

// Logging
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Tower HTTP middleware
use tower_http::{
    request_id::{MakeRequestUuid, SetRequestIdLayer},
    trace::TraceLayer,
};

// Our own modules
use cache::cache::ResponseCache;
use config::config::AppConfig;
use middleware::{
    bot_detection::BotDetector, ip_filter::IpFilter, rate_limit::RateLimiter,
    request_validation::RequestValidator,
};
use proxy::forward::ProxyHandler;
use proxy::upstream::{RetryPolicy, UpstreamPool};
use security::waf::Waf;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub ip_filter: Arc<IpFilter>,
    pub rate_limiter: Arc<RateLimiter>,
    pub bot_detector: Arc<BotDetector>,
    pub request_validator: Arc<RequestValidator>,
    pub waf: Arc<Waf>,
    pub cache: Arc<ResponseCache>,
    pub proxy_handler: Arc<ProxyHandler>,
    pub start_time: Arc<std::time::SystemTime>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
    uptime_secs: u64,
}

#[derive(Serialize)]
struct ReadinessResponse {
    status: &'static str,
    backend: &'static str,
}

#[derive(Serialize)]
struct LivenessResponse {
    status: &'static str,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rust_gateway=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Rust Security Gateway...");

    let config = Arc::new(
        AppConfig::load().expect("Failed to load configuration. Check config/default.toml"),
    );

    config.validate().unwrap_or_else(|errors| {
        panic!(
            "Configuration validation failed:\n  {}",
            errors.join("\n  ")
        );
    });

    info!("Configuration loaded and validated successfully");
    info!(
        "   Gateway listening on: {}:{}",
        config.server.host, config.server.port
    );
    info!("   Forwarding to backend: {}", config.backend.url);

    let start_time = Arc::new(std::time::SystemTime::now());

    // IP Filter
    let ip_filter = Arc::new(IpFilter::new(
        config.ip_filter.blacklist.clone(),
        config.ip_filter.whitelist.clone(),
    ));
    info!(
        "IP Filter initialized ({} blacklisted, {} whitelisted)",
        config.ip_filter.blacklist.len(),
        config.ip_filter.whitelist.len()
    );

    // Rate Limiter
    let rate_limiter = Arc::new(RateLimiter::new(
        config.rate_limit.max_requests,
        config.rate_limit.window_seconds,
    ));
    info!(
        "Rate Limiter initialized ({} req/{} sec)",
        config.rate_limit.max_requests, config.rate_limit.window_seconds
    );

    // Bot Detector
    let bot_detector = Arc::new(BotDetector::new(
        config.bot_detection.block_missing_user_agent,
        config.bot_detection.bad_user_agents.clone(),
    ));
    info!("Bot Detector initialized");

    // WAF
    let waf = Arc::new(Waf::new());
    info!("Web Application Firewall initialized");

    // Request Validator
    let request_validator = Arc::new(RequestValidator::new(config.waf.max_body_size));
    info!(
        "Request Validator initialized (max body: {} bytes)",
        config.waf.max_body_size
    );

    // Cache
    let cache = Arc::new(ResponseCache::new(
        config.cache.max_items,
        config.cache.ttl_seconds,
    ));
    info!(
        "Response Cache initialized (TTL: {} sec, max: {} items)",
        config.cache.ttl_seconds, config.cache.max_items
    );

    // Proxy Handler with upstream pool, retries, and circuit breaker
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.backend.timeout_seconds))
        .pool_max_idle_per_host(32)
        .pool_idle_timeout(Duration::from_secs(90))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("RustGateway/1.0")
        .build()
        .expect("Failed to build HTTP client");

    let retry_policy = RetryPolicy::new(
        config.backend.retry.max_retries,
        config.backend.retry.base_delay_ms,
    );

    let cb = &config.backend.circuit_breaker;
    let pool = Arc::new(UpstreamPool::from_url(
        config.backend.url.clone(),
        retry_policy,
        if cb.enabled {
            cb.failure_threshold
        } else {
            u32::MAX
        },
        Duration::from_secs(cb.recovery_timeout_secs),
    ));

    let proxy_handler = Arc::new(ProxyHandler::new(client, pool));
    info!(
        "Proxy Handler initialized (backend: {}, retries: {}, circuit breaker: {})",
        config.backend.url,
        config.backend.retry.max_retries,
        if config.backend.circuit_breaker.enabled {
            "on"
        } else {
            "off"
        },
    );

    let state = AppState {
        config: config.clone(),
        ip_filter,
        rate_limiter,
        bot_detector,
        request_validator,
        waf,
        cache,
        proxy_handler,
        start_time,
    };

    // Build router with health endpoints BEFORE the catch-all proxy route
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/live", get(live_handler))
        .route("/", any(handle_request))
        .route("/*path", any(handle_request))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::extract::Request| {
                    let request_id = request
                        .extensions()
                        .get::<uuid::Uuid>()
                        .map(|u| u.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    tracing::info_span!(
                        "http_request",
                        method = ?request.method(),
                        uri = ?request.uri(),
                        request_id = %request_id,
                    )
                })
                .on_request(|request: &axum::extract::Request, _span: &tracing::Span| {
                    let request_id = request
                        .extensions()
                        .get::<uuid::Uuid>()
                        .map(|u| u.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    tracing::debug!(
                        "started {} {} (request_id: {})",
                        request.method(),
                        request.uri(),
                        request_id,
                    );
                })
                .on_response(
                    |response: &axum::http::Response<axum::body::Body>,
                     latency: Duration,
                     _span: &tracing::Span| {
                        tracing::debug!(
                            "response {} ({}µs)",
                            response.status(),
                            latency.as_micros(),
                        );
                    },
                ),
        )
        .layer(SetRequestIdLayer::new(
            axum::http::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("Invalid server address in config");

    if config.tls.enabled {
        info!("TLS is enabled, starting HTTPS server...");
        info!("Gateway is LIVE and listening on https://{}", addr);
        info!("Health endpoint: https://{}/health", addr);
        info!("Readiness endpoint: https://{}/ready", addr);
        info!("Liveness endpoint: https://{}/live", addr);

        let tls_config = tls::create_tls_config(&config.tls.cert_path, &config.tls.key_path)
            .expect("Failed to create TLS configuration");

        tls::serve_tls(app, addr, tls_config, shutdown_signal()).await;
    } else {
        info!("Gateway is LIVE and listening on http://{}", addr);
        info!("Health endpoint: http://{}/health", addr);
        info!("Readiness endpoint: http://{}/ready", addr);
        info!("Liveness endpoint: http://{}/live", addr);

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("Failed to bind to address. Is the port already in use?");

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .expect("Server crashed unexpectedly");
    }
}

/// Health endpoint - overall service health
async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    let uptime = state
        .start_time
        .elapsed()
        .unwrap_or(Duration::from_secs(0))
        .as_secs();

    Json(HealthResponse {
        status: "ok",
        service: "rust-gateway",
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: uptime,
    })
}

/// Readiness endpoint - is the gateway ready to accept traffic?
async fn ready_handler() -> Json<ReadinessResponse> {
    // Basic readiness: the process is running and accepting connections
    // Full backend health checks will be added in Phase 3
    Json(ReadinessResponse {
        status: "ready",
        backend: "unknown",
    })
}

/// Liveness endpoint - is the process alive?
async fn live_handler() -> Json<LivenessResponse> {
    Json(LivenessResponse { status: "alive" })
}

/// Handle graceful shutdown on SIGTERM/SIGINT
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received, gracefully shutting down...");
}

async fn handle_request(
    State(state): State<AppState>, // Our "backpack" with all tools
    req: axum::extract::Request,   // The incoming HTTP request
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Extract the client IP first (needed for all checks and logging)
    let ip_str = extract_client_ip(&req);

    // Extract request info for logging BEFORE we consume the request
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    // Get the request ID for correlation
    let request_id = req
        .extensions()
        .get::<uuid::Uuid>()
        .map(|u| u.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    info!(
        "Incoming request: {} {} from IP: {} (request_id: {})",
        method, path, ip_str, request_id
    );

    if let Err(response) = state.ip_filter.check(&ip_str) {
        warn!(
            "BLOCKED by IP Filter: {} (request_id: {})",
            ip_str, request_id
        );
        return response;
    }

    if let Err(response) = state.rate_limiter.check(&ip_str) {
        warn!(
            "RATE LIMITED: {} (too many requests) (request_id: {})",
            ip_str, request_id
        );
        return response;
    }

    if let Err(response) = state.bot_detector.check(req.headers()) {
        warn!(
            "BLOCKED by Bot Detector: {} (request_id: {})",
            ip_str, request_id
        );
        return response;
    }

    let (parts, body) = req.into_parts();

    // Read the body bytes (the content of the request)
    let body_bytes = match read_body(body).await {
        Ok(bytes) => bytes,
        Err(_) => {
            warn!(
                "Failed to read request body from: {} (request_id: {})",
                ip_str, request_id
            );
            return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
        }
    };

    // Check body size limit FIRST
    if let Err(response) = state.request_validator.check_body_size(&body_bytes) {
        warn!(
            "REQUEST TOO LARGE from: {} ({} bytes) (request_id: {})",
            ip_str,
            body_bytes.len(),
            request_id
        );
        return response;
    }

    // Scan the body for attack patterns
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    if let Err(response) = state.waf.inspect_body(&body_str) {
        warn!(
            "WAF BLOCKED request body from: {} (request_id: {})",
            ip_str, request_id
        );
        return response;
    }

    // Scan the URL/query parameters for attack patterns
    let query = parts.uri.query().unwrap_or("").to_string();
    if let Err(response) = state.waf.inspect_query(&query) {
        warn!(
            "WAF BLOCKED query params from: {} (request_id: {})",
            ip_str, request_id
        );
        return response;
    }

    // Scan the headers for attack patterns
    if let Err(response) = state.waf.inspect_headers(&parts.headers) {
        warn!(
            "WAF BLOCKED headers from: {} (request_id: {})",
            ip_str, request_id
        );
        return response;
    }

    if let Err(response) = state.request_validator.validate_headers(&parts.headers) {
        warn!(
            "INVALID REQUEST from: {} - bad headers (request_id: {})",
            ip_str, request_id
        );
        return response;
    }

    if parts.method == axum::http::Method::GET {
        let cache_key = format!("{}{}", parts.uri.path(), query);
        if let Some(cached_response) = state.cache.get(&cache_key) {
            info!("Cache HIT for: {} (request_id: {})", cache_key, request_id);
            return cached_response;
        }
        info!("Cache MISS for: {} (request_id: {})", cache_key, request_id);
    }

    // "All checks passed! Forward the request to the real server."
    info!(
        "All checks passed for: {} - forwarding to backend (request_id: {})",
        ip_str, request_id
    );

    // Rebuild the request from parts + body and forward to backend
    let req = axum::extract::Request::from_parts(parts, axum::body::Body::from(body_bytes));

    state.proxy_handler.forward(req).await
}

fn extract_client_ip(req: &axum::extract::Request) -> String {
    // Check X-Forwarded-For header (set by proxies/load balancers)
    if let Some(forwarded_for) = req.headers().get("x-forwarded-for")
        && let Ok(value) = forwarded_for.to_str()
    {
        // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
        // We want the first one (the real client)
        if let Some(first_ip) = value.split(',').next() {
            return first_ip.trim().to_string();
        }
    }

    // Check X-Real-IP header (set by Nginx)
    if let Some(real_ip) = req.headers().get("x-real-ip")
        && let Ok(value) = real_ip.to_str()
    {
        return value.to_string();
    }

    // Fall back to unknown
    "127.0.0.1".to_string()
}

async fn read_body(body: axum::body::Body) -> Result<bytes::Bytes, axum::Error> {
    use http_body_util::BodyExt;
    body.collect().await.map(|collected| collected.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = make_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_liveness_endpoint() {
        let app = make_test_app();
        let response = app
            .oneshot(Request::builder().uri("/live").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readiness_endpoint() {
        let app = make_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_returns_json() {
        use http_body_util::BodyExt;
        let app = make_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["service"], "rust-gateway");
    }

    #[tokio::test]
    async fn test_liveness_returns_json() {
        use http_body_util::BodyExt;
        let app = make_test_app();
        let response = app
            .oneshot(Request::builder().uri("/live").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "alive");
    }

    fn make_test_app() -> Router {
        use std::time::Duration;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();

        let pool = Arc::new(UpstreamPool::from_url(
            "http://localhost:8080".to_string(),
            proxy::upstream::RetryPolicy::new(0, 100),
            10,
            Duration::from_secs(30),
        ));

        Router::new()
            .route("/health", get(health_handler))
            .route("/ready", get(ready_handler))
            .route("/live", get(live_handler))
            .route("/", any(handle_request))
            .route("/*path", any(handle_request))
            .with_state(AppState {
                config: Arc::new(AppConfig::default()),
                ip_filter: Arc::new(IpFilter::new(vec![], vec![])),
                rate_limiter: Arc::new(RateLimiter::new(100, 60)),
                bot_detector: Arc::new(BotDetector::new(false, vec![])),
                request_validator: Arc::new(RequestValidator::new(1_048_576)),
                waf: Arc::new(Waf::new()),
                cache: Arc::new(ResponseCache::new(100, 300)),
                proxy_handler: Arc::new(ProxyHandler::new(client, pool)),
                start_time: Arc::new(std::time::SystemTime::now()),
            })
    }
}
