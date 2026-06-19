mod cache;
mod config;
mod metrics;
mod middleware;
mod proxy;
mod security;
mod tls;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, StatusCode},
    routing::{any, get},
};
use serde::Serialize;
use tokio::sync::RwLock;
use tower_http::{
    cors::{Any, CorsLayer},
    request_id::{MakeRequestUuid, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use cache::cache::ResponseCache;
use config::config::AppConfig;
use metrics::Metrics;
use middleware::{
    bot_detection::BotDetector, ip_filter::IpFilter, rate_limit::RateLimiter,
    request_validation::RequestValidator,
};
use proxy::forward::ProxyHandler;
use proxy::upstream::{LoadBalancer, RetryPolicy, UpstreamPool};
use security::waf::Waf;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<AppConfig>>,
    pub config_path: String,
    pub ip_filter: Arc<IpFilter>,
    pub rate_limiter: Arc<RateLimiter>,
    pub bot_detector: Arc<BotDetector>,
    pub request_validator: Arc<RequestValidator>,
    pub waf: Arc<Waf>,
    pub cache: Arc<ResponseCache>,
    pub proxy_handler: Arc<ProxyHandler>,
    pub metrics: Arc<Metrics>,
    pub start_time: Arc<std::time::SystemTime>,
    pub hsts_header: Option<HeaderValue>,
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
    // Initialize tracing subscriber before loading config to capture startup logs
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "rust_gateway=debug,tower_http=debug".into());

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    info!("Starting Rust Security Gateway...");

    let config_path =
        std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config/default.toml".to_string());
    let cfg = AppConfig::load_from(&config_path).expect("Failed to load configuration");

    cfg.validate().unwrap_or_else(|errors| {
        panic!(
            "Configuration validation failed:\n  {}",
            errors.join("\n  ")
        );
    });

    info!("Configuration loaded and validated successfully");
    info!(
        "   Gateway listening on: {}:{}",
        cfg.server.host, cfg.server.port
    );
    for url in &cfg.backend.urls {
        info!("   Forwarding to backend: {}", url);
    }
    if cfg.backend.urls.is_empty() {
        info!("   Forwarding to backend: {}", cfg.backend.url);
    }

    let start_time = Arc::new(std::time::SystemTime::now());

    // Metrics
    let metrics = Arc::new(Metrics::new().expect("Failed to initialize metrics"));
    info!("Metrics initialized");

    // IP Filter
    let ip_filter = Arc::new(IpFilter::new(
        cfg.ip_filter.blacklist.clone(),
        cfg.ip_filter.whitelist.clone(),
    ));
    info!(
        "IP Filter initialized ({} blacklisted, {} whitelisted)",
        cfg.ip_filter.blacklist.len(),
        cfg.ip_filter.whitelist.len()
    );

    // Rate Limiter
    let rate_limiter = Arc::new(RateLimiter::new(
        cfg.rate_limit.max_requests,
        cfg.rate_limit.window_seconds,
    ));
    info!(
        "Rate Limiter initialized ({} req/{} sec)",
        cfg.rate_limit.max_requests, cfg.rate_limit.window_seconds
    );

    // Bot Detector
    let bot_detector = Arc::new(BotDetector::new(
        cfg.bot_detection.block_missing_user_agent,
        cfg.bot_detection.bad_user_agents.clone(),
    ));
    info!("Bot Detector initialized");

    // WAF
    let waf = Arc::new(Waf::new());
    info!("Web Application Firewall initialized");

    // Request Validator
    let request_validator = Arc::new(RequestValidator::new(cfg.waf.max_body_size));
    info!(
        "Request Validator initialized (max body: {} bytes)",
        cfg.waf.max_body_size
    );

    // Cache
    let cache = Arc::new(ResponseCache::new(
        cfg.cache.max_items,
        cfg.cache.ttl_seconds,
    ));
    info!(
        "Response Cache initialized (TTL: {} sec, max: {} items)",
        cfg.cache.ttl_seconds, cfg.cache.max_items
    );

    // Proxy Handler with upstream pool, retries, and circuit breaker
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.backend.timeout_seconds))
        .pool_max_idle_per_host(cfg.pool.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(cfg.pool.idle_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("RustGateway/1.0")
        .build()
        .expect("Failed to build HTTP client");

    let retry_policy = RetryPolicy::new(
        cfg.backend.retry.max_retries,
        cfg.backend.retry.base_delay_ms,
    );

    let cb = &cfg.backend.circuit_breaker;
    let backend_urls = if !cfg.backend.urls.is_empty() {
        cfg.backend.urls.clone()
    } else {
        vec![cfg.backend.url.clone()]
    };
    let load_balancer = match cfg.backend.load_balancing.strategy.as_str() {
        "least_connections" => LoadBalancer::LeastConnections,
        _ => LoadBalancer::RoundRobin,
    };
    let pool = Arc::new(UpstreamPool::new(
        backend_urls,
        retry_policy,
        if cb.enabled {
            cb.failure_threshold
        } else {
            u32::MAX
        },
        Duration::from_secs(cb.recovery_timeout_secs),
        load_balancer,
    ));

    let proxy_handler = Arc::new(ProxyHandler::new(client.clone(), pool.clone()));
    info!(
        "Proxy Handler initialized (backends: {} urls, strategy: {}, retries: {}, circuit breaker: {})",
        pool.upstreams().len(),
        cfg.backend.load_balancing.strategy,
        cfg.backend.retry.max_retries,
        if cfg.backend.circuit_breaker.enabled {
            "on"
        } else {
            "off"
        },
    );

    // Active health checks — background task that probes upstreams periodically
    if cfg.backend.health_check.enabled {
        let hc = cfg.backend.health_check.clone();
        let checker = proxy::health::HealthChecker::new(
            pool.clone(),
            client.clone(),
            hc.interval_secs,
            hc.timeout_secs,
            hc.path.clone(),
        );
        tokio::spawn(async move {
            checker.run().await;
        });
        info!(
            "Health checker started (interval: {}s, timeout: {}s, path: {})",
            hc.interval_secs, hc.timeout_secs, hc.path
        );
    }

    let hsts_header = if cfg.tls.enabled && cfg.tls.hsts.enabled {
        let mut value = format!("max-age={}", cfg.tls.hsts.max_age);
        if cfg.tls.hsts.include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if cfg.tls.hsts.preload {
            value.push_str("; preload");
        }
        Some(HeaderValue::from_str(&value).expect("Invalid HSTS header value"))
    } else {
        None
    };

    let state = AppState {
        config: Arc::new(RwLock::new(cfg.clone())),
        config_path: config_path.clone(),
        ip_filter,
        rate_limiter,
        bot_detector,
        request_validator,
        waf,
        cache,
        proxy_handler,
        metrics,
        start_time,
        hsts_header,
    };

    // Spawn SIGHUP listener for config reload
    let reload_state = state.clone();
    let reload_path = config_path.clone();
    tokio::spawn(async move {
        sighup_listener(reload_state, &reload_path).await;
    });

    // Build router with health/metrics endpoints BEFORE the catch-all proxy route
    let mut app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/live", get(live_handler))
        .route("/metrics", get(metrics_handler))
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
        ));

    // Add CORS layer if enabled
    if cfg.cors.enabled {
        let methods: Vec<axum::http::Method> = cfg
            .cors
            .allowed_methods
            .iter()
            .filter_map(|m| m.parse().ok())
            .collect();
        let headers: Vec<axum::http::HeaderName> = cfg
            .cors
            .allowed_headers
            .iter()
            .filter_map(|h| h.parse().ok())
            .collect();

        let cors = if cfg.cors.allowed_origins.is_empty() {
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(methods)
                .allow_headers(headers)
                .allow_credentials(cfg.cors.allow_credentials)
                .max_age(Duration::from_secs(cfg.cors.max_age_secs))
        } else {
            let origins: Vec<HeaderValue> = cfg
                .cors
                .allowed_origins
                .iter()
                .filter_map(|o| HeaderValue::from_str(o).ok())
                .collect();
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods(methods)
                .allow_headers(headers)
                .allow_credentials(cfg.cors.allow_credentials)
                .max_age(Duration::from_secs(cfg.cors.max_age_secs))
        };
        app = app.layer(cors);
        info!("CORS middleware enabled");
    }

    let app = app.with_state(state);

    let addr: SocketAddr = format!("{}:{}", cfg.server.host, cfg.server.port)
        .parse()
        .expect("Invalid server address in config");

    if cfg.tls.enabled {
        info!("TLS is enabled, starting HTTPS server...");
        info!("Gateway is LIVE and listening on https://{}", addr);
        info!("Health endpoint: https://{}/health", addr);
        info!("Readiness endpoint: https://{}/ready", addr);
        info!("Liveness endpoint: https://{}/live", addr);

        let tls_config =
            tls::create_tls_config(&cfg.tls).expect("Failed to create TLS configuration");

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

/// Metrics endpoint - Prometheus metrics
async fn metrics_handler(State(state): State<AppState>) -> axum::response::Response {
    use axum::response::IntoResponse;

    match state.metrics.encode() {
        Ok(body) => (
            StatusCode::OK,
            [("Content-Type", "text/plain; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(e) => {
            error!("Failed to encode metrics: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Metrics error").into_response()
        }
    }
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

/// Listen for SIGHUP and reload configuration
#[cfg(unix)]
async fn sighup_listener(state: AppState, config_path: &str) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sig = signal(SignalKind::hangup()).expect("failed to install SIGHUP handler");
    info!("SIGHUP config reload listener installed");
    loop {
        sig.recv().await;
        info!("SIGHUP received, reloading configuration...");
        reload_config(&state, config_path).await;
    }
}

/// Reload configuration from disk and update shared state
async fn reload_config(state: &AppState, config_path: &str) {
    match AppConfig::load_from(config_path) {
        Ok(new_config) => {
            info!("Config file reloaded successfully");
            // Update the shared config
            let mut cfg = state.config.write().await;
            *cfg = new_config;
            info!(
                "Configuration hot-reloaded. Some changes may require a restart to take full effect."
            );
        }
        Err(e) => {
            error!(
                "Failed to reload config: {}. Keeping previous configuration.",
                e
            );
        }
    }
}

async fn handle_request(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> axum::response::Response {
    let start = Instant::now();
    let method_string = req.method().to_string();

    let response = handle_request_inner(state.clone(), req).await;

    let status_str = response.status().as_u16().to_string();
    state
        .metrics
        .http_requests_total
        .with_label_values(&[&method_string, &status_str])
        .inc();
    state
        .metrics
        .http_request_duration_seconds
        .with_label_values(&[&method_string])
        .observe(start.elapsed().as_secs_f64());

    response
}

async fn handle_request_inner(
    state: AppState,
    req: axum::extract::Request,
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
        state.metrics.rate_limit_hits_total.inc();
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

    let is_get = parts.method == axum::http::Method::GET;
    let cache_key = if is_get {
        let key = format!("{}{}", parts.uri.path(), query);
        if let Some(cached_response) = state.cache.get(&key) {
            info!("Cache HIT for: {} (request_id: {})", key, request_id);
            state.metrics.cache_hits_total.inc();
            return cached_response;
        }
        info!("Cache MISS for: {} (request_id: {})", key, request_id);
        state.metrics.cache_misses_total.inc();
        key
    } else {
        String::new()
    };

    // "All checks passed! Forward the request to the real server."
    info!(
        "All checks passed for: {} - forwarding to backend (request_id: {})",
        ip_str, request_id
    );

    // Rebuild the request from parts + body and forward to backend
    let req = axum::extract::Request::from_parts(parts, axum::body::Body::from(body_bytes));

    let response = state.proxy_handler.forward(req).await;

    // Cache write-through: store successful GET responses
    if is_get && response.status() == StatusCode::OK {
        use http_body_util::BodyExt;
        let (parts, body) = response.into_parts();
        match body.collect().await {
            Ok(collected) => {
                let bytes = collected.to_bytes();
                let content_type = parts
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/octet-stream")
                    .to_string();

                state.cache.set(
                    cache_key.clone(),
                    parts.status.as_u16(),
                    bytes.to_vec(),
                    content_type,
                );

                info!(
                    "Cached response for: {} (request_id: {})",
                    cache_key, request_id
                );
                axum::http::Response::from_parts(parts, axum::body::Body::from(bytes))
            }
            Err(e) => {
                error!("Failed to read response body for caching: {}", e);
                axum::http::Response::from_parts(parts, axum::body::Body::from(bytes::Bytes::new()))
            }
        }
    } else {
        response
    }
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
    async fn test_metrics_endpoint() {
        let app = make_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_returns_ok() {
        let app = make_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
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
            .route("/metrics", get(metrics_handler))
            .route("/", any(handle_request))
            .route("/*path", any(handle_request))
            .with_state(AppState {
                config: Arc::new(RwLock::new(AppConfig::default())),
                config_path: "config/default.toml".to_string(),
                ip_filter: Arc::new(IpFilter::new(vec![], vec![])),
                rate_limiter: Arc::new(RateLimiter::new(100, 60)),
                bot_detector: Arc::new(BotDetector::new(false, vec![])),
                request_validator: Arc::new(RequestValidator::new(1_048_576)),
                waf: Arc::new(Waf::new()),
                cache: Arc::new(ResponseCache::new(100, 300)),
                proxy_handler: Arc::new(ProxyHandler::new(client, pool)),
                metrics: Arc::new(Metrics::new().unwrap()),
                start_time: Arc::new(std::time::SystemTime::now()),
                hsts_header: None,
            })
    }
}
