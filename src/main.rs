mod cache;
mod config;
mod middleware;
mod proxy;
mod security;

// Standard library imports
use std::net::SocketAddr;
use std::sync::Arc;

// Axum - our web framework
use axum::{
    Router,
    extract::State,
    routing::any, // "any" means: handle GET, POST, DELETE... all methods
};

// Logging
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Our own modules
use cache::cache::ResponseCache;
use config::config::AppConfig;
use middleware::{
    bot_detection::BotDetector, ip_filter::IpFilter, rate_limit::RateLimiter,
    request_validation::RequestValidator,
};
use proxy::forward::ProxyHandler;
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
    info!("Configuration loaded successfully");
    info!(
        "   Gateway listening on: {}:{}",
        config.server.host, config.server.port
    );
    info!("   Forwarding to backend: {}", config.backend.url);

    // IP Filter - knows who is banned
    let ip_filter = Arc::new(IpFilter::new(
        config.ip_filter.blacklist.clone(),
        config.ip_filter.whitelist.clone(),
    ));
    info!(
        "IP Filter initialized ({} blacklisted, {} whitelisted)",
        config.ip_filter.blacklist.len(),
        config.ip_filter.whitelist.len()
    );

    // Rate Limiter - counts how many requests each IP makes
    let rate_limiter = Arc::new(RateLimiter::new(
        config.rate_limit.max_requests,
        config.rate_limit.window_seconds,
    ));
    info!(
        "Rate Limiter initialized ({} req/{} sec)",
        config.rate_limit.max_requests, config.rate_limit.window_seconds
    );

    // Bot Detector - catches fake/suspicious browsers
    let bot_detector = Arc::new(BotDetector::new(
        config.bot_detection.block_missing_user_agent,
        config.bot_detection.bad_user_agents.clone(),
    ));
    info!("Bot Detector initialized");

    // WAF - scans for SQL injection, XSS, and other attacks
    let waf = Arc::new(Waf::new());
    info!("Web Application Firewall initialized");

    // Request Validator - checks request size and format
    let request_validator = Arc::new(RequestValidator::new(config.waf.max_body_size));
    info!(
        "Request Validator initialized (max body: {} bytes)",
        config.waf.max_body_size
    );

    // Cache - remembers previous responses to answer faster
    let cache = Arc::new(ResponseCache::new(
        config.cache.max_items,
        config.cache.ttl_seconds,
    ));
    info!(
        "Response Cache initialized (TTL: {} sec, max: {} items)",
        config.cache.ttl_seconds, config.cache.max_items
    );

    //Proxy Handler - the actual forwarder to the backend
    let proxy_handler = Arc::new(ProxyHandler::new(
        config.backend.url.clone(),
        config.backend.timeout_seconds,
    ));
    info!(
        "Proxy Handler initialized (backend: {})",
        config.backend.url
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
    };

    let app = Router::new()
        // Match all paths and all HTTP methods
        .route("/", any(handle_request))
        .route("/*path", any(handle_request))
        // Attach our state (the backpack) to the router
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("❌ Invalid server address in config");

    info!("Gateway is LIVE and listening on http://{}", addr);
    info!("Send requests to http://localhost:{}", config.server.port);
    info!(
        "All requests will be inspected and forwarded to: {}",
        config.backend.url
    );
    info!("Press Ctrl+C to stop the gateway");

    // Create the TCP listener
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address. Is the port already in use?");

    // Start serving
    axum::serve(listener, app)
        .await
        .expect("Server crashed unexpectedly");
}

async fn handle_request(
    State(state): State<AppState>, // Our "backpack" with all tools
    req: axum::extract::Request,   // The incoming HTTP request
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    // Extract the client IP first (needed for all checks and logging)
    let ip_str = extract_client_ip(&req);

    // Extract request info for logging BEFORE we consume the request
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    info!("Incoming request: {} {} from IP: {}", method, path, ip_str);

    if let Err(response) = state.ip_filter.check(&ip_str) {
        warn!("BLOCKED by IP Filter: {}", ip_str);
        return response;
    }

    if let Err(response) = state.rate_limiter.check(&ip_str) {
        warn!("RATE LIMITED: {} (too many requests)", ip_str);
        return response;
    }

    if let Err(response) = state.bot_detector.check(req.headers()) {
        warn!("BLOCKED by Bot Detector: {}", ip_str);
        return response;
    }

    let (parts, body) = req.into_parts();

    // Read the body bytes (the content of the request)
    let body_bytes = match read_body(body).await {
        Ok(bytes) => bytes,
        Err(_) => {
            warn!("Failed to read request body from: {}", ip_str);
            return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
        }
    };

    // Check body size limit FIRST
    if let Err(response) = state.request_validator.check_body_size(&body_bytes) {
        warn!(
            "REQUEST TOO LARGE from: {} ({} bytes)",
            ip_str,
            body_bytes.len()
        );
        return response;
    }

    // Scan the body for attack patterns
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    if let Err(response) = state.waf.inspect_body(&body_str) {
        warn!("WAF BLOCKED request body from: {}", ip_str);
        return response;
    }

    // Scan the URL/query parameters for attack patterns
    let query = parts.uri.query().unwrap_or("").to_string();
    if let Err(response) = state.waf.inspect_query(&query) {
        warn!("WAF BLOCKED query params from: {}", ip_str);
        return response;
    }

    // Scan the headers for attack patterns
    if let Err(response) = state.waf.inspect_headers(&parts.headers) {
        warn!("WAF BLOCKED headers from: {}", ip_str);
        return response;
    }

    if let Err(response) = state.request_validator.validate_headers(&parts.headers) {
        warn!("INVALID REQUEST from: {} - bad headers", ip_str);
        return response;
    }

    if parts.method == axum::http::Method::GET {
        let cache_key = format!("{}{}", parts.uri.path(), query);
        if let Some(cached_response) = state.cache.get(&cache_key) {
            info!("Cache HIT for: {}", cache_key);
            return cached_response;
        }
        info!("Cache MISS for: {}", cache_key);
    }

    // "All checks passed! Forward the request to the real server."
    info!("All checks passed for: {} - forwarding to backend", ip_str);

    // Rebuild the request from parts + body
    let req = axum::extract::Request::from_parts(parts, axum::body::Body::from(body_bytes));

    let response = state.proxy_handler.forward(req).await;

    // If it's a GET request, save the response in cache for next time
    // (We only cache successful responses)

    response
}

fn extract_client_ip(req: &axum::extract::Request) -> String {
    // Check X-Forwarded-For header (set by proxies/load balancers)
    if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded_for.to_str() {
            // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
            // We want the first one (the real client)
            if let Some(first_ip) = value.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }

    // Check X-Real-IP header (set by Nginx)
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            return value.to_string();
        }
    }

    // Fall back to unknown
    "127.0.0.1".to_string()
}

async fn read_body(body: axum::body::Body) -> Result<bytes::Bytes, axum::Error> {
    use http_body_util::BodyExt;
    // Collect all body chunks into one big buffer
    body.collect().await.map(|collected| collected.to_bytes())
}
