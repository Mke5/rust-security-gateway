# rust-gateway

A security-hardened HTTP reverse proxy written in Rust. Provides TLS termination, WAF, rate limiting, IP filtering, bot detection, load balancing, circuit breaking, caching, Prometheus metrics, and JSON logging — all configurable via a single TOML file.

## Features

| Phase | Feature | Status |
|-------|---------|--------|
| 0 | Project scaffolding, config loading, basic reverse proxy | Done |
| 1 | Rate limiting, IP blacklist/whitelist | Done |
| 2 | Bot detection, WAF (SQLi, XSS, path traversal, command injection, LFI, RFI, SSTI, RCE) | Done |
| 3 | Request validation, response caching, health/readiness/liveness endpoints | Done |
| 4 | Retry logic, circuit breaker, upstream pool, active health checks | Done |
| 5 | Mutual TLS (mTLS), Prometheus metrics, structured JSON logging | Done |
| 6 | TLS termination (rustls), HTTP/1.x, HTTP/2, graceful shutdown | Done |
| 7 | Trace/request-id middleware, TCP_NODELAY, connection pooling, SIGHUP config reload | Done |
| 8 | CORS, HSTS, load balancing (round-robin, least-connections), expanded WAF rules | Done |

### Future

| Feature | Priority | Notes |
|---------|----------|-------|
| ACME / Let's Encrypt auto TLS | Medium | Config skeleton exists (`[acme]`). Implement `acme-lib` or `rustls-acme` for automatic cert provisioning and renewal. |
| JWT authentication middleware | Medium | Config skeleton exists (`[auth]`). Validate JWTs from `Authorization` header against JWKS or shared secret. |
| Per-route rate limiting | Medium | Config skeleton exists (`[[route_rate_limits]]`). Apply different rate limits per request path. |
| HTTP/2 upstream | Low | Config field exists (`tls.http2`). Wire h2 connector in reqwest client. |
| Full SIGHUP state rebuild | Low | Currently reloads config into `RwLock`. Rebuild ip_filter, rate_limiter, bot_detector on SIGHUP. |
| Integration tests | Medium | Spin up test backends and verify full request lifecycle. |
| CI/CD pipeline | Medium | GitHub Actions: fmt, clippy, test, build, release. |

## Quick Start

### Prerequisites

- Rust 1.75+ (edition 2024)
- OpenSSL or compatible TLS stack (for `rustls`)

### Build & Run

```bash
# Build
cargo build --release

# Run with default config
./target/release/rust-gateway

# Run with custom config path
CONFIG_PATH=./my-config.toml ./target/release/rust-gateway
```

The server listens on `http://0.0.0.0:3000` by default (configurable in `config/default.toml`).

### Verify

```bash
# Health check
curl http://localhost:3000/health

# Readiness
curl http://localhost:3000/ready

# Liveness
curl http://localhost:3000/live

# Metrics
curl http://localhost:3000/metrics
```

## Configuration

All configuration lives in a single TOML file (default: `config/default.toml`, override with `CONFIG_PATH` env var).

### `[server]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | `"0.0.0.0"` | Bind address |
| `port` | integer | `3000` | Bind port |

### `[backend]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | `"http://localhost:8080"` | Upstream URL (used when `urls` is empty) |
| `urls` | string[] | `[]` | Multiple upstream URLs for load balancing |
| `timeout_seconds` | integer | `30` | HTTP request timeout |

#### `[backend.retry]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_retries` | integer | `2` | Max retry attempts on failure |
| `base_delay_ms` | integer | `100` | Base delay between retries (exponential backoff) |

#### `[backend.circuit_breaker]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable circuit breaker |
| `failure_threshold` | integer | `5` | Consecutive failures before opening circuit |
| `recovery_timeout_secs` | integer | `30` | Time before attempting half-open |

#### `[backend.health_check]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable active health checks |
| `interval_secs` | integer | `10` | Probe interval |
| `timeout_secs` | integer | `5` | Probe timeout |
| `path` | string | `"/health"` | Probe URL path |

#### `[backend.load_balancing]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `strategy` | string | `"least_connections"` | `"round_robin"` or `"least_connections"` |

### `[rate_limit]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_requests` | integer | `100` | Max requests per window per IP |
| `window_seconds` | integer | `60` | Rate limit window |

### `[[route_rate_limits]]`

Per-route rate limit overrides (future). Config skeleton:

```toml
[[route_rate_limits]]
path = "/api/login"
max_requests = 20
window_seconds = 60
```

### `[cache]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ttl_seconds` | integer | `300` | Cache TTL |
| `max_items` | integer | `1000` | Max cache entries |

### `[ip_filter]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `blacklist` | string[] | `[]` | Blocked IPs |
| `whitelist` | string[] | `[]` | Allowed IPs (takes priority) |

### `[bot_detection]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `block_missing_user_agent` | bool | `true` | Block requests without User-Agent |
| `bad_user_agents` | string[] | `[...]` | Known bad user agent strings |

### `[waf]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_body_size` | integer | `1048576` | Max request body (bytes) |

WAF inspects query strings, request bodies, and headers for SQL injection, XSS, path traversal, command injection, LFI, RFI, SSTI, and RCE patterns.

### `[tls]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable TLS/HTTPS |
| `cert_path` | string | `"certs/cert.pem"` | TLS certificate (PEM) |
| `key_path` | string | `"certs/key.pem"` | TLS private key (PEM) |
| `client_ca_path` | string | `""` | CA for mTLS client verification |
| `http2` | bool | `false` | Enable HTTP/2 (future) |

#### `[tls.hsts]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable HSTS header |
| `max_age` | integer | `31536000` | max-age directive |
| `include_subdomains` | bool | `true` | includeSubDomains directive |
| `preload` | bool | `false` | preload directive |

### `[logging]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `format` | string | `"json"` | Log format (`"json"` or `"text"`) |

### `[pool]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_idle_per_host` | integer | `32` | Max idle connections per upstream host |
| `idle_timeout_secs` | integer | `90` | Idle connection timeout |

### `[cors]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable CORS middleware |
| `allowed_origins` | string[] | `[]` | (empty = allow all) |
| `allowed_methods` | string[] | `["GET","POST",...]` | Allowed HTTP methods |
| `allowed_headers` | string[] | `["Content-Type",...]` | Allowed request headers |
| `allow_credentials` | bool | `true` | Allow credentials |
| `max_age_secs` | integer | `86400` | Preflight cache TTL |

### `[auth]`

Config skeleton for JWT authentication (future):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable JWT auth |
| `api_keys` | string[] | `[]` | Static API keys |
| `jwks_url` | string | `""` | JWKS endpoint URL |
| `jwt_secret` | string | `""` | HMAC shared secret |
| `jwt_issuer` | string | `""` | Expected JWT issuer |
| `jwt_audience` | string | `""` | Expected JWT audience |

### `[acme]`

Config skeleton for Let's Encrypt auto TLS (future):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable ACME |
| `directory_url` | string | `"https://acme-v02.api.letsencrypt.org/directory"` | ACME directory |
| `email` | string | `""` | Contact email |
| `domains` | string[] | `[]` | Domain names for cert |
| `cache_path` | string | `"acme_cache"` | Cert cache directory |
| `use_staging` | bool | `false` | Use Let's Encrypt staging |

## Architecture

```
Client ──► Trace/Request-ID ──► CORS ──► IP Filter ──► Rate Limiter
            ──► Bot Detector ──► Request Validator ──► WAF ──► Cache
            ──► Proxy Handler (Retry ──► Circuit Breaker ──► Load Balancer
            ──► Upstream Pool) ──► Backend
```

Middleware stack (applied in order):

1. **TraceLayer** — span/request-id per request
2. **SetRequestIdLayer** — auto-generate UUIDs
3. **CorsLayer** — CORS headers (optional)
4. **IP Filter** — blacklist/whitelist
5. **Rate Limiter** — per-IP sliding window
6. **Bot Detector** — User-Agent filtering
7. **Request Validator** — body size limits, Content-Type checks
8. **WAF** — regex-based attack detection
9. **Cache** — response caching
10. **Proxy Handler** — forward to backend

## Signal Handling

| Signal | Action |
|--------|--------|
| `SIGTERM` | Graceful shutdown (drain connections) |
| `SIGINT` (Ctrl+C) | Graceful shutdown |
| `SIGHUP` | Reload configuration from disk |

## Development

```bash
# Run with hot-reload (cargo-watch)
cargo watch -x run

# Run tests
cargo test

# Check lints
cargo clippy

# Format code
cargo fmt
```

### Testing TLS Locally

```bash
# Generate self-signed cert
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost"

# Update config/default.toml:
#   [tls]
#   enabled = true
#   cert_path = "certs/cert.pem"
#   key_path = "certs/key.pem"

# Run
cargo run
```

## Project Structure

```
src/
├── main.rs                 # Entry point, router, signal handling
├── cache/                  # Response caching
├── config/                 # Configuration loading and validation
├── metrics/                # Prometheus metrics
├── middleware/             # Request middleware (filter, rate-limit, bot-detection, validation)
├── proxy/                  # Proxy forwarding, upstream pool, health checks
├── security/               # WAF (attack pattern detection)
└── tls.rs                  # TLS termination (rustls)

config/
└── default.toml            # Default configuration
```

## Implementation Notes for Future Contributors

### ACME Auto TLS

The `[acme]` config section is defined but not wired. To implement:

1. Add the `acme-lib` or `rustls-acme` crate to Cargo.toml
2. On startup (when `acme.enabled = true`), provision a certificate via ACME
3. Pass the certificate to `create_tls_config()` instead of loading from disk
4. Set up automatic renewal (background task that checks expiry)
5. Fall back to `cert_path`/`key_path` if ACME fails

### JWT Authentication

The `[auth]` config section is defined but the middleware is not implemented. To implement:

1. Add a `jsonwebtoken` or `jwt-simple` crate
2. Create an `AuthMiddleware` layer that extracts the `Authorization: Bearer <token>` header
3. Validate the JWT (signature, expiry, issuer, audience)
4. For JWKS: fetch keys from `jwks_url`, cache them, and use for validation
5. For static API keys: hash and compare
6. Return 401 if validation fails

### Per-Route Rate Limiting

The `[[route_rate_limits]]` config array is defined. To implement:

1. Store per-route rate limits in a `HashMap<String, (u64, u64)>`
2. In the rate limiter middleware, check if the request path matches a route-specific limit
3. Apply the route-specific limit instead of the global one
4. Support prefix matching (e.g., `/api/*`)

### Full SIGHUP State Rebuild

Currently SIGHUP only reloads the config into an `RwLock`. To rebuild state:

1. Create a `ReloadableState` struct holding `ip_filter`, `rate_limiter`, `bot_detector`, etc.
2. Wrap it in `Arc<RwLock<ReloadableState>>`
3. On SIGHUP, rebuild all components from the new config
4. Swap the reloadable state atomically

### HTTP/2 Upstream

The `tls.http2` config field exists. To implement:

1. Enable HTTP/2 in the `reqwest::Client` builder via `http2_prior_knowledge()` or `http2_alpn_protocols()`
2. Handle TLS upgrade for h2 connections
3. Test with backends that support HTTP/2
