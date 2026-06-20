# rust-gateway

[![CI/CD](https://github.com/anomalyco/gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/anomalyco/gateway/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/anomalyco/gateway)](https://github.com/anomalyco/gateway/releases)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-blue)](https://www.rust-lang.org)

A security-hardened HTTP reverse proxy written in Rust. Provides TLS termination, WAF, rate limiting, IP filtering, bot detection, load balancing, circuit breaking, caching, Prometheus metrics, and JSON logging — all configurable via a single TOML file.

Pre-built binaries are available for Linux (x86_64, aarch64), macOS (x86_64, Apple Silicon), and Windows (x86_64) on the [Releases page](https://github.com/anomalyco/gateway/releases).

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
| Per-route rate limiting | Medium | Config skeleton exists (`[[route_rate_limits]]`). Apply different rate limits per request path. |
| HTTP/2 upstream | Low | Config field exists (`tls.http2`). Wire h2 connector in reqwest client. |
| Full SIGHUP state rebuild | Low | Currently reloads config into `RwLock`. Rebuild ip_filter, rate_limiter, bot_detector on SIGHUP. |
| Integration tests | Medium | Spin up test backends and verify full request lifecycle. |


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

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable auth |
| `api_keys` | string[] | `[]` | Static API keys |

## Implementation Notes for Future Contributors

### Per-Route Rate Limiting

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
```

## CI/CD

The project uses GitHub Actions for continuous integration and delivery.

### Workflow

| Stage | Description |
|-------|-------------|
| `check` | Runs `cargo fmt --check` and `cargo clippy` on every push/PR |
| `test` | Runs `cargo test` on Linux, macOS, and Windows |
| `build` | Builds release binaries for all targets (matrix build) |
| `release` | On tag push (`v*`), creates a GitHub Release with compressed binaries |

### Build Targets

| Target | OS | Arch |
|--------|----|------|
| `x86_64-unknown-linux-gnu` | Linux | x86_64 |
| `aarch64-unknown-linux-gnu` | Linux | ARM64 |
| `x86_64-apple-darwin` | macOS | Intel |
| `aarch64-apple-darwin` | macOS | Apple Silicon |
| `x86_64-pc-windows-msvc` | Windows | x86_64 |

### Creating a Release

```bash
# Tag the commit
git tag v0.1.0
git push origin v0.1.0
```

The release workflow automatically:
1. Builds all targets
2. Packages binaries (`.tar.gz` for Linux/macOS, `.zip` for Windows)
3. Creates a GitHub Release with release notes
4. Attaches all archives as assets

## Implementation Notes for Future Contributors

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
