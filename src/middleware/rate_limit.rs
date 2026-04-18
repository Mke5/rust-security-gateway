use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

#[derive(Debug, Clone)]
struct IpRecord {
    /// How many requests this IP has made in the current window
    count: u64,
    /// When the current time window started (Unix timestamp in seconds)
    window_start: u64,
}

/// The Rate Limiter - stores records for all IP addresses
pub struct RateLimiter {
    /// The in-memory store: maps IP → IpRecord
    /// Mutex ensures only one thread touches this at a time (thread safety)
    records: Mutex<HashMap<String, IpRecord>>,

    /// Maximum requests allowed per window
    max_requests: u64,

    /// How long each window lasts (in seconds)
    window_seconds: u64,
}

impl RateLimiter {
    pub fn new(max_requests: u64, window_seconds: u64) -> Self {
        RateLimiter {
            records: Mutex::new(HashMap::new()),
            max_requests,
            window_seconds,
        }
    }

    pub fn check(&self, ip: &str) -> Result<(), Response> {
        // Get the current time as a Unix timestamp (seconds since Jan 1, 1970)
        let now = current_timestamp();

        // Lock the records map so we can safely read/write it
        // (like acquiring a key to a locked room)
        let mut records = self
            .records
            .lock()
            .expect("Rate limiter mutex was poisoned");

        // Get the existing record for this IP, or create a new one
        let record = records.entry(ip.to_string()).or_insert(IpRecord {
            count: 0,
            window_start: now,
        });

        // Has the time window expired?
        // Example: if window is 60 seconds and it's been 65 seconds → reset
        if now - record.window_start >= self.window_seconds {
            // Reset the window: start fresh
            record.count = 0;
            record.window_start = now;
            debug!("Rate limit window reset for IP: {}", ip);
        }

        // Increment the request count for this IP
        record.count += 1;

        debug!(
            "Rate check for {}: {}/{} in current window",
            ip, record.count, self.max_requests
        );

        // Is the count over the limit?
        if record.count > self.max_requests {
            // Calculate when the rate limit resets
            let retry_after = self.window_seconds - (now - record.window_start);

            return Err((
                StatusCode::TOO_MANY_REQUESTS, // HTTP 429
                [
                    ("Retry-After", retry_after.to_string()),
                    ("X-RateLimit-Limit", self.max_requests.to_string()),
                    ("X-RateLimit-Remaining", "0".to_string()),
                    (
                        "X-RateLimit-Reset",
                        (record.window_start + self.window_seconds).to_string(),
                    ),
                ],
                format!(
                    "Rate limit exceeded. You have made {} requests.  ",
                    record.count
                ),
            )
                .into_response());
        }

        Ok(())
    }

    pub fn get_stats(&self, ip: &str) -> Option<(u64, u64)> {
        let records = self
            .records
            .lock()
            .expect("Rate limiter mutex was poisoned");

        records.get(ip).map(|r| (r.count, r.window_start))
    }

    /// Reset the rate limit for a specific IP (admin function)
    pub fn reset(&self, ip: &str) {
        let mut records = self
            .records
            .lock()
            .expect("Rate limiter mutex was poisoned");
        records.remove(ip);
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards - this is a very unusual error!")
        .as_secs()
}
