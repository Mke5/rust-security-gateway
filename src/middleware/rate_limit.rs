use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
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

    /// When the last stale-record eviction ran (Unix timestamp in seconds)
    last_cleanup: AtomicU64,

    /// How often to scan for stale records (in seconds)
    cleanup_interval: u64,
}

impl RateLimiter {
    pub fn new(max_requests: u64, window_seconds: u64) -> Self {
        RateLimiter {
            records: Mutex::new(HashMap::new()),
            max_requests,
            window_seconds,
            last_cleanup: AtomicU64::new(current_timestamp()),
            cleanup_interval: window_seconds.max(60),
        }
    }

    /// Evict records whose time window has fully expired.
    /// Called periodically inside `check()` while the records lock is held.
    fn evict_stale(&self, records: &mut HashMap<String, IpRecord>, now: u64) {
        let before = records.len();
        records.retain(|_, r| now - r.window_start < self.window_seconds);
        let evicted = before - records.len();
        if evicted > 0 {
            debug!("Evicted {} stale rate limit records", evicted);
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

        // Periodically evict stale records to prevent unbounded memory growth
        let last = self.last_cleanup.load(Ordering::Relaxed);
        if now - last >= self.cleanup_interval {
            self.evict_stale(&mut records, now);
            self.last_cleanup.store(now, Ordering::Relaxed);
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evict_stale_removes_expired_entries() {
        let limiter = RateLimiter::new(10, 60);
        let mut records: HashMap<String, IpRecord> = HashMap::new();
        let now = current_timestamp();

        // Insert a record that is still within its window
        records.insert(
            "active".to_string(),
            IpRecord {
                count: 3,
                window_start: now - 30, // 30s ago, still within 60s window
            },
        );

        // Insert a record whose window has expired
        records.insert(
            "stale".to_string(),
            IpRecord {
                count: 5,
                window_start: now - 120, // 120s ago, well past 60s window
            },
        );

        assert_eq!(records.len(), 2);
        limiter.evict_stale(&mut records, now);
        assert_eq!(records.len(), 1);
        assert!(records.contains_key("active"));
        assert!(!records.contains_key("stale"));
    }

    #[test]
    fn test_evict_stale_preserves_active_entries() {
        let limiter = RateLimiter::new(10, 60);
        let mut records: HashMap<String, IpRecord> = HashMap::new();
        let now = current_timestamp();

        for i in 0..5 {
            records.insert(
                format!("ip_{}", i),
                IpRecord {
                    count: i,
                    window_start: now - 10, // all within the window
                },
            );
        }

        limiter.evict_stale(&mut records, now);
        assert_eq!(records.len(), 5);
    }

    #[test]
    fn test_evict_stale_empty_map() {
        let limiter = RateLimiter::new(10, 60);
        let mut records: HashMap<String, IpRecord> = HashMap::new();
        let now = current_timestamp();

        limiter.evict_stale(&mut records, now);
        assert!(records.is_empty());
    }

    #[test]
    fn test_check_triggers_cleanup() {
        let limiter = RateLimiter::new(100, 60);
        // Force cleanup interval to be very short
        limiter.last_cleanup.store(0, Ordering::Relaxed);

        // Insert a stale record directly
        let now = current_timestamp();
        {
            let mut records = limiter.records.lock().unwrap();
            records.insert(
                "stale-ip".to_string(),
                IpRecord {
                    count: 1,
                    window_start: now - 120, // expired
                },
            );
        }

        // This check should trigger cleanup due to last_cleanup = 0
        let _ = limiter.check("fresh-ip");
        let records = limiter.records.lock().unwrap();
        // The stale entry should be gone
        assert!(!records.contains_key("stale-ip"));
        // The fresh IP entry should exist
        assert!(records.contains_key("fresh-ip"));
    }
}
