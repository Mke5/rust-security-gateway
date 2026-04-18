use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

// =============================================================================
// Helper Functions
// =============================================================================

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

// =============================================================================
// Data Structures
// =============================================================================

/// A single entry in the cache
#[derive(Clone)]
struct CacheEntry {
    /// The HTTP status code (e.g., 200, 404)
    status_code: u16,

    /// The response body as bytes
    body: Vec<u8>,

    /// The Content-Type header of the response
    content_type: String,

    /// When this entry was created (Unix timestamp in seconds)
    created_at: u64,

    /// How long this entry is valid for (in seconds)
    ttl: u64,
}

impl CacheEntry {
    // Has this cache entry expired?
    fn is_expired(&self, now: u64) -> bool {
        now > self.created_at + self.ttl
    }
}

/// The main cache store
pub struct ResponseCache {
    /// The actual storage: URL → CacheEntry
    store: Mutex<HashMap<String, CacheEntry>>,

    /// Maximum number of entries to store
    max_items: usize,

    /// Default TTL (time-to-live) in seconds
    ttl_seconds: u64,

    /// How many cache hits (for statistics)
    hits: Mutex<u64>,

    /// How many cache misses (for statistics)
    misses: Mutex<u64>,
}

// =============================================================================
// Implementation
// =============================================================================

impl ResponseCache {
    /// Create a new cache
    ///
    /// # Arguments
    /// * `max_items` - Maximum entries to store (evicts old ones when full)
    /// * `ttl_seconds` - How long each entry lives before expiring
    pub fn new(max_items: usize, ttl_seconds: u64) -> Self {
        ResponseCache {
            store: Mutex::new(HashMap::new()),
            max_items,
            ttl_seconds,
            hits: Mutex::new(0),
            misses: Mutex::new(0),
        }
    }

    /// Try to get a cached response for the given key.
    ///
    /// Returns Some(Response) if cache hit, None if miss or expired.
    pub fn get(&self, key: &str) -> Option<Response> {
        let now = current_timestamp();
        let store = self.store.lock().expect("Cache mutex poisoned");

        if let Some(entry) = store.get(key) {
            // Is the entry still valid?
            if !entry.is_expired(now) {
                debug!("Cache HIT for key: {}", key);

                // Increment hit counter
                if let Ok(mut hits) = self.hits.lock() {
                    *hits += 1;
                }

                // Build the response from the cached data
                let status = StatusCode::from_u16(entry.status_code).unwrap_or(StatusCode::OK);

                let body = entry.body.clone();
                let content_type = entry.content_type.clone();

                // We need to drop the lock before building the response
                drop(store);

                return Some(
                    (
                        status,
                        [
                            ("Content-Type", content_type.as_str()),
                            ("X-Cache", "HIT"),
                            ("X-Cache-Age", "cached"),
                        ],
                        body,
                    )
                        .into_response(),
                );
            } else {
                debug!("Cache EXPIRED for key: {}", key);
            }
        }

        // Cache miss
        if let Ok(mut misses) = self.misses.lock() {
            *misses += 1;
        }

        debug!("Cache MISS for key: {}", key);
        None
    }

    /// Store a response in the cache.
    ///
    /// # Arguments
    /// * `key` - The cache key (URL path + query)
    /// * `status_code` - The HTTP status code
    /// * `body` - The response body bytes
    /// * `content_type` - The Content-Type header value
    pub fn set(&self, key: String, status_code: u16, body: Vec<u8>, content_type: String) {
        let now = current_timestamp();
        let mut store = self.store.lock().expect("Cache mutex poisoned");

        // If we're at max capacity, evict expired entries first
        if store.len() >= self.max_items {
            self.evict_expired_entries(&mut store, now);

            // If still at max capacity after eviction, remove oldest entry
            if store.len() >= self.max_items {
                self.evict_oldest_entry(&mut store);
            }
        }

        // Store the new entry
        store.insert(
            key.clone(),
            CacheEntry {
                status_code,
                body,
                content_type,
                created_at: now,
                ttl: self.ttl_seconds,
            },
        );

        debug!(
            "Cached response for key: {} (total entries: {})",
            key,
            store.len()
        );
    }

    /// Remove all expired entries from the cache.
    /// This is called automatically when we're near capacity.
    fn evict_expired_entries(&self, store: &mut HashMap<String, CacheEntry>, now: u64) {
        let before = store.len();
        store.retain(|_, entry| !entry.is_expired(now));
        let evicted = before - store.len();

        if evicted > 0 {
            debug!("Evicted {} expired cache entries", evicted);
        }
    }

    /// Remove the single oldest entry from the cache.
    /// Used when the cache is full and no entries have expired.
    fn evict_oldest_entry(&self, store: &mut HashMap<String, CacheEntry>) {
        // Find the key with the oldest created_at timestamp
        if let Some(oldest_key) = store
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(key, _)| key.clone())
        {
            store.remove(&oldest_key);
            debug!("Evicted oldest cache entry: {}", oldest_key);
        }
    }

    /// Invalidate (delete) a specific cache entry.
    /// Use this when data changes (e.g., after a POST request updates data).
    pub fn invalidate(&self, key: &str) {
        let mut store = self.store.lock().expect("Cache mutex poisoned");
        store.remove(key);
        debug!("Invalidated cache entry: {}", key);
    }

    /// Clear the entire cache.
    pub fn clear(&self) {
        let mut store = self.store.lock().expect("Cache mutex poisoned");
        store.clear();
        debug!("Cache cleared");
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let store = self.store.lock().expect("Cache mutex poisoned");
        let hits = *self.hits.lock().expect("Hits mutex poisoned");
        let misses = *self.misses.lock().expect("Misses mutex poisoned");

        CacheStats {
            entries: store.len(),
            hits,
            misses,
            hit_rate: if hits + misses > 0 {
                (hits as f64) / ((hits + misses) as f64) * 100.0
            } else {
                0.0
            },
        }
    }
}

/// Cache statistics for monitoring
#[derive(Debug)]
pub struct CacheStats {
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64, // Percentage
}
