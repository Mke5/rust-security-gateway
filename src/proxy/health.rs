use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use tokio::time::interval;
use tracing::{debug, info, warn};

use super::upstream::UpstreamPool;

pub struct HealthChecker {
    pool: Arc<UpstreamPool>,
    client: Client,
    interval: Duration,
    timeout: Duration,
    path: String,
}

impl HealthChecker {
    pub fn new(
        pool: Arc<UpstreamPool>,
        client: Client,
        interval_secs: u64,
        timeout_secs: u64,
        path: String,
    ) -> Self {
        Self {
            pool,
            client,
            interval: Duration::from_secs(interval_secs),
            timeout: Duration::from_secs(timeout_secs),
            path,
        }
    }

    pub async fn run(&self) {
        info!(
            "Health checker started (interval: {:?}, timeout: {:?}, path: {})",
            self.interval, self.timeout, self.path
        );
        let mut ticker = interval(self.interval);
        loop {
            ticker.tick().await;
            self.check_all().await;
        }
    }

    async fn check_all(&self) {
        for upstream in self.pool.upstreams() {
            let url = format!("{}{}", upstream.url.trim_end_matches('/'), self.path);
            debug!("Health check: GET {}", url);

            let result = tokio::time::timeout(self.timeout, self.client.get(&url).send()).await;

            match result {
                Ok(Ok(resp)) if resp.status().is_success() => {
                    upstream.record_success();
                    debug!("Health check OK: {}", url);
                }
                Ok(Ok(resp)) => {
                    warn!(
                        "Health check FAIL (status {}): {}",
                        resp.status().as_u16(),
                        url
                    );
                    upstream.record_failure();
                }
                Ok(Err(e)) => {
                    warn!("Health check ERROR: {} - {}", url, e);
                    upstream.record_failure();
                }
                Err(_) => {
                    warn!(
                        "Health check TIMEOUT ({}s): {}",
                        self.timeout.as_secs(),
                        url
                    );
                    upstream.record_failure();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::upstream::{LoadBalancer, RetryPolicy};

    #[tokio::test]
    async fn test_health_checker_record_failure_on_bad_host() {
        let pool = Arc::new(UpstreamPool::new(
            vec!["http://127.0.0.1:1".into()],
            RetryPolicy::new(2, 100),
            1,
            Duration::from_secs(1),
            LoadBalancer::RoundRobin,
        ));

        let client = Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();

        let checker = HealthChecker::new(pool.clone(), client, 1, 1, "/health".to_string());

        checker.check_all().await;

        let upstream = &pool.upstreams()[0];
        assert!(!upstream.is_available());
    }

    #[tokio::test]
    async fn test_health_checker_with_unreachable_upstream() {
        let pool = Arc::new(UpstreamPool::new(
            vec!["http://192.0.2.1:9".into()],
            RetryPolicy::new(2, 100),
            2,
            Duration::from_secs(10),
            LoadBalancer::RoundRobin,
        ));

        let client = Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();

        let checker = HealthChecker::new(pool.clone(), client, 1, 1, "/health".to_string());

        checker.check_all().await;

        let upstream = &pool.upstreams()[0];
        // Should have one failure (not yet at threshold of 2)
        assert!(upstream.is_available());

        checker.check_all().await;

        // Two failures should open the circuit
        assert!(!upstream.is_available());
    }

    #[tokio::test]
    async fn test_health_checker_upstreams_empty() {
        let pool = Arc::new(UpstreamPool::new(
            vec![],
            RetryPolicy::new(2, 100),
            5,
            Duration::from_secs(30),
            LoadBalancer::RoundRobin,
        ));

        let client = Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();

        let checker = HealthChecker::new(pool.clone(), client, 1, 1, "/health".to_string());

        // Should not panic on empty pool
        checker.check_all().await;
    }

    #[test]
    fn test_health_check_path_construction() {
        let pool = Arc::new(UpstreamPool::new(
            vec!["http://backend:8080".into()],
            RetryPolicy::new(2, 100),
            5,
            Duration::from_secs(30),
            LoadBalancer::RoundRobin,
        ));
        let client = Client::builder().build().unwrap();
        let checker = HealthChecker::new(pool.clone(), client, 10, 5, "/api/health".to_string());

        let expected = format!("{}{}", "http://backend:8080", "/api/health");
        assert_eq!(
            expected,
            format!(
                "{}{}",
                pool.upstreams()[0].url.trim_end_matches('/'),
                "/api/health"
            )
        );
        // Verify checker's path is stored correctly
        assert_eq!(checker.path, "/api/health");
    }
}
