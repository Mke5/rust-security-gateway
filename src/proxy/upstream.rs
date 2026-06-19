use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq)]
enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
struct CircuitBreakerInner {
    state: CircuitState,
    failure_count: u32,
    last_failure_time: Option<Instant>,
    failure_threshold: u32,
    recovery_timeout: Duration,
}

impl CircuitBreakerInner {
    fn new(failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            last_failure_time: None,
            failure_threshold,
            recovery_timeout,
        }
    }

    fn is_available(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if let Some(time) = self.last_failure_time {
                    if time.elapsed() >= self.recovery_timeout {
                        self.state = CircuitState::HalfOpen;
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => true,
        }
    }

    fn record_success(&mut self) {
        self.failure_count = 0;
        self.state = CircuitState::Closed;
        self.last_failure_time = None;
    }

    fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(Instant::now());
        if self.failure_count >= self.failure_threshold {
            self.state = CircuitState::Open;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LoadBalancer {
    RoundRobin,
    LeastConnections,
}

#[derive(Debug)]
pub struct Upstream {
    pub url: String,
    inner: Mutex<CircuitBreakerInner>,
    active_connections: AtomicU64,
}

impl Upstream {
    pub fn new(url: String, failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            url,
            inner: Mutex::new(CircuitBreakerInner::new(
                failure_threshold,
                recovery_timeout,
            )),
            active_connections: AtomicU64::new(0),
        }
    }

    pub fn is_available(&self) -> bool {
        self.inner.lock().unwrap().is_available()
    }

    pub fn record_success(&self) {
        self.inner.lock().unwrap().record_success();
    }

    pub fn record_failure(&self) {
        self.inner.lock().unwrap().record_failure();
    }

    pub fn acquire(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn release(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay: Duration,
}

impl RetryPolicy {
    pub fn new(max_retries: u32, base_delay_ms: u64) -> Self {
        Self {
            max_retries,
            base_delay: Duration::from_millis(base_delay_ms),
        }
    }

    pub fn delay(&self, attempt: u32) -> Duration {
        let exp = 2u64.pow(attempt);
        self.base_delay.mul_f64(exp as f64)
    }
}

#[derive(Debug)]
pub struct UpstreamPool {
    upstreams: Vec<Arc<Upstream>>,
    counter: AtomicUsize,
    retry: RetryPolicy,
    load_balancer: LoadBalancer,
}

impl UpstreamPool {
    pub fn new(
        urls: Vec<String>,
        retry: RetryPolicy,
        failure_threshold: u32,
        recovery_timeout: Duration,
        load_balancer: LoadBalancer,
    ) -> Self {
        let upstreams = urls
            .into_iter()
            .map(|url| Arc::new(Upstream::new(url, failure_threshold, recovery_timeout)))
            .collect();

        Self {
            upstreams,
            counter: AtomicUsize::new(0),
            retry,
            load_balancer,
        }
    }

    pub fn from_url(
        url: String,
        retry: RetryPolicy,
        failure_threshold: u32,
        recovery_timeout: Duration,
    ) -> Self {
        Self::new(
            vec![url],
            retry,
            failure_threshold,
            recovery_timeout,
            LoadBalancer::RoundRobin,
        )
    }

    pub fn pick(&self) -> Option<Arc<Upstream>> {
        if self.upstreams.is_empty() {
            return None;
        }
        match self.load_balancer {
            LoadBalancer::RoundRobin => self.pick_round_robin(),
            LoadBalancer::LeastConnections => self.pick_least_connections(),
        }
    }

    fn pick_round_robin(&self) -> Option<Arc<Upstream>> {
        let len = self.upstreams.len();
        for _ in 0..len {
            let idx = self.counter.fetch_add(1, Ordering::Relaxed) % len;
            let upstream = self.upstreams[idx].clone();
            if upstream.is_available() {
                return Some(upstream);
            }
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % len;
        Some(self.upstreams[idx].clone())
    }

    fn pick_least_connections(&self) -> Option<Arc<Upstream>> {
        let mut best: Option<&Arc<Upstream>> = None;
        let mut best_connections = u64::MAX;
        for upstream in &self.upstreams {
            if upstream.is_available() {
                let conns = upstream.active_connections();
                if conns < best_connections {
                    best_connections = conns;
                    best = Some(upstream);
                }
            }
        }
        best.cloned().or_else(|| {
            // All circuits open — fall back to first upstream
            self.upstreams.first().cloned()
        })
    }

    pub fn retry_policy(&self) -> &RetryPolicy {
        &self.retry
    }

    pub fn is_empty(&self) -> bool {
        self.upstreams.is_empty()
    }

    pub fn upstreams(&self) -> &[Arc<Upstream>] {
        &self.upstreams
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_policy_delay() {
        let policy = RetryPolicy::new(3, 50);
        assert_eq!(policy.delay(0), Duration::from_millis(50));
        assert_eq!(policy.delay(1), Duration::from_millis(100));
        assert_eq!(policy.delay(2), Duration::from_millis(200));
    }

    #[test]
    fn test_circuit_breaker_initial_closed() {
        let upstream = Upstream::new("http://test:8080".into(), 3, Duration::from_secs(10));
        assert!(upstream.is_available());
    }

    #[test]
    fn test_circuit_breaker_opens_after_threshold() {
        let upstream = Upstream::new("http://test:8080".into(), 3, Duration::from_secs(10));
        assert!(upstream.is_available());
        upstream.record_failure();
        assert!(upstream.is_available());
        upstream.record_failure();
        assert!(upstream.is_available());
        upstream.record_failure();
        assert!(!upstream.is_available());
    }

    #[test]
    fn test_circuit_breaker_recovers() {
        let upstream = Upstream::new("http://test:8080".into(), 2, Duration::from_millis(50));
        upstream.record_failure();
        assert!(upstream.is_available());
        upstream.record_failure();
        assert!(!upstream.is_available());
        std::thread::sleep(Duration::from_millis(60));
        assert!(upstream.is_available());
    }

    #[test]
    fn test_circuit_breaker_success_resets() {
        let upstream = Upstream::new("http://test:8080".into(), 3, Duration::from_secs(10));
        upstream.record_failure();
        upstream.record_failure();
        upstream.record_success();
        assert!(upstream.is_available());
        upstream.record_failure();
        assert!(upstream.is_available());
        upstream.record_failure();
        assert!(upstream.is_available());
        upstream.record_failure();
        assert!(!upstream.is_available());
    }

    #[test]
    fn test_upstream_pool_pick() {
        let pool = UpstreamPool::new(
            vec!["http://a:8080".into(), "http://b:8080".into()],
            RetryPolicy::new(2, 100),
            5,
            Duration::from_secs(30),
            LoadBalancer::RoundRobin,
        );
        let picked = pool.pick().unwrap();
        assert!(picked.url == "http://a:8080" || picked.url == "http://b:8080");
    }

    #[test]
    fn test_upstream_pool_empty() {
        let pool = UpstreamPool::new(
            vec![],
            RetryPolicy::new(2, 100),
            5,
            Duration::from_secs(30),
            LoadBalancer::RoundRobin,
        );
        assert!(pool.is_empty());
        assert!(pool.pick().is_none());
    }

    #[test]
    fn test_upstream_pool_skips_open() {
        let pool = UpstreamPool::new(
            vec!["http://bad:8080".into(), "http://good:8080".into()],
            RetryPolicy::new(2, 100),
            1,
            Duration::from_secs(60),
            LoadBalancer::RoundRobin,
        );
        let bad = pool.pick().unwrap();
        bad.record_failure();
        assert!(!bad.is_available());
        let picked = pool.pick().unwrap();
        assert_eq!(picked.url, "http://good:8080");
    }
}
