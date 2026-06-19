use prometheus::{Counter, CounterVec, HistogramOpts, HistogramVec, Opts, Registry, TextEncoder};

pub struct Metrics {
    registry: Registry,
    pub http_requests_total: CounterVec,
    pub http_request_duration_seconds: HistogramVec,
    pub cache_hits_total: Counter,
    pub cache_misses_total: Counter,
    pub rate_limit_hits_total: Counter,
}

impl Metrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let http_requests_total = CounterVec::new(
            Opts::new("http_requests_total", "Total number of HTTP requests"),
            &["method", "status"],
        )?;
        registry.register(Box::new(http_requests_total.clone()))?;

        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["method"],
        )?;
        registry.register(Box::new(http_request_duration_seconds.clone()))?;

        let cache_hits_total = Counter::new("cache_hits_total", "Total number of cache hits")?;
        registry.register(Box::new(cache_hits_total.clone()))?;

        let cache_misses_total =
            Counter::new("cache_misses_total", "Total number of cache misses")?;
        registry.register(Box::new(cache_misses_total.clone()))?;

        let rate_limit_hits_total = Counter::new(
            "rate_limit_hits_total",
            "Total number of rate-limited requests",
        )?;
        registry.register(Box::new(rate_limit_hits_total.clone()))?;

        Ok(Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            cache_hits_total,
            cache_misses_total,
            rate_limit_hits_total,
        })
    }

    pub fn encode(&self) -> Result<String, prometheus::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = String::new();
        encoder.encode_utf8(&metric_families, &mut buffer)?;
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_new() {
        let metrics = Metrics::new().unwrap();
        // Observe at least one value so metrics appear in output
        metrics
            .http_requests_total
            .with_label_values(&["GET", "200"])
            .inc();
        metrics
            .http_request_duration_seconds
            .with_label_values(&["GET"])
            .observe(0.1);
        metrics.cache_hits_total.inc();
        metrics.cache_misses_total.inc();
        metrics.rate_limit_hits_total.inc();

        let output = metrics.encode().unwrap();
        assert!(output.contains("http_requests_total"), "output: {}", output);
        assert!(
            output.contains("http_request_duration_seconds"),
            "output: {}",
            output
        );
        assert!(output.contains("cache_hits_total"), "output: {}", output);
        assert!(output.contains("cache_misses_total"), "output: {}", output);
        assert!(
            output.contains("rate_limit_hits_total"),
            "output: {}",
            output
        );
    }

    #[test]
    fn test_metrics_increment() {
        let metrics = Metrics::new().unwrap();
        metrics
            .http_requests_total
            .with_label_values(&["GET", "200"])
            .inc();
        metrics.rate_limit_hits_total.inc();

        let output = metrics.encode().unwrap();
        assert!(output.contains(r#"http_requests_total{method="GET",status="200"} 1"#));
        assert!(output.contains("rate_limit_hits_total 1"));
    }

    #[test]
    fn test_metrics_duration() {
        let metrics = Metrics::new().unwrap();
        metrics
            .http_request_duration_seconds
            .with_label_values(&["POST"])
            .observe(0.042);

        let output = metrics.encode().unwrap();
        assert!(
            output.contains(r#"http_request_duration_seconds_bucket{method="POST",le="0.05"} 1"#)
        );
    }

    #[test]
    fn test_metrics_cache_counters() {
        let metrics = Metrics::new().unwrap();
        metrics.cache_hits_total.inc_by(3.0);
        metrics.cache_misses_total.inc_by(5.0);

        let output = metrics.encode().unwrap();
        assert!(output.contains("cache_hits_total 3"));
        assert!(output.contains("cache_misses_total 5"));
    }
}
