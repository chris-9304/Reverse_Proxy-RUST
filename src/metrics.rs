use prometheus::{Encoder, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder};
use std::sync::Arc;

pub struct Metrics {
    registry: Registry,
    http_requests_total: IntCounterVec,
    http_request_duration_seconds: HistogramVec,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        let registry = Registry::new();

        let http_requests_total = IntCounterVec::new(
            Opts::new("http_requests_total", "Total number of HTTP requests"),
            &["status", "method", "path"],
        )
        .expect("metric can be created");

        let http_request_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
            &["status", "method", "path"],
        )
        .expect("metric can be created");

        registry
            .register(Box::new(http_requests_total.clone()))
            .expect("collector can be registered");
        registry
            .register(Box::new(http_request_duration_seconds.clone()))
            .expect("collector can be registered");

        Arc::new(Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
        })
    }

    /// Encode metrics in Prometheus text format. Fails only on encoder or UTF-8 error (should not happen in practice).
    pub fn encode(&self) -> Result<String, prometheus::Error> {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode(&metric_families, &mut buffer)?;
        String::from_utf8(buffer)
            .map_err(|e| prometheus::Error::Msg(format!("metrics UTF-8: {}", e)))
    }

    pub fn record_request(&self, status: u16, method: &str, path: &str, duration_secs: f64) {
        let status_str = status.to_string();
        self.http_requests_total
            .with_label_values(&[&status_str, method, path])
            .inc();
        self.http_request_duration_seconds
            .with_label_values(&[&status_str, method, path])
            .observe(duration_secs);
    }
}
