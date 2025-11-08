// Numan Thabit 2025
// metrics.rs - Prometheus and tracing
use prometheus::{Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Registry};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("prometheus error: {0}")]
    Prometheus(#[from] prometheus::Error),
}

#[derive(Debug, Clone)]
pub struct Metrics {
    registry: Registry,
    pub tx_late_drop_rate: Histogram,
    pub guard_delta_ns: IntGauge,
    pub software_pacing_overruns: IntCounter,
    pub ecn_ce_ratio: Histogram,
    pub credit_scale: Histogram,
    pub pmtu_current: IntGauge,
    pub pmtu_probe_success: IntCounter,
    pub pmtu_probe_fail: IntCounter,
    pub aead_failures: IntCounter,
    pub hdr_mac_failures: IntCounter,
    pub retry_cookie_sent: IntCounter,
    pub retry_cookie_ok: IntCounter,
    pub ack_bytes_total: IntCounter,
    pub nack_count: IntCounter,
    pub repair_attempts: IntCounterVec,
    pub repair_success: IntCounter,
    pub repair_fail: IntCounter,
    pub dup_filter_hits: IntCounter,
    pub burst_clamps: IntCounter,
    pub floor_hits_p2: IntCounter,
    pub queue_depth_p0: IntGauge,
    pub queue_depth_p1: IntGauge,
    pub queue_depth_p2: IntGauge,
    pub queue_depth_p3: IntGauge,
}

impl Metrics {
    pub fn new() -> Result<Self, MetricsError> {
        let registry = Registry::new_custom(Some("numiport".into()), None)?;

        macro_rules! register_counter {
            ($name:expr, $help:expr) => {{
                let counter = IntCounter::new($name, $help)?;
                registry.register(Box::new(counter.clone()))?;
                counter
            }};
        }

        macro_rules! register_counter_vec {
            ($name:expr, $help:expr, $labels:expr) => {{
                let counter = IntCounterVec::new(prometheus::Opts::new($name, $help), $labels)?;
                registry.register(Box::new(counter.clone()))?;
                counter
            }};
        }

        macro_rules! register_gauge {
            ($name:expr, $help:expr) => {{
                let gauge = IntGauge::new($name, $help)?;
                registry.register(Box::new(gauge.clone()))?;
                gauge
            }};
        }

        macro_rules! register_histogram {
            ($name:expr, $help:expr, $buckets:expr) => {{
                let opts = HistogramOpts::new($name, $help).buckets($buckets.to_vec());
                let hist = Histogram::with_opts(opts)?;
                registry.register(Box::new(hist.clone()))?;
                hist
            }};
        }

        let tx_late_drop_rate = register_histogram!(
            "tx_late_drop_rate",
            "ETF late drop rate measurements",
            &[0.0, 0.001, 0.01, 0.05, 0.1, 0.2]
        );
        let guard_delta_ns =
            register_gauge!("guard_delta_ns", "Current guard delta in nanoseconds");
        let software_pacing_overruns = register_counter!(
            "software_pacing_overruns",
            "Count of software pacer deadline overruns"
        );
        let ecn_ce_ratio = register_histogram!(
            "ecn_ce_ratio",
            "Observed ECN CE ratios per slot",
            &[0.0, 0.01, 0.05, 0.1, 0.2, 0.4]
        );
        let credit_scale = register_histogram!(
            "credit_scale",
            "Applied credit scale factors",
            &[0.3, 0.5, 0.7, 0.85, 1.0, 1.1, 1.2]
        );
        let pmtu_current = register_gauge!("pmtu_current", "Current negotiated PMTU per peer");
        let pmtu_probe_success =
            register_counter!("pmtu_probe_success", "Successful PMTU probe count");
        let pmtu_probe_fail = register_counter!("pmtu_probe_fail", "Failed PMTU probe count");
        let aead_failures = register_counter!("aead_failures", "AEAD authentication failures");
        let hdr_mac_failures =
            register_counter!("hdr_mac_failures", "Header MAC verification failures");
        let retry_cookie_sent = register_counter!("retry_cookie_sent", "Retry cookies issued");
        let retry_cookie_ok = register_counter!("retry_cookie_ok", "Retry cookie validations");
        let ack_bytes_total =
            register_counter!("ack_bytes_total", "Total acknowledged payload bytes");
        let nack_count = register_counter!("nack_count", "Number of NACKs processed");
        let repair_attempts = register_counter_vec!(
            "repair_attempts_total",
            "Repair attempts issued per slot",
            &["slot"]
        );
        let repair_success =
            register_counter!("repair_success_total", "Successful repair deliveries");
        let repair_fail = register_counter!("repair_fail_total", "Failed repair deliveries");
        let dup_filter_hits = register_counter!("dup_filter_hits", "Replay filter hits");
        let burst_clamps = register_counter!("burst_clamps", "Burst clamp activations");
        let floor_hits_p2 = register_counter!("floor_hits_p2", "Times the P2 floor was enforced");
        let queue_depth_p0 = register_gauge!("queue_depth_p0", "Queue depth for class P0");
        let queue_depth_p1 = register_gauge!("queue_depth_p1", "Queue depth for class P1");
        let queue_depth_p2 = register_gauge!("queue_depth_p2", "Queue depth for class P2");
        let queue_depth_p3 = register_gauge!("queue_depth_p3", "Queue depth for class P3");

        Ok(Self {
            registry,
            tx_late_drop_rate,
            guard_delta_ns,
            software_pacing_overruns,
            ecn_ce_ratio,
            credit_scale,
            pmtu_current,
            pmtu_probe_success,
            pmtu_probe_fail,
            aead_failures,
            hdr_mac_failures,
            retry_cookie_sent,
            retry_cookie_ok,
            ack_bytes_total,
            nack_count,
            repair_attempts,
            repair_success,
            repair_fail,
            dup_filter_hits,
            burst_clamps,
            floor_hits_p2,
            queue_depth_p0,
            queue_depth_p1,
            queue_depth_p2,
            queue_depth_p3,
        })
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.registry.gather()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_metrics_registry() {
        let metrics = Metrics::new().expect("metrics");
        metrics.guard_delta_ns.set(500_000);
        metrics.aead_failures.inc();
        metrics.repair_attempts.with_label_values(&["0"]).inc();
        metrics.repair_success.inc();
        assert!(!metrics.gather().is_empty());
    }
}
