use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Default)]
pub struct RegistryMetrics(Arc<Inner>);

#[derive(Default)]
struct Inner {
    requests: AtomicU64,
    stages: AtomicU64,
    downloads: AtomicU64,
    denied: AtomicU64,
    errors: AtomicU64,
}

impl RegistryMetrics {
    pub fn request(&self) {
        self.0.requests.fetch_add(1, Ordering::Relaxed);
    }
    pub fn stage(&self) {
        self.0.stages.fetch_add(1, Ordering::Relaxed);
    }
    pub fn download(&self) {
        self.0.downloads.fetch_add(1, Ordering::Relaxed);
    }
    pub fn denied(&self) {
        self.0.denied.fetch_add(1, Ordering::Relaxed);
    }
    pub fn error(&self) {
        self.0.errors.fetch_add(1, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"requests":self.0.requests.load(Ordering::Relaxed),"stages":self.0.stages.load(Ordering::Relaxed),"downloads":self.0.downloads.load(Ordering::Relaxed),"denied":self.0.denied.load(Ordering::Relaxed),"errors":self.0.errors.load(Ordering::Relaxed)})
    }
    pub fn prometheus(&self) -> String {
        let s = self.snapshot();
        format!(
            "# TYPE oath_registry_requests_total counter\noath_registry_requests_total {}\n# TYPE oath_registry_stages_total counter\noath_registry_stages_total {}\n# TYPE oath_registry_downloads_total counter\noath_registry_downloads_total {}\n# TYPE oath_registry_denied_total counter\noath_registry_denied_total {}\n# TYPE oath_registry_errors_total counter\noath_registry_errors_total {}\n",
            s["requests"], s["stages"], s["downloads"], s["denied"], s["errors"]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counters_are_machine_readable() {
        let metrics = RegistryMetrics::default();
        metrics.request();
        metrics.stage();
        assert_eq!(metrics.snapshot()["requests"], 1);
        assert!(
            metrics
                .prometheus()
                .contains("oath_registry_stages_total 1")
        );
    }
}
