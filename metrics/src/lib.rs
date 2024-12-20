use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::OnceLock;

use axum::routing::get;
use axum::Router;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use sysinfo::System;

pub struct AppMetrics {
    registry: Registry,
    pub memory_usage: Gauge<f64, AtomicU64>,
    pub block_height: Gauge,
}

impl AppMetrics {
    pub fn new() -> Self {
        let mut registry = <Registry>::default();
        let memory_usage = Gauge::<f64, AtomicU64>::default();
        let block_height = Gauge::default();

        registry.register("block_height", "Current block height", block_height.clone());
        registry.register(
            "memory_usage_gigabytes",
            "System memory usage in GB",
            memory_usage.clone(),
        );

        Self {
            registry,
            block_height,
            memory_usage,
        }
    }

    /// Gets how much memory is being used by the system in which Floresta is
    /// running on, not how much memory Floresta itself it's using.
    pub fn update_memory_usage(&self) {
        let mut system = System::new_all();
        system.refresh_memory();

        // get used memory in gigabytes                / KB    / MB    / GB
        let used_memory = system.used_memory() as f64 / 1024. / 1024. / 1024.;
        self.memory_usage.set(used_memory);
    }
}

impl Default for AppMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// Singleton to share metrics across crates
static METRICS: OnceLock<AppMetrics> = OnceLock::new();
pub fn get_metrics() -> &'static AppMetrics {
    METRICS.get_or_init(AppMetrics::new)
}

async fn metrics_handler() -> String {
    let mut buffer = String::new();
    encode(&mut buffer, &get_metrics().registry).unwrap();

    buffer
}

pub async fn metrics_server(metrics_server_address: SocketAddr) {
    let app = Router::new().route("/", get(metrics_handler));
    let listener = tokio::net::TcpListener::bind(metrics_server_address)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
