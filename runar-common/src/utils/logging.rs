use lazy_static::lazy_static;
use log::{debug, error, info, trace, warn};
use std::sync::Arc;
use tokio::sync::RwLock;

lazy_static! {
    static ref NODE_ID: Arc<RwLock<String>> = Arc::new(RwLock::new("NONE".to_string()));
}

#[derive(Debug, Clone, Copy)]
pub enum Component {
    Node,
    Service,
    P2P,
    Registry,
    Test,
    ServiceRegistry,
    IPC,
}

impl Component {
    pub fn as_str(&self) -> &'static str {
        match self {
            Component::Node => "Node",
            Component::Service => "Service",
            Component::P2P => "P2P",
            Component::Registry => "Registry",
            Component::Test => "Test",
            Component::ServiceRegistry => "ServiceRegistry",
            Component::IPC => "IPC",
        }
    }
}

/// Set the node ID for logging
pub async fn set_node_id(node_id: &str) {
    let mut current_node_id = NODE_ID.write().await;
    *current_node_id = node_id.to_string();
}

// Log trace level message with component
pub async fn trace_log(component: Component, message: &str) {
    let node_id = NODE_ID.read().await;
    trace!("[{}][{}] {}", *node_id, component.as_str(), message);
}

// Log debug level message with component
pub async fn debug_log(component: Component, message: &str) {
    let node_id = NODE_ID.read().await;
    debug!("[{}][{}] {}", *node_id, component.as_str(), message);
}

// Log info level message with component
pub async fn info_log(component: Component, message: &str) {
    let node_id = NODE_ID.read().await;
    info!("[{}][{}] {}", *node_id, component.as_str(), message);
}

// Log warning level message with component
pub async fn warn_log(component: Component, message: &str) {
    let node_id = NODE_ID.read().await;
    warn!("[{}][{}] {}", *node_id, component.as_str(), message);
}

// Log error level message with component
pub async fn error_log(component: Component, message: &str) {
    let node_id = NODE_ID.read().await;
    error!("[{}][{}] {}", *node_id, component.as_str(), message);
}

// Log debug message with component and data structure
pub fn debug_log_with_data<T: std::fmt::Debug>(component: Component, message: &str, data: &T) {
    debug!("[{}] {}: {:?}", component.as_str(), message, data);
}

// Initialize logging with component filters
pub fn init_logging() {
    // Set up env_logger with custom format
    let env = env_logger::Env::default()
        .filter_or("RUST_LOG", "debug") // Default to debug level
        .filter_or("RUNAR_LOG", "debug"); // Allow override with RUNAR_LOG

    env_logger::Builder::from_env(env)
        .format(|buf, record| {
            use std::io::Write;
            let level_style = buf.default_level_style(record.level());
            writeln!(
                buf,
                "{} {} [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                level_style.value(record.level()),
                record.target(),
                record.args()
            )
        })
        .init();
}

// Get test-specific filter - this is useful for enabling specific components during tests
pub fn get_test_filter() -> String {
    std::env::var("RUNAR_TEST_LOG").unwrap_or_else(|_| "debug".to_string())
}

// Configure logging for tests
pub fn configure_test_logging() {
    let filter = get_test_filter();
    let env = env_logger::Env::default().filter_or("RUST_LOG", filter);

    env_logger::Builder::from_env(env)
        .format(|buf, record| {
            use std::io::Write;
            let level_style = buf.default_level_style(record.level());
            writeln!(
                buf,
                "{} {} [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                level_style.value(record.level()),
                record.target(),
                record.args()
            )
        })
        .is_test(true)
        .init();
}
