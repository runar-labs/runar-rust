// Node Discovery Interface
//
// INTENTION: Define interfaces for node discovery mechanisms. Discovery is responsible
// for finding and announcing node presence on the network, but NOT maintaining
// a registry of nodes or managing connections.

use anyhow::Result;
use async_trait::async_trait;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

pub mod multicast_discovery;

pub use multicast_discovery::{MulticastDiscovery, PeerInfo};

/// Configuration options for node discovery
#[derive(Clone, Debug)]
pub struct DiscoveryOptions {
    /// How often to announce this node's presence (in seconds)
    pub announce_interval: Duration,
    /// Timeout for discovery operations (in seconds)
    pub discovery_timeout: Duration,
    /// Per-peer debounce window to coalesce bursty events
    pub debounce_window: Duration,
    /// Whether to use multicast for discovery (if supported)
    pub use_multicast: bool,
    /// Whether to limit discovery to the local network
    pub local_network_only: bool,
    /// The multicast group address (e.g., "239.255.42.98")
    pub multicast_group: String,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            announce_interval: Duration::from_secs(5),
            discovery_timeout: Duration::from_secs(10),
            debounce_window: Duration::from_millis(400),
            use_multicast: true,
            local_network_only: true,
            multicast_group: DEFAULT_MULTICAST_ADDR.to_string(),
        }
    }
}

// Make the constant public
pub const DEFAULT_MULTICAST_ADDR: &str = "239.255.42.98";

/// Discovery events emitted by providers. Providers are event sources; Node decides behavior.
#[derive(Clone, Debug)]
pub enum DiscoveryEvent {
    Discovered(PeerInfo),
    Updated(PeerInfo),
    Lost(String), // peer_id
}

/// Callback function type for discovery events (async)
pub type DiscoveryListener =
    Arc<dyn Fn(DiscoveryEvent) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Interface for node discovery mechanisms
#[async_trait]
pub trait NodeDiscovery: Send + Sync {
    /// Initialize the discovery mechanism with the given options
    async fn init(&self, options: DiscoveryOptions) -> Result<()>;

    /// Start announcing this node's presence on the network
    async fn start_announcing(&self) -> Result<()>;

    /// Stop announcing this node's presence
    async fn stop_announcing(&self) -> Result<()>;

    /// Subscribe a listener for discovery events
    async fn subscribe(&self, listener: DiscoveryListener) -> Result<()>;

    /// Shutdown the discovery mechanism
    async fn shutdown(&self) -> Result<()>;

    /// Update the local peer information (called when node capabilities change)
    async fn update_local_peer_info(&self, new_peer_info: PeerInfo) -> Result<()>;

    // Stateless providers do not maintain authoritative peer caches.
}
