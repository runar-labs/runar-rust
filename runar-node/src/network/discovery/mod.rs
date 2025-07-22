// Node Discovery Interface
//
// INTENTION: Define interfaces for node discovery mechanisms. Discovery is responsible
// for finding and announcing node presence on the network, but NOT maintaining
// a registry of nodes or managing connections.

use anyhow::Result;
use async_trait::async_trait;
use multicast_discovery::PeerInfo;

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

use runar_schemas::ServiceMetadata;

pub mod memory_discovery;
pub mod mock;
pub mod multicast_discovery;

pub use memory_discovery::MemoryDiscovery;
pub use mock::MockNodeDiscovery;
pub use multicast_discovery::MulticastDiscovery;

/// Configuration options for node discovery
#[derive(Clone, Debug)]
pub struct DiscoveryOptions {
    /// How often to announce this node's presence (in seconds)
    pub announce_interval: Duration,
    /// Timeout for discovery operations (in seconds)
    pub discovery_timeout: Duration,
    /// Time-to-live for discovered nodes (in seconds)
    pub node_ttl: Duration,
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
            announce_interval: Duration::from_secs(60),
            discovery_timeout: Duration::from_secs(10),
            node_ttl: Duration::from_secs(300),
            use_multicast: true,
            local_network_only: true,
            multicast_group: DEFAULT_MULTICAST_ADDR.to_string(),
        }
    }
}

// Make the constant public
pub const DEFAULT_MULTICAST_ADDR: &str = "239.255.42.98";

/// Information about a node in the network
///
/// INTENTION: Represents a snapshot of a node's presence and capabilities
/// within one or more networks. This information is shared via discovery mechanisms.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NodeInfo {
    /// The node's unique identifier
    pub node_public_key: Vec<u8>,
    /// The list of network IDs this node participates in and handles traffic for.
    /// A node can be part of multiple networks simultaneously.
    pub network_ids: Vec<String>,
    /// The node's  network addressess (e.g., "IP:PORT") - ordered by preference
    pub addresses: Vec<String>,
    /// Node services representing the services provided by this node
    pub services: Vec<ServiceMetadata>,
    /// incremental version counter that change everytime the ndoe chagnes (new services added, new event subscriptions, etc)
    /// //when taht happens a new version is published to known peers.. and that is how peers know if  they need to update their own version of it
    pub version: i64,
}

/// Callback function type for discovery events
use std::future::Future;
use std::pin::Pin;

/// Callback function type for discovery events (async)
pub type DiscoveryListener =
    Arc<dyn Fn(PeerInfo) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Interface for node discovery mechanisms
#[async_trait]
pub trait NodeDiscovery: Send + Sync {
    /// Initialize the discovery mechanism with the given options
    async fn init(&self, options: DiscoveryOptions) -> Result<()>;

    /// Start announcing this node's presence on the network
    async fn start_announcing(&self) -> Result<()>;

    /// Stop announcing this node's presence
    async fn stop_announcing(&self) -> Result<()>;

    /// Set a listener to be called when nodes are discovered or updated (async)
    async fn set_discovery_listener(&self, listener: DiscoveryListener) -> Result<()>;

    /// Shutdown the discovery mechanism
    async fn shutdown(&self) -> Result<()>;
}
