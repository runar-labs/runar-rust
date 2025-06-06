// Network Transport Module
use anyhow::Result;
use async_trait::async_trait;
use rand;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

// Internal module declarations
pub mod cert_utils;
pub mod connection_pool;
pub mod peer_registry;
pub mod peer_state;
pub mod quic_transport;
pub mod stream_pool;

pub use cert_utils::generate_self_signed_cert;
pub use connection_pool::ConnectionPool;
pub use peer_state::PeerState;
pub use stream_pool::StreamPool;

// --- Moved from quic_transport.rs ---
/// Custom certificate verifier that skips verification for testing
///
/// INTENTION: Allow connections without certificate verification in test environments
pub struct SkipServerVerification {}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}


// Removed WebSocket module completely

// Re-export types/traits from submodules or parent modules
pub use peer_registry::{PeerEntry, PeerRegistry, PeerRegistryOptions, PeerStatus};
pub use quic_transport::{QuicTransport, QuicTransportOptions};
// Don't re-export pick_free_port since it's defined in this module

use super::discovery::multicast_discovery::PeerInfo;
// Import NodeInfo from the discovery module
use super::discovery::NodeInfo;

/// Type alias for async-returning function
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Unique identifier for a node in the network
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId {
    /// Unique ID for this node within the network
    pub public_key: String,
}

impl PeerId {
    /// Create a new NodeIdentifier
    pub fn new(node_id: String) -> Self {
        Self {
            public_key: node_id,
        }
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.public_key)
    }
}

/// Options for network transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportOptions {
    /// Timeout for network operations
    pub timeout: Option<Duration>,
    /// Maximum message size in bytes
    pub max_message_size: Option<usize>,
    /// Bind address for the transport
    pub bind_address: SocketAddr,
}

#[allow(clippy::derivable_impls)]
impl Default for TransportOptions {
    fn default() -> Self {
        let port = pick_free_port(50000..51000).unwrap_or(0);
        let bind_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        println!("TransportOptions Using port: {port}");
        Self {
            timeout: Some(Duration::from_secs(30)),
            max_message_size: Some(1024 * 1024), // 1MB default
            bind_address,
        }
    }
}

/// Find a free port in the given range using a randomized approach
pub fn pick_free_port(port_range: Range<u16>) -> Option<u16> {
    use rand::Rng;
    let mut rng = rand::rng();
    let range_size = port_range.end - port_range.start;

    // Limit number of attempts to avoid infinite loops
    let max_attempts = 50;
    let mut attempts = 0;

    while attempts < max_attempts {
        // Generate a random port within the range
        let port = port_range.start + rng.random_range(0..range_size);

        // Check if the port is available for TCP
        if let Ok(tcp_listener) =
            TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
        {
            let bound_port = match tcp_listener.local_addr() {
                Ok(addr) => addr.port(),
                Err(_) => {
                    attempts += 1;
                    continue;
                }
            };

            // For UDP/QUIC protocols, we should also check UDP availability
            // Since TcpListener only checks TCP ports
            if let Ok(_) = std::net::UdpSocket::bind(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                bound_port,
            )) {
                return Some(bound_port);
            }
        }

        attempts += 1;
    }

    None // No free port found after max attempts
}

/// Types of messages that can be sent over the network
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkMessageType {
    /// Service request message
    Request,
    /// Service response message
    Response,
    /// Event publication
    Event,
    /// Node discovery related message
    Discovery,
    /// Heartbeat/health check
    Heartbeat,
}

/// Represents a payload item in a network message
///
/// IMPORTANT: This is implemented as a struct with fields, not as a tuple.
/// The serialized data is stored in value_bytes and should be deserialized
/// using SerializerRegistry when needed.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkMessagePayloadItem {
    /// The path/topic associated with this payload
    pub path: String,

    /// The serialized value/payload data as bytes
    pub value_bytes: Vec<u8>,

    /// Correlation ID for request/response tracking
    pub correlation_id: String,
}

impl NetworkMessagePayloadItem {
    /// Create a new NetworkMessagePayloadItem
    pub fn new(path: String, value_bytes: Vec<u8>, correlation_id: String) -> Self {
        Self {
            path,
            value_bytes,
            correlation_id,
        }
    }
}

/// Represents a message exchanged between nodes
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkMessage {
    /// Source node identifier
    pub source: PeerId,

    /// Destination node identifier (MUST be specified)
    pub destination: PeerId,

    /// Message type (Request, Response, Event, etc.)
    pub message_type: String,

    /// List of payloads  
    pub payloads: Vec<NetworkMessagePayloadItem>,
}

/// Handler function type for incoming network messages
pub type MessageHandler = Box<dyn Fn(NetworkMessage) -> Result<()> + Send + Sync>;

/// Callback type for message handling with future
pub type MessageCallback =
    Arc<dyn Fn(NetworkMessage) -> BoxFuture<'static, Result<()>> + Send + Sync>;

/// Callback type for connection status changes
pub type ConnectionCallback =
    Arc<dyn Fn(PeerId, bool, Option<NodeInfo>) -> BoxFuture<'static, Result<()>> + Send + Sync>;

/// Network transport interface
#[async_trait]
pub trait NetworkTransport: Send + Sync {
    // No init method - all required fields should be provided in constructor

    /// Start listening for incoming connections
    async fn start(&self) -> Result<(), NetworkError>;

    /// Stop listening for incoming connections
    async fn stop(&self) -> Result<(), NetworkError>;

    /// Disconnect from a remote node
    async fn disconnect(&self, node_id: PeerId) -> Result<(), NetworkError>;

    /// Check if connected to a specific node
    async fn is_connected(&self, node_id: PeerId) -> bool;

    /// Send a message to a remote node
    async fn send_message(&self, message: NetworkMessage) -> Result<(), NetworkError>;

    /// connect to a discovered node
    ///
    /// Returns the NodeInfo of the connected peer after successful handshake
    async fn connect_peer(&self, discovery_msg: PeerInfo) -> Result<(), NetworkError>;

    /// Get the local address this transport is bound to as a string
    fn get_local_address(&self) -> String;

    /// Update the list of connected peers with the latest node info
    async fn update_peers(&self, node_info: NodeInfo) -> Result<(), NetworkError>;

    // /// Register a message handler for incoming messages
    // async fn register_message_handler(
    //     &self,
    //     handler: Box<dyn Fn(NetworkMessage) -> Result<(), NetworkError> + Send + Sync + 'static>,
    // ) -> Result<(), NetworkError>;

    /// Subscribe to peer node info updates
    ///
    /// INTENTION: Allow callers to subscribe to peer node info updates when they are received
    /// during handshakes. This is used by the Node to create RemoteService instances.
    async fn subscribe_to_peer_node_info(&self) -> tokio::sync::broadcast::Receiver<NodeInfo>;
}

/// Error type for network operations
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("Message error: {0}")]
    MessageError(String),
    #[error("Discovery error: {0}")]
    DiscoveryError(String),
    #[error("Transport error: {0}")]
    TransportError(String),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}
