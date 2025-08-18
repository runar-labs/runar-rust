// Network Transport Module
use anyhow::Result;
use async_trait::async_trait;
use rand;
use runar_schemas::NodeInfo;

use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

// Import the new rustls types
// Keep CertificateDer only where needed (quic_transport). Remove here to avoid unused import warnings.

pub mod quic_transport;

// Removed WebSocket module completely

// Re-export types/traits from submodules or parent modules
// pub use peer_registry::{PeerEntry, PeerRegistry, PeerRegistryOptions, PeerStatus};
pub use quic_transport::{QuicTransport, QuicTransportOptions};

use super::discovery::multicast_discovery::PeerInfo;

/// Type alias for async-returning function
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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

impl Default for TransportOptions {
    fn default() -> Self {
        // Use port 0 so the OS assigns an ephemeral free port at bind time.
        // This avoids test flakes under concurrent CI runs where a pre-picked
        // port may be taken by another process by the time we bind.
        let bind_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

        Self {
            timeout: Some(Duration::from_secs(30)),
            max_message_size: Some(1024 * 1024), // 1MB default
            bind_address,
        }
    }
}

impl TransportOptions {
    pub fn validate(&self) -> Result<(), NetworkError> {
        if let Some(ms) = self.max_message_size {
            if ms == 0 {
                return Err(NetworkError::ConfigurationError(
                    "max_message_size must be > 0".to_string(),
                ));
            }
        }
        Ok(())
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
            if std::net::UdpSocket::bind(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                bound_port,
            ))
            .is_ok()
            {
                return Some(bound_port);
            }
        }

        attempts += 1;
    }

    None // No free port found after max attempts
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessagePayloadItem {
    /// The path/topic associated with this payload
    pub path: String,

    /// The serialized value/payload data as bytes
    pub payload_bytes: Vec<u8>,

    /// Correlation ID
    pub correlation_id: String,

    pub profile_public_key: Vec<u8>,
}

pub const MESSAGE_TYPE_DISCOVERY: u32 = 1;
pub const MESSAGE_TYPE_HEARTBEAT: u32 = 2;
pub const MESSAGE_TYPE_HANDSHAKE: u32 = 3;
pub const MESSAGE_TYPE_REQUEST: u32 = 4;
pub const MESSAGE_TYPE_RESPONSE: u32 = 5;
pub const MESSAGE_TYPE_EVENT: u32 = 6;
pub const MESSAGE_TYPE_ERROR: u32 = 7;

/// Represents a message exchanged between nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    /// Source node identifier
    pub source_node_id: String,

    /// Destination node identifier (MUST be specified)
    pub destination_node_id: String,

    /// Message type (Request, Response, Event, etc.)
    pub message_type: u32,

    /// Single payload for this message
    pub payload: NetworkMessagePayloadItem,
}

// Handler function type for incoming network messages that may return a response
// pub type MessageHandler = Box<
//     dyn Fn(
//             NetworkMessage,
//         ) -> std::pin::Pin<
//             Box<
//                 dyn std::future::Future<Output = Result<Option<NetworkMessage>, NetworkError>>
//                     + Send,
//             >,
//         > + Send
//         + Sync,
// >;

// Handler function type for one-way network messages (fire-and-forget)
// pub type OneWayMessageHandler = Box<
//     dyn Fn(
//             NetworkMessage,
//         )
//             -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), NetworkError>> + Send>>
//         + Send
//         + Sync,
// >;

/// Callback type for message handling with future
pub type MessageCallback =
    Arc<dyn Fn(NetworkMessage) -> BoxFuture<'static, Result<()>> + Send + Sync>;

/// Callback type for connection status changes
pub type ConnectionCallback =
    Arc<dyn Fn(String, bool) -> BoxFuture<'static, Result<()>> + Send + Sync>;

pub type PeerConnectedCallback =
    Arc<dyn Fn(String, NodeInfo) -> BoxFuture<'static, ()> + Send + Sync>;

pub type PeerDisconnectedCallback = Arc<dyn Fn(String) -> BoxFuture<'static, ()> + Send + Sync>;

pub type GetLocalNodeInfoCallback =
    Arc<dyn Fn() -> BoxFuture<'static, Result<NodeInfo>> + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMessage {
    pub path: String,
    pub correlation_id: String,
    pub payload_bytes: Vec<u8>,
    pub profile_public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMessage {
    pub correlation_id: String,
    pub payload_bytes: Vec<u8>,
    pub profile_public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMessage {
    pub path: String,
    pub correlation_id: String,
    pub payload_bytes: Vec<u8>,
}

pub type RequestCallback =
    Arc<dyn Fn(RequestMessage) -> BoxFuture<'static, Result<ResponseMessage>> + Send + Sync>;

pub type EventCallback = Arc<dyn Fn(EventMessage) -> BoxFuture<'static, Result<()>> + Send + Sync>;

/// Network transport interface
#[async_trait]
pub trait NetworkTransport: Send + Sync {
    // No init method - all required fields should be provided in constructor

    /// Start listening for incoming connections
    async fn start(self: Arc<Self>) -> Result<(), NetworkError>;

    /// Stop listening for incoming connections
    async fn stop(&self) -> Result<(), NetworkError>;

    /// Disconnect from a remote node
    async fn disconnect(&self, node_id: &str) -> Result<(), NetworkError>;

    /// Check if connected to a specific node
    async fn is_connected(&self, peer_node_id: &str) -> bool;

    /// Perform an RPC request/response exchange (pattern A). The transport
    /// opens a fresh bidirectional stream, writes the request, finishes the
    /// send half, reads the response and returns the deserialized payload bytes.
    async fn request(
        &self,
        topic_path: &str,
        correlation_id: &str,
        payload: Vec<u8>,
        peer_node_id: &str,
        profile_public_key: Vec<u8>,
    ) -> Result<Vec<u8>, NetworkError>;

    /// Fire-and-forget / broadcast message (pattern B)  
    /// events or heart-beats.
    async fn publish(
        &self,
        topic_path: &str,
        correlation_id: &str,
        payload: Vec<u8>,
        peer_node_id: &str,
    ) -> Result<(), NetworkError>;

    /// connect to a discovered node and perform the NodeInfo handshake.
    async fn connect_peer(self: Arc<Self>, discovery_msg: PeerInfo) -> Result<(), NetworkError>;

    /// Get the local address this transport is bound to as a string
    fn get_local_address(&self) -> String;

    /// Update the list of connected peers with the latest node info
    async fn update_peers(&self, node_info: NodeInfo) -> Result<(), NetworkError>;

    /// Expose the transport-owned keystore (read-only).
    fn keystore(&self) -> Arc<dyn runar_serializer::traits::EnvelopeCrypto>;

    /// Expose the transport-owned label resolver.
    fn label_resolver(&self) -> Arc<dyn runar_serializer::traits::LabelResolver>;
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
