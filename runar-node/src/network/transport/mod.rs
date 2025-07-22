// Network Transport Module
use anyhow::Result;
use async_trait::async_trait;
use prost::Message;
use rand;
use runar_serializer::ArcValue;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

// Import the new rustls types
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls_pki_types::{CertificateDer, ServerName};

// Internal module declarations
pub mod connection_pool;
pub mod keystore_proxy;
pub mod peer_state;
pub mod quic_transport;
pub mod stream_pool;

pub use connection_pool::ConnectionPool;
pub use keystore_proxy::KeystoreReadProxy;
pub use peer_state::PeerState;
pub use stream_pool::StreamPool; 
use crate::routing::TopicPath;
// --- Moved from quic_transport.rs ---
/// Custom certificate verifier that skips verification for testing
///
/// INTENTION: Allow connections without certificate verification in test environments
#[derive(Debug)]
pub struct SkipServerVerification {}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

// Removed WebSocket module completely

// Re-export types/traits from submodules or parent modules
// pub use peer_registry::{PeerEntry, PeerRegistry, PeerRegistryOptions, PeerStatus};
pub use quic_transport::{QuicTransport, QuicTransportOptions};
// Don't re-export pick_free_port since it's defined in this module

use super::discovery::multicast_discovery::PeerInfo;
// Import NodeInfo from the discovery module
use super::discovery::NodeInfo;

/// Type alias for async-returning function
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// /// Unique identifier for a node in the network
// #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
// pub struct PeerId {
//     /// Unique ID for this node within the network
//     pub public_key: String,
//     pub node_id: String,
// }

// impl PeerId {
//     /// Create a new NodeIdentifier
//     pub fn new(public_key: String, node_id: String) -> Self {
//         Self {
//             public_key: public_key,
//             node_id: node_id,
//         }
//     }
// }

// impl fmt::Display for PeerId {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "{}", self.public_key)
//     }
// }

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

#[derive(Serialize, Deserialize, Clone, Message)]
pub struct MessageContext {
    #[prost(bytes, tag = "1")]
    pub profile_public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Message)]
pub struct NetworkMessagePayloadItem {
    /// The path/topic associated with this payload
    #[prost(string, tag = "1")]
    pub path: String,

    /// The serialized value/payload data as bytes
    #[prost(bytes, tag = "2")]
    pub value_bytes: Vec<u8>,

    #[prost(message, tag = "3")]
    pub context: Option<MessageContext>,

    /// Correlation ID for request/response tracking
    #[prost(string, tag = "4")]
    pub correlation_id: String,
}

impl NetworkMessagePayloadItem {
    /// Create a new NetworkMessagePayloadItem
    pub fn new(path: String, value_bytes: Vec<u8>, correlation_id: String, context: MessageContext) -> Self {
        Self {
            path,
            value_bytes,
            correlation_id,
            context: Some(context),
        }
    }
}

pub const MESSAGE_TYPE_DISCOVERY: u32 = 1;
pub const MESSAGE_TYPE_HEARTBEAT: u32 = 2;
pub const MESSAGE_TYPE_ANNOUNCEMENT: u32 = 3;
pub const MESSAGE_TYPE_HANDSHAKE: u32 = 4;
pub const MESSAGE_TYPE_REQUEST: u32 = 5;
pub const MESSAGE_TYPE_RESPONSE: u32 = 6;
pub const MESSAGE_TYPE_EVENT: u32 = 7;
pub const MESSAGE_TYPE_ERROR: u32 = 8;
pub const MESSAGE_TYPE_NODE_INFO_UPDATE: u32 = 9;
pub const MESSAGE_TYPE_NODE_INFO_HANDSHAKE_RESPONSE: u32 = 10;

/// Represents a message exchanged between nodes
#[derive(Serialize, Deserialize, Clone, Message)]
pub struct NetworkMessage {
    /// Source node identifier
    #[prost(string, tag = "1")]
    pub source_node_id: String,

    /// Destination node identifier (MUST be specified)
    #[prost(string, tag = "2")]
    pub destination_node_id: String,

    /// Message type (Request, Response, Event, etc.)
    #[prost(uint32, tag = "3")]
    pub message_type: u32,

    /// List of payloads  
    #[prost(message, repeated, tag = "4")]
    pub payloads: Vec<NetworkMessagePayloadItem>,
}

/// Handler function type for incoming network messages
pub type MessageHandler = Box<dyn Fn(NetworkMessage) -> Result<()> + Send + Sync>;

/// Callback type for message handling with future
pub type MessageCallback =
    Arc<dyn Fn(NetworkMessage) -> BoxFuture<'static, Result<()>> + Send + Sync>;

/// Callback type for connection status changes
pub type ConnectionCallback =
    Arc<dyn Fn(String, bool, Option<NodeInfo>) -> BoxFuture<'static, Result<()>> + Send + Sync>;

/// Network transport interface
#[async_trait]
pub trait NetworkTransport: Send + Sync {
    // No init method - all required fields should be provided in constructor

    /// Start listening for incoming connections
    async fn start(&self) -> Result<(), NetworkError>;

    /// Stop listening for incoming connections
    async fn stop(&self) -> Result<(), NetworkError>;

    /// Disconnect from a remote node
    async fn disconnect(&self, node_id: String) -> Result<(), NetworkError>;

    /// Check if connected to a specific node
    async fn is_connected(&self, node_id: String) -> bool;

    /// Send a message to a remote node
    async fn send_message(&self, message: NetworkMessage) -> Result<(), NetworkError>;

    async fn send_request(&self, topic_path: &TopicPath, params: Option<ArcValue>, request_id: &str, peer_node_id: &str, context: MessageContext) -> Result<(), NetworkError>;

    /// connect to a discovered node
    ///
    /// Returns the NodeInfo of the connected peer after successful handshake
    async fn connect_peer(&self, discovery_msg: PeerInfo) -> Result<(), NetworkError>;

    /// Get the local address this transport is bound to as a string
    fn get_local_address(&self) -> String;

    /// Update the list of connected peers with the latest node info
    async fn update_peers(&self, node_info: NodeInfo) -> Result<(), NetworkError>;

    /// Subscribe to peer node info updates
    ///
    /// INTENTION: Allow callers to subscribe to peer node info updates when they are received
    /// during handshakes. This is used by the Node to create RemoteService instances.
    async fn subscribe_to_peer_node_info(&self) -> tokio::sync::broadcast::Receiver<NodeInfo>;

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
