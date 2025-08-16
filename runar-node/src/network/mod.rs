// Network Module
//
// This module provides network functionality for the Runar system, including
// peer discovery, transport management, and network communication.
//
// ## Components
//
// - **Discovery**: Automatic peer discovery using multicast and memory-based discovery
// - **Transport**: QUIC-based network transport with TLS encryption
// - **Peer Management**: Connection pooling and peer state tracking
// - **Network Configuration**: Flexible configuration for different network topologies
//
// ## Key Features
//
// - **Peer Discovery**: Automatic discovery of other nodes in the network
// - **Secure Transport**: QUIC with TLS for encrypted communication
// - **Connection Pooling**: Efficient connection reuse and management
// - **Load Balancing**: Built-in load balancing for distributed services
// - **Network Isolation**: Support for multiple networks with proper boundaries
//
// ## Examples
//
// ```rust
// use runar_node::network::{NetworkConfig, DiscoveryOptions};
//
// // Configure networking
// let config = NetworkConfig::default()
//     .with_discovery(DiscoveryOptions::multicast("224.0.0.1:8888"))
//     .with_transport(TransportOptions::quic(8889));
//
// // Enable networking on a node
// let node_config = NodeConfig::new("my-node", "my-network")
//     .with_network_config(config);
// ```

pub mod discovery;
pub mod network_config;
pub mod transport;

pub use discovery::{DiscoveryListener, DiscoveryOptions, MulticastDiscovery, NodeDiscovery};
pub use runar_schemas::{ActionMetadata, ServiceMetadata};
pub use transport::{
    MessageHandler, NetworkMessage, NetworkMessageType, NetworkTransport, QuicTransport,
    QuicTransportOptions, TransportOptions,
};
