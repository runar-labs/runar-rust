// Network Module
//
// This module provides network functionality for the Runar system.

pub mod discovery;
pub mod network_config;
pub mod transport;

pub use discovery::{
    DiscoveryListener, DiscoveryOptions, MemoryDiscovery, MulticastDiscovery, NodeDiscovery,
    NodeInfo,
};
pub use runar_common::types::{ActionMetadata, EventMetadata, ServiceMetadata};
pub use transport::{
    MessageHandler, NetworkMessage, NetworkMessageType, NetworkTransport, PeerEntry, PeerRegistry,
    PeerStatus, QuicTransport, QuicTransportOptions, TransportOptions,
};

// Implementation modules should be imported directly when needed:
// use runar_node::network::discovery::multicast_discovery::MulticastDiscovery;
// use runar_node::network::transport::quic_transport::{QuicTransport, QuicTransportOptions};
