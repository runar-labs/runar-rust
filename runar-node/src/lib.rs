// Public modules
pub mod config;
pub mod network;
pub mod node;
pub mod routing;
pub mod services;

// Re-export the main types from the node module
pub use node::{Node, NodeConfig};

// Re-export the main types from the services module
pub use services::abstract_service::{AbstractService, ServiceState};
pub use services::service_registry::ServiceRegistry;
pub use services::{
    ActionHandler, EventContext, LifecycleContext, NodeDelegate, PublishOptions, RegistryDelegate,
    RequestContext, ServiceRequest, SubscriptionOptions,
};

// Re-export the schema types from runar_common
pub use runar_common::types::schemas::{ActionMetadata, EventMetadata, ServiceMetadata};

// Re-export the main types from the routing module
pub use routing::TopicPath;

// Re-export the main types from the network module
pub use network::{
    DiscoveryOptions, NetworkMessage, NetworkMessageType, NetworkTransport, NodeDiscovery,
    NodeInfo, TransportOptions,
};
// Re-export peer registry types from transport
pub use network::transport::{PeerEntry, PeerRegistry, PeerStatus};

// Re-export common macros for convenience
pub use runar_common::vmap;

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");
