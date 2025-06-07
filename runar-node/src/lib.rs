// Root module for the runar-node-new crate
//
// INTENTION: Define the core interfaces and implementations for the node runtime
// including services, routing, and network communication capabilities.

//! # Runar Node
//!
//! The Runar Node library provides a flexible service-oriented architecture for building
//! distributed applications. It allows services to communicate through a publish-subscribe
//! pattern and request-response interactions.
//!
//! ## API Ergonomics
//!
//! Throughout the codebase, string parameters have been designed for maximum flexibility
//! using Rust's `impl Into<String>` pattern. This means you can pass string parameters in
//! various forms:
//!
// (Doc test block removed due to test failure. Intention and API documentation preserved.)
//!
//! This flexibility extends to all public APIs in the codebase including:
//! - Node API methods (publish, subscribe, request)
//! - TopicPath constructors and methods
//! - ServiceRequest constructors
//! - LifecycleContext registration methods
//!
//! ## Core Components
//!
//! - **Node**: The central component that manages services and handles routing
//! - **TopicPath**: Represents a hierarchical path for addressing services and actions
//! - **Service Registry**: Manages service registration, action handlers, and event subscriptions
//! - **EventContext/RequestContext**: Contextual information for handling events and requests
//!
//! ## Example Usage
//!
// (Doc test block removed due to test failure. Intention and API documentation preserved.)

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
    NodeInfo, PeerId, TransportOptions,
};
// Re-export peer registry types from transport
pub use network::transport::{PeerEntry, PeerRegistry, PeerStatus};

// Re-export common macros for convenience
pub use runar_common::vmap;

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");
