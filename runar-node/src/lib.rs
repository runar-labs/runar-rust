//! # Runar Node
//!
//! A high-performance, distributed service mesh framework for building privacy-preserving applications.
//!
//! ## Overview
//!
//! The Runar Node provides a complete runtime environment for services to communicate, discover each other,
//! and handle requests in a distributed, encrypted manner. It's designed to be lightweight, performant,
//! and easy to integrate into existing applications.
//!
//! ## Key Features
//!
//! - **Service Registry**: Automatic service discovery and registration
//! - **Request/Response**: Type-safe service-to-service communication
//! - **Event Publishing**: Publish/subscribe pattern for loose coupling
//! - **Network Transport**: QUIC-based networking with automatic peer discovery
//! - **Load Balancing**: Built-in load balancing for distributed services
//! - **Encryption**: End-to-end encryption with selective field access
//! - **Lifecycle Management**: Automatic service lifecycle management
//!
//! ## Quick Start
//!
//! ```rust
//! use runar_node::{Node, NodeConfig};
//! use runar_node::AbstractService;
//!
//! // Example of how to create and start a node (conceptual)
//! async fn example_usage() -> anyhow::Result<()> {
//!     // Note: This example shows the concept but would need proper
//!     // key manager state to actually create a Node instance.
//!     
//!     // Create a node configuration
//!     // let config = NodeConfig::new("my-node", "my-network");
//!     //
//!     // Create and start the node
//!     // let  node = Node::new(config).await?;
//!     // node.start().await?;
//!     //
//!     // Your services can now communicate!
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! The Runar Node is built around several core concepts:
//!
//! - **Node**: The main runtime that manages services and networking
//! - **Services**: Business logic components that handle requests and publish events
//! - **Topics**: Hierarchical addressing system for routing messages
//! - **Network**: Peer-to-peer communication layer with automatic discovery
//! - **Registry**: Service discovery and metadata management
//!
//! ## Modules
//!
//! - [`config`] - Configuration management for nodes and services
//! - [`network`] - Network transport, discovery, and peer management
//! - [`node`] - Core node implementation and lifecycle management
//! - [`routing`] - Topic-based routing and path resolution
//! - [`services`] - Service abstraction and registry management
//!
//! ## Examples
//!
//! See the `examples/` directory for complete working examples of:
//!
//! - Basic service implementation
//! - Request/response patterns
//! - Event publishing and subscription
//! - Network configuration
//! - Service lifecycle management
//!
//! ## License
//!
//! This project is licensed under the MIT License - see the LICENSE file for details.

// Public modules
pub mod config;
pub mod node;
pub mod services;

// Re-export the main types from the node module
pub use node::{Node, NodeConfig};

// Re-export the main types from the services module
pub use services::abstract_service::{AbstractService, ServiceState};
pub use services::service_registry::ServiceRegistry;
pub use services::{
    ActionHandler, EventContext, LifecycleContext, NodeDelegate, PublishOptions, RegistryDelegate,
    RequestContext, ServiceRequest,
};

// Re-export the schema types from runar_schemas
pub use runar_schemas::{ActionMetadata, ServiceMetadata};

pub use runar_common::routing::TopicPath;

pub use runar_transporter::discovery::{DiscoveryOptions, NodeDiscovery};
pub use runar_transporter::transport::{
    GetLocalNodeInfoCallback, NetworkMessage, NetworkMessageType, NetworkTransport,
};

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");
