// Import modules
pub mod cli;
pub mod config;
pub mod db;
pub mod init;
pub mod ipc;
pub mod key_management;
pub mod node;
pub mod p2p;
pub mod routing;
pub mod server;
pub mod services;
pub mod util;
pub mod web;

// Import common types from runar_common
pub use runar_common::types::ValueType;
pub use runar_common::types::SerializableStruct;

// Re-export types for easier access
pub use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
// Use logging from common crate instead of local util
pub use runar_common::utils::logging;

use crate::db::SqliteDatabase;
use crate::services::service_registry::ServiceRegistry;

// Re-export IPC functionality
pub use crate::ipc::init_ipc_server;

// Re-export important types and traits for macros and external use
pub use crate::node::{Node, NodeConfig};
pub use crate::routing::{TopicPath, PathType};
pub use crate::services::{
    RequestContext, ResponseStatus, ServiceRequest, ServiceResponse,
    // Re-export registry types for macros
    ActionHandler, ProcessHandler, EventSubscription, PublicationInfo,
};
pub use crate::services::abstract_service::{AbstractService, ServiceMetadata};
pub use crate::server::Service;
// Export types needed for macro tests
pub use crate::services::abstract_service::ServiceState;
pub use crate::p2p::crypto::{AccessToken, NetworkId, PeerId};
pub use crate::p2p::transport::P2PTransport;

// Re-export initializer types
pub use crate::init::{Initializer, INITIALIZERS};

// Re-export common types and macros
pub use runar_common::utils::*;
pub use runar_common::vmap;
pub use runar_common::vjson;

// Re-export distributed slice attribute if enabled
#[cfg(feature = "distributed_slice")]
pub use services::distributed_slice;

/// Initialize a node with the given configuration directory
pub async fn init_node(config_dir: PathBuf) -> Result<Arc<node::Node>> {
    // Create the node configuration
    let node_name = "runar-node";
    let private_key = config::NodeConfig::generate_keypair()?.to_bytes().to_vec();
    let web_ui_port = 3000;

    let config = config::NodeConfig::new(
        node_name.to_string(),
        private_key,
        config_dir.clone(),
        web_ui_port,
    )?;

    // Create the node
    let node_config = node::NodeConfig::new(
        &config.node_name,
        config_dir.to_str().unwrap_or("."),
        config_dir.to_str().unwrap_or("."),
    );
    let mut node = node::Node::new(node_config).await?;
    node.init().await?;

    Ok(Arc::new(node))
}

/// Initialize the Runar Node with services
pub async fn init_with_services(db_path: &str, network_id: &str) -> Result<()> {
    // Extract the node path from the database path
    let db_path_buf = std::path::PathBuf::from(db_path);
    let node_path = db_path_buf
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_str()
        .unwrap();

    // Create NodeConfig
    let node_config = node::NodeConfig::new(network_id, node_path, node_path);

    // Create and initialize a new node
    let mut node = node::Node::new(node_config).await?;
    node.init().await?;

    // Run the main command-line interface
    cli::run().await
}

/// Initialize the Runar Node
pub async fn init() -> Result<()> {
    // This is a placeholder for future initialization code
    Ok(())
}

/// Initialize the Runar Node with services
pub async fn start_node(config: node::NodeConfig) -> Result<node::Node> {
    // Create and initialize a new node
    let mut node = node::Node::new(config).await?;
    node.init().await?;
    Ok(node)
}

// EventType definition for macro tests
#[derive(Clone, Debug)]
pub struct EventType {
    pub data: serde_json::Value,
}

// Re-export remaining node types
pub use crate::node::NodeRequestHandlerImpl;
// Be selective about what to re-export from services to avoid conflicts
pub use crate::services::ServiceManager;
pub use crate::services::NodeRequestHandler;
