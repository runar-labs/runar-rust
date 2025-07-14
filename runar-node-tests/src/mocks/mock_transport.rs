// Mock Transport Implementation
//
// INTENTION: Provide a mock implementation of the NetworkTransport trait for testing only.

use anyhow::Result;
use async_trait::async_trait;
use std::sync::RwLock;

use runar_common::Logger;
use runar_node::network::discovery::{multicast_discovery::PeerInfo, NodeInfo};
use runar_node::network::transport::{
    MessageHandler, NetworkError, NetworkMessage, NetworkTransport,
};
use tokio::sync::broadcast;

/// A mock network transport that stores messages in memory
pub struct MockNetworkTransport {
    /// Messages sent through this transport
    messages: RwLock<Vec<NetworkMessage>>,
    /// Handlers registered with this transport
    handlers: RwLock<Vec<MessageHandler>>,
    /// Local node identifier
    node_id: String,
    /// Logger
    logger: Logger,
}

impl MockNetworkTransport {
    /// Create a new mock transport
    pub fn new(node_id: String, logger: Logger) -> Self {
        Self {
            messages: RwLock::new(Vec::new()),
            handlers: RwLock::new(Vec::new()),
            node_id,
            logger,
        }
    }

    /// Get all messages sent through this transport
    pub fn get_messages(&self) -> Vec<NetworkMessage> {
        self.messages.read().unwrap().clone()
    }
}

#[async_trait]
impl NetworkTransport for MockNetworkTransport {
    async fn start(&self) -> Result<(), NetworkError> {
        self.logger.info("MockNetworkTransport: start called");
        Ok(())
    }

    async fn stop(&self) -> Result<(), NetworkError> {
        self.logger.info("MockNetworkTransport: stop called");
        Ok(())
    }

    async fn disconnect(&self, node_id: String) -> Result<(), NetworkError> {
        self.logger.info(format!(
            "MockNetworkTransport: disconnect called for node_id: {node_id}"
        ));
        Ok(())
    }

    async fn is_connected(&self, node_id: String) -> bool {
        self.logger.info(format!(
            "MockNetworkTransport: is_connected called for node_id: {node_id}"
        ));
        false
    }

    async fn send_message(&self, message: NetworkMessage) -> Result<(), NetworkError> {
        self.logger.info(format!(
            "MockNetworkTransport: send_message called to: {}",
            message.destination_node_id
        ));
        self.messages.write().unwrap().push(message);
        Ok(())
    }

    async fn connect_peer(&self, discovery_msg: PeerInfo) -> Result<(), NetworkError> {
        self.logger.info(format!(
            "MockNetworkTransport: connect_peer called for peer: {:?}",
            discovery_msg.public_key
        ));
        Ok(())
    }

    fn get_local_address(&self) -> String {
        "127.0.0.1:8090".to_string()
    }

    async fn update_peers(&self, node_info: NodeInfo) -> Result<(), NetworkError> {
        self.logger.info(format!(
            "MockNetworkTransport: update_peers called for node: {:?}",
            node_info.node_public_key
        ));
        Ok(())
    }

    async fn subscribe_to_peer_node_info(&self) -> broadcast::Receiver<NodeInfo> {
        // Return a dummy broadcast channel for tests
        let (_tx, rx) = broadcast::channel(1);
        rx
    }
}
