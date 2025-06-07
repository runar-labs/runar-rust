// Mock Transport Implementation
//
// INTENTION: Provide a mock implementation of the NetworkTransport trait for testing only.

use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use crate::network::transport::{
    NetworkTransport, TransportFactory, NetworkMessage, 
    NodeIdentifier, MessageHandler, PeerRegistry
};
use crate::network::discovery::NodeInfo;
use runar_common::Logger;

/// A mock network transport that stores messages in memory
pub struct MockNetworkTransport {
    /// Messages sent through this transport
    messages: RwLock<Vec<NetworkMessage>>,
    /// Handlers registered with this transport
    handlers: RwLock<Vec<MessageHandler>>,
    /// Local node identifier
    node_id: NodeIdentifier,
    /// Peer registry
    peer_registry: Arc<PeerRegistry>,
    /// Logger
    logger: Logger,
}

impl MockNetworkTransport {
    /// Create a new mock transport
    pub fn new(node_id: NodeIdentifier, logger: Logger) -> Self {
        Self {
            messages: RwLock::new(Vec::new()),
            handlers: RwLock::new(Vec::new()),
            node_id,
            peer_registry: Arc::new(PeerRegistry::new()),
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
    async fn init(&self) -> Result<()> {
        self.logger.info("Initializing mock transport");
        Ok(())
    }
    
    async fn connect(&self, node_info: &NodeInfo) -> Result<()> {
        // Just log the connection attempt
        self.logger.info(format!("Mock connecting to node: {}", node_info.identifier));
        Ok(())
    }
    
    async fn send(&self, message: NetworkMessage) -> Result<()> {
        self.logger.info(format!("Mock sending message to: {:?}", message.destination));
        self.messages.write().unwrap().push(message.clone());
        
        // Call handlers
        for handler in self.handlers.read().unwrap().iter() {
            handler(message.clone())?;
        }
        
        Ok(())
    }
    
    fn register_handler(&self, handler: MessageHandler) -> Result<()> {
        self.handlers.write().unwrap().push(handler);
        Ok(())
    }
    
    fn peer_registry(&self) -> &PeerRegistry {
        &self.peer_registry
    }
    
    fn local_node_id(&self) -> &NodeIdentifier {
        &self.node_id
    }
    
    async fn local_address(&self) -> Option<SocketAddr> {
        // Use a fixed address for mock transport
        Some("127.0.0.1:8090".parse().unwrap())
    }
    
    async fn shutdown(&self) -> Result<()> {
        self.logger.info("Shutting down Mock transport");
        Ok(())
    }
}

/// Factory for creating mock transport instances
pub struct MockTransportFactory;

#[async_trait]
impl TransportFactory for MockTransportFactory {
    type Transport = MockNetworkTransport;
    
    async fn create_transport(
        &self, 
        node_id: NodeIdentifier, 
        logger: Logger
    ) -> Result<Self::Transport> {
        Ok(MockNetworkTransport::new(node_id, logger))
    }
} 