// Network Module Tests
//
// Tests for the network components including transport and discovery

use std::sync::Arc;
use std::collections::HashMap;
use anyhow::{anyhow, Result};
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use std::net::SocketAddr;
use async_trait::async_trait;

use runar_node::network::transport::{NetworkTransport, NetworkMessage, PeerId, MessageHandler};
use runar_node::network::transport::{NetworkError, ConnectionCallback};
use runar_node::network::discovery::{NodeDiscovery, NodeInfo, DiscoveryOptions, DiscoveryListener};
use runar_common::types::{ValueType, ServiceMetadata, ActionMetadata, EventMetadata, FieldSchema, SchemaDataType};
use runar_common::Logger;
use runar_node::network::transport::peer_registry::PeerRegistry;

// Mock implementation of NetworkTransport for testing
struct MockTransport {
    node_id: PeerId,
    sent_messages: RwLock<Vec<NetworkMessage>>,
    message_sink: Option<mpsc::Sender<NetworkMessage>>,
    logger: Logger,
    peer_registry: Arc<PeerRegistry>,
}

impl MockTransport {
    fn new(_network_id: &str, node_id: &str) -> Self {
        Self {
            node_id: PeerId::new(node_id.to_string()),
            sent_messages: RwLock::new(Vec::new()),
            message_sink: None,
            logger: Logger::new_root(runar_common::Component::Network, node_id),
            peer_registry: Arc::new(PeerRegistry::new()),
        }
    }
    
    fn set_message_sink(&mut self, sink: mpsc::Sender<NetworkMessage>) {
        self.message_sink = Some(sink);
    }
    
    async fn get_sent_messages(&self) -> Vec<NetworkMessage> {
        self.sent_messages.read().await.clone()
    }
}

#[async_trait]
impl NetworkTransport for MockTransport {
    async fn initialize(&self) -> Result<(), NetworkError> {
        self.logger.debug("MockTransport: initialize called");
        Ok(())
    }

    async fn start(&self) -> Result<(), NetworkError> {
        self.logger.debug("MockTransport: start called");
        Ok(())
    }

    async fn stop(&self) -> Result<(), NetworkError> {
        self.logger.debug("MockTransport: stop called");
        Ok(())
    }

    fn is_running(&self) -> bool {
        true // Mock is always "running"
    }

    fn get_local_address(&self) -> String {
        "mock://127.0.0.1:0".to_string()
    }

    fn get_local_node_id(&self) -> PeerId {
        self.node_id.clone()
    }

    // Correct signature: takes PeerId, not &NodeInfo
    async fn connect(&self, _node_id: PeerId, _address: SocketAddr) -> Result<(), NetworkError> {
        self.logger.debug("MockTransport: connect called");
        Ok(())
    }

    async fn disconnect(&self, _node_id: PeerId) -> Result<(), NetworkError> {
        self.logger.debug("MockTransport: disconnect called");
        Ok(())
    }

    fn is_connected(&self, _node_id: PeerId) -> bool {
        false // Mock doesn't track connections
    }

    async fn send_message(&self, message: NetworkMessage) -> Result<(), NetworkError> {
        self.logger.debug(format!("MockTransport: send_message called: {:?}", message));
        self.sent_messages.write().await.push(message.clone());
        if let Some(sink) = &self.message_sink {
            if let Err(e) = sink.send(message).await {
                self.logger.error(format!("MockTransport: Failed to send message to sink: {e}"));
            }
        }
        Ok(())
    }

    // Correct name: register_message_handler
    fn register_message_handler(&self, _handler: MessageHandler) -> Result<()> {
        self.logger.debug("MockTransport: register_message_handler called");
        // Handler registration not really mocked here, messages go to sink
        Ok(())
    }

    fn set_connection_callback(&self, _callback: ConnectionCallback) -> Result<()> {
        self.logger.debug("MockTransport: set_connection_callback called");
        Ok(())
    }

    fn get_connected_nodes(&self) -> Vec<PeerId> {
        Vec::new()
    }

    async fn send_request(&self, message: NetworkMessage) -> Result<NetworkMessage, NetworkError> {
        self.logger.debug(format!("MockTransport: send_request called: {:?}", message));
        self.send_message(message.clone()).await?;
        // Mock doesn't actually wait for a response, return error or dummy response?
        // Let's return an error for now.
        Err(NetworkError::TransportError("send_request mock response not implemented".to_string()))
    }

    async fn handle_message(&self, _message: NetworkMessage) -> Result<(), NetworkError> {
        self.logger.debug("MockTransport: handle_message called");
        Ok(())
    }

    async fn start_discovery(&self) -> Result<(), NetworkError> {
        self.logger.debug("MockTransport: start_discovery called");
        Ok(())
    }

    async fn stop_discovery(&self) -> Result<(), NetworkError> {
        self.logger.debug("MockTransport: stop_discovery called");
        Ok(())
    }

    async fn register_discovered_node(&self, _node_info: NodeInfo) -> Result<(), NetworkError> {
        self.logger.debug("MockTransport: register_discovered_node called");
        Ok(())
    }

    fn get_discovered_nodes(&self) -> Vec<PeerId> {
        Vec::new()
    }

    fn set_node_discovery(&self, _discovery: Box<dyn NodeDiscovery>) -> Result<()> {
        self.logger.debug("MockTransport: set_node_discovery called");
        Ok(())
    }

    fn complete_pending_request(&self, _correlation_id: String, _response: NetworkMessage) -> Result<(), NetworkError> {
        self.logger.debug("MockTransport: complete_pending_request called");
        Ok(())
    }
}

// Mock implementation of NodeDiscovery for testing
struct MockDiscovery {
    nodes: RwLock<HashMap<String, Vec<NodeInfo>>>,
    listeners: RwLock<Vec<DiscoveryListener>>,
    logger: Logger,
}

impl MockDiscovery {
    fn new() -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            listeners: RwLock::new(Vec::new()),
            logger: Logger::new_root(runar_common::Component::Network, "mock-discovery"),
        }
    }
}

#[async_trait]
impl NodeDiscovery for MockDiscovery {
    async fn init(&self, _options: DiscoveryOptions) -> Result<()> {
        Ok(())
    }
    
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
    
    async fn register_node(&self, node_info: NodeInfo) -> Result<()> {
        let mut nodes = self.nodes.write().await;
        let network_ids = node_info.network_ids.clone();
        
        for network_id in network_ids {
            if let Some(network_nodes) = nodes.get_mut(&network_id) {
                network_nodes.push(node_info.clone());
            } else {
                nodes.insert(network_id, vec![node_info.clone()]);
            }
        }
        
        // Notify listeners
        for listener in self.listeners.read().await.iter() {
            listener(node_info.clone());
        }
        
        Ok(())
    }
    
    async fn set_discovery_listener(&self, listener: DiscoveryListener) -> Result<()> {
        self.listeners.write().await.push(listener);
        Ok(())
    }
    
    async fn start_announcing(&self ) -> Result<()> {
        Ok(())
    }
    
    async fn stop_announcing(&self) -> Result<()> {
        // Implementation not needed for tests
        Ok(())
    }
    
    async fn update_node(&self, _node_info: NodeInfo) -> Result<()> {
        // Implementation not needed for tests
        Ok(())
    }
    
    async fn discover_nodes(&self, network_id: Option<&str>) -> Result<Vec<NodeInfo>> {
        let nodes = self.nodes.read().await;
        
        if let Some(id) = network_id {
            if let Some(network_nodes) = nodes.get(id) {
                Ok(network_nodes.clone())
            } else {
                Ok(Vec::new())
            }
        } else {
            // Collect all nodes from all networks
            let mut all_nodes = Vec::new();
            for nodes_vec in nodes.values() {
                all_nodes.extend(nodes_vec.clone());
            }
            Ok(all_nodes)
        }
    }
    
    async fn find_node(&self, _network_id: &str, node_id: &str) -> Result<Option<NodeInfo>> {
        let nodes = self.nodes.read().await;
        
        for network_nodes in nodes.values() {
            if let Some(node) = network_nodes.iter()
                .find(|node| node.peer_id.node_id == node_id) {
                return Ok(Some(node.clone()));
            }
        }
        
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;
    
    #[tokio::test]
    async fn test_transport_send_message() -> Result<()> {
        let transport = MockTransport::new("unused_network", "node-1");
        
        let topic = "test/service/action".to_string();
        let correlation_id = "test-correlation-id".to_string();
        let params = ValueType::String("test params".to_string());
        let message = NetworkMessage {
            source: PeerId::new("node-1".to_string()),
            destination: PeerId::new("node-2".to_string()),
            message_type: "Request".to_string(),
            payloads: vec![(topic.clone(), params.clone(), correlation_id.clone())],
        };
        
        transport.send_message(message.clone()).await?;

        let sent_messages = transport.get_sent_messages().await;
        assert_eq!(sent_messages.len(), 1);
        assert_eq!(sent_messages[0].message_type, "Request");
        assert_eq!(sent_messages[0].payloads.len(), 1);
        assert_eq!(sent_messages[0].payloads[0].0, topic);
        assert_eq!(sent_messages[0].payloads[0].1, params);
        assert_eq!(sent_messages[0].payloads[0].2, correlation_id);
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_discovery_register_node() -> Result<()> {
        let discovery = MockDiscovery::new();
        let (tx, mut rx) = mpsc::channel::<NodeInfo>(10);
        
        // Set a discovery listener
        discovery.set_discovery_listener(Box::new(move |node_info| {
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = tx.send(node_info).await {
                    eprintln!("Channel send error: {}", e);
                }
            });
        })).await?;
        
        let node_info = NodeInfo {
            peer_id: PeerId::new("node-1".to_string()),
            network_ids: vec!["test-network".to_string()],
            addresses: vec!["localhost:8080".to_string()],
            capabilities: vec![
                ServiceMetadata {
                    name: "test-service".to_string(),
                    version: "1.0.0".to_string(),
                    description: "Test service for unit tests".to_string(),
                    actions: vec![
                        ActionMetadata {
                            name: "request".to_string(),
                            description: "Test request".to_string(),
                            input_schema: None,
                            output_schema: None,
                        }
                    ],
                    events: vec![
                        EventMetadata {
                            name: "event".to_string(),
                            description: "Test event".to_string(),
                            data_schema: None,
                        }
                    ],
                }
            ],
            last_seen: SystemTime::now(),
        };
        
        // Register node
        discovery.register_node(node_info.clone()).await?;
        
        // Check if listener was notified
        if let Some(received_node_info) = rx.recv().await {
            assert_eq!(received_node_info.peer_id.public_key, "node-1");
            assert_eq!(received_node_info.addresses, vec!["localhost:8080".to_string()]);
        } else {
            return Err(anyhow!("Discovery listener was not notified"));
        }
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_transport_handler() -> Result<()> {
        // Create a channel
        let (tx, mut rx) = mpsc::channel(10);
        
        // Use new PeerId constructor
        let mut transport = MockTransport::new("unused_network", "node-1");
        
        // Set message sink
        transport.set_message_sink(tx);
        
        // Create a test message using new NetworkMessage structure
        let topic = "test/service/action".to_string();
        let correlation_id = "test-correlation-id".to_string();
        let params = ValueType::String("test params".to_string());
        let message = NetworkMessage {
            source: PeerId::new("node-2".to_string()),
            destination: PeerId::new("node-1".to_string()),
            message_type: "Request".to_string(),
            payloads: vec![(topic.clone(), params.clone(), correlation_id.clone())],
        };
        
        // Send the message using send_message
        transport.send_message(message.clone()).await?;
        
        // Check if the message was received through the channel
        if let Some(received) = rx.recv().await {
            assert_eq!(received.source.node_id, "node-2");
            assert_eq!(received.message_type, "Request");
            // Check payload instead of old correlation_id field
            assert_eq!(received.payloads.len(), 1);
            assert_eq!(received.payloads[0].2, correlation_id);
        } else {
            return Err(anyhow!("No message received"));
        }
        
        Ok(())
    }
} 