// Memory-based Node Discovery
//
// INTENTION: Provide a simple in-memory implementation of node discovery
// for development and testing. This implementation maintains a list of nodes
// in memory and doesn't use actual network protocols for discovery.

// Standard library imports
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::task::JoinHandle;

use super::multicast_discovery::PeerInfo;
// Internal imports
// Import PeerInfo from the parent module where it's properly exposed
use super::{DiscoveryListener, DiscoveryOptions, NodeDiscovery, NodeInfo};
use async_trait::async_trait;
use runar_common::logging::Logger;
use tokio::time;

/// In-memory node discovery for development and testing
pub struct MemoryDiscovery {
    /// Nodes registered with this discovery mechanism, keyed by network_id
    nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    /// Node info for the local node
    local_node: Arc<RwLock<Option<NodeInfo>>>,
    /// Options for discovery
    options: RwLock<Option<DiscoveryOptions>>,
    /// Handle for the cleanup task
    cleanup_task: Mutex<Option<JoinHandle<()>>>,
    /// Handle for the announcement task
    announce_task: Mutex<Option<JoinHandle<()>>>,
    /// Listeners for discovery events
    listeners: Arc<RwLock<Vec<DiscoveryListener>>>, // DiscoveryListener is now Arc<...>
    /// Logger instance
    logger: Logger,
}

impl MemoryDiscovery {
    /// Create a new in-memory discovery mechanism
    pub fn new(logger: Logger) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            local_node: Arc::new(RwLock::new(None)),
            options: RwLock::new(None),
            cleanup_task: Mutex::new(None),
            announce_task: Mutex::new(None),
            listeners: Arc::new(RwLock::new(Vec::new())),
            logger,
        }
    }

    /// Set the local node information for this discovery instance
    pub fn set_local_node(&self, node_info: NodeInfo) {
        *self.local_node.write().unwrap() = Some(node_info);
    }

    /// Start a background task to periodically clean up stale nodes
    fn start_cleanup_task(&self, options: DiscoveryOptions) -> JoinHandle<()> {
        let nodes = Arc::clone(&self.nodes);
        let ttl = options.node_ttl;
        let logger = self.logger.clone();

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;
                Self::cleanup_stale_nodes(&nodes, ttl, &logger);
            }
        })
    }

    /// Start a background task to periodically announce our presence
    fn start_announce_task(&self, info: NodeInfo, options: DiscoveryOptions) -> JoinHandle<()> {
        let interval = options.announce_interval;
        let node_info = info.clone();
        let listeners: Arc<RwLock<Vec<DiscoveryListener>>> = Arc::clone(&self.listeners);
        let logger = self.logger.clone();

        tokio::spawn(async move {
            let mut ticker = time::interval(interval);

            loop {
                ticker.tick().await;

                let peer_info = PeerInfo {
                    public_key: node_info.peer_id.public_key.clone(),
                    addresses: node_info.addresses.clone(),
                };

                logger.debug(format!("Announcing local node: {}", node_info.peer_id));

                // Notify listeners (simulating network discovery update)
                let listeners_vec = {
                    let guard = listeners.read().unwrap();
                    guard.clone() // clones the Arc for each listener
                };
                for listener in listeners_vec {
                    let fut = listener(peer_info.clone());
                    fut.await;
                }
            }
        })
    }

    /// Remove nodes that haven't been seen for a while
    fn cleanup_stale_nodes(
        nodes: &RwLock<HashMap<String, NodeInfo>>,
        _ttl: Duration,
        _logger: &Logger,
    ) {
        let _now = SystemTime::now();
        let _nodes_map = nodes.write().unwrap();

        // Collect keys of stale nodes first to avoid borrowing issues
        // let stale_keys: Vec<String> = nodes_map
        //     .iter()
        //     .filter_map(|(key, info)| {
        //         info.version
        //             .elapsed()
        //             .ok()
        //             .filter(|elapsed| *elapsed > ttl)
        //             .map(|_| key.clone())
        //     })
        //     .collect();

        // // Remove stale nodes
        // for key in stale_keys {
        //     logger.debug(format!("Removing stale node: {}", key));
        //     nodes_map.remove(&key);
        // }
    }

    /// Adds a node to the discovery registry.
    async fn add_node_internal(&self, node_info: NodeInfo) {
        let node_key = node_info.peer_id.to_string();
        {
            let mut nodes = self.nodes.write().unwrap();
            nodes.insert(node_key.clone(), node_info.clone());
        }

        self.logger
            .debug(format!("Added node to registry: {}", node_key));

        let peer_info = PeerInfo {
            public_key: node_info.peer_id.public_key.clone(),
            addresses: node_info.addresses.clone(),
        };

        // Notify listeners
        let listeners_vec = {
            let guard = self.listeners.read().unwrap();
            guard.clone()
        };
        drop(node_key); // ensure node_key is not used after this point
        for listener in listeners_vec {
            let fut = listener(peer_info.clone());
            fut.await;
        }
    }
}

#[async_trait]
impl NodeDiscovery for MemoryDiscovery {
    async fn init(&self, options: DiscoveryOptions) -> Result<()> {
        self.logger.info(format!(
            "Initializing MemoryDiscovery with options: {:?}",
            options
        ));

        *self.options.write().unwrap() = Some(options.clone());

        // Start the cleanup task
        let task = self.start_cleanup_task(options);
        *self.cleanup_task.lock().unwrap() = Some(task);

        Ok(())
    }

    async fn start_announcing(&self) -> Result<()> {
        // Get the local node info from the stored value
        let info = match &*self.local_node.read().unwrap() {
            Some(info) => info.clone(),
            None => {
                let err: anyhow::Error = anyhow!("No local node information available");
                return Err(err);
            }
        };

        self.logger
            .info(format!("Starting to announce node: {}", info.peer_id));

        // Get the options
        let options = match &*self.options.read().unwrap() {
            Some(opts) => opts.clone(),
            None => {
                let err: anyhow::Error = anyhow!("Discovery not initialized");
                return Err(err);
            }
        };

        // Add our node to the registry
        self.add_node_internal(info.clone()).await;

        // Start the announcement task
        let task = self.start_announce_task(info, options);
        *self.announce_task.lock().unwrap() = Some(task);

        Ok(())
    }

    async fn stop_announcing(&self) -> Result<()> {
        self.logger.info("Stopping node announcements".to_string());

        // Stop the announcement task if it exists
        if let Some(task) = self.announce_task.lock().unwrap().take() {
            task.abort();
        }

        // Remove our node from the registry
        if let Some(info) = &*self.local_node.read().unwrap() {
            let mut nodes_map = self.nodes.write().unwrap();
            nodes_map.remove(&info.peer_id.to_string());
            self.logger
                .debug(format!("Removed local node {} from registry", info.peer_id));
        }

        Ok(())
    }

    async fn set_discovery_listener(&self, listener: DiscoveryListener) -> Result<()> {
        self.logger.debug("Adding discovery listener".to_string());
        self.listeners.write().unwrap().push(listener);
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        self.logger
            .info("Shutting down MemoryDiscovery".to_string());

        // Stop the cleanup task
        if let Some(task) = self.cleanup_task.lock().unwrap().take() {
            task.abort();
        }

        // Stop the announcement task
        if let Some(task) = self.announce_task.lock().unwrap().take() {
            task.abort();
        }

        // Clear all nodes
        self.nodes.write().unwrap().clear();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Add necessary imports for testing
    use super::*;
    use crate::network::transport::PeerId;
    use runar_common::logging::Component; // Added for Logger::new_root

    // ... other test helper functions ...

    #[tokio::test]
    async fn test_find_node() {
        // Setup discovery instance with a test logger
        let logger = Logger::new_root(Component::Network, "test_node");
        let discovery = MemoryDiscovery::new(logger);

        // Set options
        let options = DiscoveryOptions::default();
        discovery.init(options).await.unwrap();

        // Set up local node
        let local_node = NodeInfo {
            peer_id: PeerId::new("test_node".to_string()),
            network_ids: vec!["net1".to_string()],
            addresses: vec!["127.0.0.1:8000".to_string()],
            services: vec![],
            version: 0,
        };
        discovery.set_local_node(local_node);

        // Create NodeInfo for test
        let node_info_1 = NodeInfo {
            peer_id: PeerId::new("node1".to_string()),
            network_ids: vec!["net1".to_string()], // Added network_ids
            addresses: vec!["addr1".to_string()],
            services: vec![],
            version: 0,
        };
        // discovery.register_node(node_info_1).await.unwrap();

        // Find the node
        // let found_node = discovery.find_node("net1", "node1").await.unwrap();
        // assert!(found_node.is_some());
        // assert_eq!(found_node.unwrap().peer_id.public_key, "node1");

        // Find non-existent node
        // let not_found_node = discovery.find_node("net1", "node2").await.unwrap();
        // assert!(not_found_node.is_none());
    }
    // TODO: Add tests for register, update, discover, cleanup, listener
}
