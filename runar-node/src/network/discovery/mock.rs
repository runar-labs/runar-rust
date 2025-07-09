// Mock Node Discovery Implementation
//
// INTENTION: Provide a mock implementation of the NodeDiscovery trait for testing.

use anyhow::Result;
use async_trait::async_trait;
use runar_common::compact_ids::compact_id;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::{DiscoveryListener, DiscoveryOptions, NodeDiscovery, NodeInfo};

/// A mock implementation of NodeDiscovery that stores nodes in memory
pub struct MockNodeDiscovery {
    /// Known nodes
    nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    /// Listeners for discovery events
    listeners: Arc<RwLock<Vec<DiscoveryListener>>>, // DiscoveryListener is now Arc<...>
}

impl Default for MockNodeDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl MockNodeDiscovery {
    /// Create a new mock discovery instance
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            listeners: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a test node to the discovery service
    pub fn add_test_node(&self, node_info: NodeInfo) {
        let key = compact_id(&node_info.node_public_key);
        self.nodes.write().unwrap().insert(key, node_info);
    }

    /// Clear all nodes
    pub fn clear_nodes(&self) {
        self.nodes.write().unwrap().clear();
    }

    /// Helper to add nodes for testing
    pub async fn add_mock_node(&self, node_info: NodeInfo) {
        let key = compact_id(&node_info.node_public_key);
        self.nodes.write().unwrap().insert(key, node_info.clone());
        // Notify listeners
        let peer_info = crate::network::discovery::PeerInfo {
            public_key: node_info.node_public_key.clone(),
            addresses: node_info.addresses.clone(),
        };
        let listeners = {
            let guard = self.listeners.read().unwrap();
            guard.iter().cloned().collect::<Vec<_>>()
        };
        for listener in listeners {
            let fut = listener(peer_info.clone());
            fut.await;
        }
    }
}

#[async_trait]
impl NodeDiscovery for MockNodeDiscovery {
    async fn init(&self, _options: DiscoveryOptions) -> Result<()> {
        Ok(())
    }

    async fn start_announcing(&self) -> Result<()> {
        Ok(())
    }

    async fn stop_announcing(&self) -> Result<()> {
        Ok(())
    }

    async fn set_discovery_listener(&self, listener: DiscoveryListener) -> Result<()> {
        self.listeners.write().unwrap().push(listener);
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        self.nodes.write().unwrap().clear();
        Ok(())
    }
}
