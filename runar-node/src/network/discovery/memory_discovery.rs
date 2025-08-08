// Memory-based Node Discovery
//
// INTENTION: Provide a simple in-memory implementation of node discovery
// for development and testing. This implementation maintains a list of nodes
// in memory and doesn't use actual network protocols for discovery.

// Standard library imports
use anyhow::{anyhow, Result};
use runar_common::compact_ids::compact_id;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::task::JoinHandle;

use super::multicast_discovery::PeerInfo;
// Internal imports
// Import PeerInfo from the parent module where it's properly exposed
use super::{DiscoveryEvent, DiscoveryListener, DiscoveryOptions, NodeDiscovery, NodeInfo};
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
        let _listeners: Arc<RwLock<Vec<DiscoveryListener>>> = Arc::clone(&self.listeners);
        let logger = self.logger.clone();

        tokio::spawn(async move {
            let mut ticker = time::interval(interval);

            loop {
                ticker.tick().await;

                // In memory discovery, periodic announce is a no-op. We notify listeners only
                // on first-time discovery (see add_node_internal) or after explicit removal.
                logger.debug(format!(
                    "Periodic announce for local node: {} (no listener notification)",
                    compact_id(&node_info.node_public_key)
                ));
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
        let node_key = compact_id(&node_info.node_public_key);
        let is_new = {
            let nodes = self.nodes.read().unwrap();
            !nodes.contains_key(&node_key)
        };
        {
            let mut nodes = self.nodes.write().unwrap();
            nodes.insert(node_key.clone(), node_info.clone());
        }

        self.logger
            .debug(format!("Added node to registry: {node_key}"));

        let peer_info = PeerInfo {
            public_key: node_info.node_public_key.clone(),
            addresses: node_info.addresses.clone(),
        };

        // Notify listeners only on first discovery. Updates to existing entries
        // do not trigger notifications unless the entry was previously removed.
        if is_new {
            let listeners_vec = {
                let guard = self.listeners.read().unwrap();
                guard.clone()
            };
            drop(node_key); // ensure node_key is not used after this point
            for listener in listeners_vec {
                let fut = listener(DiscoveryEvent::Discovered(peer_info.clone()));
                fut.await;
            }
        }
    }
}

#[async_trait]
impl NodeDiscovery for MemoryDiscovery {
    async fn init(&self, options: DiscoveryOptions) -> Result<()> {
        self.logger.info(format!(
            "Initializing MemoryDiscovery with options: {options:?}"
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

        self.logger.info(format!(
            "Starting to announce node: {}",
            compact_id(&info.node_public_key)
        ));

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

        // Remove our node from the registry and notify Lost
        let local_info_opt = { self.local_node.read().unwrap().clone() };
        if let Some(info) = local_info_opt {
            let key = compact_id(&info.node_public_key);
            {
                let mut nodes_map = self.nodes.write().unwrap();
                nodes_map.remove(&key);
            }
            self.logger
                .debug(format!("Removed local node {key} from registry (emitting Lost)"));

            let listeners_vec = {
                let guard = self.listeners.read().unwrap();
                guard.clone()
            };
            for listener in listeners_vec {
                let fut = listener(DiscoveryEvent::Lost(key.clone()));
                fut.await;
            }
        }

        Ok(())
    }

    async fn subscribe(&self, listener: DiscoveryListener) -> Result<()> {
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

    async fn update_local_node_info(&self, new_node_info: NodeInfo) -> Result<()> {
        let mut local_node_guard = self.local_node.write().unwrap();
        *local_node_guard = Some(new_node_info);
        drop(local_node_guard);
        
        self.logger.debug("Updated local node information for memory discovery");
        Ok(())
    }

    // Stateless interface: no remove_discovered_peer
}
