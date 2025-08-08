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
    /// Last-seen timestamps per peer for TTL/Lost emission
    last_seen: Arc<RwLock<HashMap<String, SystemTime>>>,
    /// Debounce: last emit time per peer
    last_emitted: Arc<RwLock<HashMap<String, SystemTime>>>,
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
            last_seen: Arc::new(RwLock::new(HashMap::new())),
            last_emitted: Arc::new(RwLock::new(HashMap::new())),
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
        let last_seen = Arc::clone(&self.last_seen);
        let ttl = options.node_ttl;
        let debounce = options.debounce_window;
        let logger = self.logger.clone();
        let listeners = Arc::clone(&self.listeners);

        tokio::spawn(async move {
            let check_interval = if ttl <= Duration::from_millis(100) {
                Duration::from_millis(100)
            } else if ttl <= Duration::from_secs(1) {
                ttl
            } else {
                Duration::from_secs(1)
            };
            let mut interval = time::interval(check_interval);

            loop {
                interval.tick().await;
                Self::cleanup_stale_nodes(
                    &nodes,
                    &last_seen,
                    &listeners,
                    ttl,
                    debounce,
                    &logger,
                )
                .await;
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
    async fn cleanup_stale_nodes(
        nodes: &Arc<RwLock<HashMap<String, NodeInfo>>>,
        last_seen: &Arc<RwLock<HashMap<String, SystemTime>>>,
        listeners: &Arc<RwLock<Vec<DiscoveryListener>>>,
        ttl: Duration,
        _debounce: Duration,
        logger: &Logger,
    ) {
        let now = SystemTime::now();
        let stale_keys: Vec<String> = {
            let seen = last_seen.read().unwrap();
            seen.iter()
                .filter_map(|(peer_id, ts)| match now.duration_since(*ts) {
                    Ok(elapsed) if elapsed > ttl => Some(peer_id.clone()),
                    _ => None,
                })
                .collect()
        };
        if stale_keys.is_empty() {
            return;
        }
        let listeners_vec = { listeners.read().unwrap().clone() };
        for key in stale_keys {
            logger.debug(format!("[memory_discovery] TTL expired for {key}, emitting Lost"));
            nodes.write().unwrap().remove(&key);
            last_seen.write().unwrap().remove(&key);
            for listener in &listeners_vec {
                let fut = listener(DiscoveryEvent::Lost(key.clone()));
                fut.await;
            }
        }
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
        // do not trigger notifications unless debounced window has elapsed.
        let mut should_emit = is_new;
        if !is_new {
            // debounce Updated
            let mut emitted = self.last_emitted.write().unwrap();
            let now = SystemTime::now();
            let last = emitted.get(&node_key).cloned();
            let debounce = self
                .options
                .read()
                .unwrap()
                .as_ref()
                .map(|o| o.debounce_window)
                .unwrap_or(Duration::from_millis(400));
            if last.map(|t| now.duration_since(t).unwrap_or_default() >= debounce) != Some(false) {
                should_emit = true;
                emitted.insert(node_key.clone(), now);
            }
        } else {
            self.last_emitted
                .write()
                .unwrap()
                .insert(node_key.clone(), SystemTime::now());
        }
        // update last_seen
        self.last_seen
            .write()
            .unwrap()
            .insert(node_key.clone(), SystemTime::now());

        if should_emit {
            let addresses_len = node_info.addresses.len();
            let event_label = if is_new { "Discovered" } else { "Updated" };
            self.logger.debug(format!(
                "📣 [discovery] provider=memory event={event_label} peer_id={node_key} addresses={addresses_len} debounced={}",
                !is_new
            ));
            let listeners_vec = {
                let guard = self.listeners.read().unwrap();
                guard.clone()
            };
            drop(node_key); // ensure node_key is not used after this point
            for listener in listeners_vec {
                let fut = listener(if is_new {
                    DiscoveryEvent::Discovered(peer_info.clone())
                } else {
                    DiscoveryEvent::Updated(peer_info.clone())
                });
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
