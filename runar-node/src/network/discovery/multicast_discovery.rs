// Multicast-based Node Discovery
//
// INTENTION: Provide an implementation of the NodeDiscovery trait that uses
// UDP multicast to discover nodes on the local network. This implementation
// periodically broadcasts announcements and listens for announcements from
// other nodes.

// Standard library imports
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use core::fmt;
use prost::Message;
use runar_common::compact_ids::compact_id;
use runar_common::logging::{Component, Logger};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::vec;
use tokio::net::UdpSocket;
use tokio::sync::{
    mpsc::{self, Sender},
    Mutex, RwLock,
};
use tokio::task::JoinHandle;
use tokio::time;

// Internal imports
use super::{DiscoveryListener, DiscoveryOptions, NodeDiscovery, NodeInfo};

// Default multicast address and port
const DEFAULT_MULTICAST_PORT: u16 = 45678;

/// Unique identifier for a node in the network
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Message)]
pub struct PeerInfo {
    #[prost(bytes, tag = "1")]
    pub public_key: Vec<u8>,
    #[prost(string, repeated, tag = "2")]
    pub addresses: Vec<String>,
}

impl PeerInfo {
    /// Create a new NodeIdentifier
    pub fn new(public_key: Vec<u8>, addresses: Vec<String>) -> Self {
        Self {
            public_key,
            addresses,
        }
    }
}

impl fmt::Display for PeerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addresses = self.addresses.join(", ");
        let node_id = compact_id(&self.public_key);
        write!(f, "{node_id} {addresses}")
    }
}

// Message formats for multicast communication
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct MulticastMessage {
    #[prost(message, optional, tag = "1")]
    pub announce: Option<PeerInfo>,
    #[prost(string, optional, tag = "2")]
    pub goodbye: Option<String>,
}

impl MulticastMessage {
    // Helper to get the sender ID if the message contains it
    fn sender_id(&self) -> Option<String> {
        if let Some(peer_info) = &self.announce {
            Some(compact_id(&peer_info.public_key))
        } else {
            self.goodbye.clone()
        }
    }
}

// Define DiscoveryCallback type alias for clarity
// type DiscoveryCallback = Box<dyn Fn(NodeInfo) + Send + Sync>;

/// Multicast-based node discovery implementation
pub struct MulticastDiscovery {
    options: Arc<RwLock<DiscoveryOptions>>,
    discovered_nodes: Arc<RwLock<HashMap<String, PeerInfo>>>,
    local_node: Arc<RwLock<Option<NodeInfo>>>,
    socket: Arc<UdpSocket>,
    listeners: Arc<RwLock<Vec<DiscoveryListener>>>,
    tx: Arc<Mutex<Option<Sender<MulticastMessage>>>>,
    // Task fields
    announce_task: Mutex<Option<JoinHandle<()>>>,
    cleanup_task: Mutex<Option<JoinHandle<()>>>,
    // Multicast address field
    multicast_addr: Arc<Mutex<SocketAddr>>,
    // Logger
    logger: Logger,
}

impl MulticastDiscovery {
    /// Create a new multicast discovery instance
    pub async fn new(
        local_node: NodeInfo,
        options: DiscoveryOptions,
        logger: Logger,
    ) -> Result<Self> {
        // Parse multicast group - handle both formats: "239.255.42.98" and "239.255.42.98:45678"
        let (multicast_addr, port) = if options.multicast_group.contains(':') {
            // Parse as a SocketAddr "IP:PORT"
            let addr: SocketAddr = options
                .multicast_group
                .parse()
                .map_err(|e| anyhow!("Invalid multicast address format: {}", e))?;
            (addr.ip(), addr.port())
        } else {
            // Parse as just an IP, use default port
            let ip: Ipv4Addr = options
                .multicast_group
                .parse()
                .map_err(|e| anyhow!("Invalid multicast address: {}", e))?;
            (IpAddr::V4(ip), DEFAULT_MULTICAST_PORT)
        };

        // Ensure it's a valid multicast address
        if let IpAddr::V4(ipv4) = multicast_addr {
            if !ipv4.is_multicast() {
                return Err(anyhow!("Not a valid multicast IPv4 address: {}", ipv4));
            }
        } else {
            return Err(anyhow!("Multicast address must be IPv4"));
        }

        // Create socket address
        let socket_addr = SocketAddr::new(multicast_addr, port);

        // Create UDP socket with proper configuration
        let socket = Self::create_multicast_socket(socket_addr, &logger).await?;
        logger.info(format!(
            "Successfully created multicast socket with address: {socket_addr}",
        ));

        // Create a Network component logger
        let discovery_logger = logger.with_component(Component::Network);

        let instance = Self {
            options: Arc::new(RwLock::new(options)),
            discovered_nodes: Arc::new(RwLock::new(HashMap::new())),
            local_node: Arc::new(RwLock::new(Some(local_node))),
            socket: Arc::new(socket),
            listeners: Arc::new(RwLock::new(Vec::new())),
            tx: Arc::new(Mutex::new(None)),
            multicast_addr: Arc::new(Mutex::new(socket_addr)),
            announce_task: Mutex::new(None),
            cleanup_task: Mutex::new(None),
            logger: discovery_logger,
        };

        // Initialize the tasks
        instance.start_listener_task();

        // Call start_sender_task and store results
        let (_sender_handle, tx) = instance.start_sender_task();
        *instance.tx.lock().await = Some(tx);

        // Start cleanup task
        let cleanup_handle = instance.start_cleanup_task(
            Arc::clone(&instance.discovered_nodes),
            instance.options.read().await.node_ttl,
        );
        *instance.cleanup_task.lock().await = Some(cleanup_handle);

        Ok(instance)
    }

    /// Create and configure a multicast socket
    async fn create_multicast_socket(addr: SocketAddr, logger: &Logger) -> Result<UdpSocket> {
        // Extract IP and port
        let multicast_ip = match addr.ip() {
            IpAddr::V4(ip) => ip,
            _ => return Err(anyhow!("Only IPv4 multicast is supported")),
        };

        let port = addr.port();

        // Create a socket with socket2 for low-level configuration
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        // Configure socket for multicast
        socket.set_reuse_address(true)?;

        // On some platforms, set_reuse_port may not be available, try it but don't fail if not
        #[cfg(unix)]
        let _ = socket.set_reuse_port(true);

        // Set multicast TTL (how many network hops multicast packets can traverse)
        socket.set_multicast_ttl_v4(2)?;

        // Allow loopback (receive our own multicast packets)
        socket.set_multicast_loop_v4(true)?;

        // Bind to the port with any address (0.0.0.0)
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        socket.bind(&bind_addr.into())?;

        // Join the multicast group
        socket.join_multicast_v4(&multicast_ip, &Ipv4Addr::UNSPECIFIED)?;

        // Convert to std socket and then to tokio socket
        let std_socket: std::net::UdpSocket = socket.into();
        std_socket.set_nonblocking(true)?;

        // Create tokio UDP socket
        let udp_socket = UdpSocket::from_std(std_socket)?;

        logger.info(format!(
            "Created multicast socket bound to {}:{} and joined multicast group {}",
            Ipv4Addr::UNSPECIFIED,
            port,
            multicast_ip
        ));

        Ok(udp_socket)
    }

    /// Start the receive task for listening to multicast messages
    fn start_listener_task(&self) -> JoinHandle<()> {
        let socket = Arc::clone(&self.socket);
        let discovered_nodes = Arc::clone(&self.discovered_nodes);
        let listeners = Arc::clone(&self.listeners);
        let local_node = Arc::clone(&self.local_node);
        let socket_for_process = Arc::clone(&self.socket);
        let logger = self.logger.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];

            // Get local node info once, outside the loop
            let local_node_guard = local_node.read().await;
            let local_peer_node_id = if let Some(info) = local_node_guard.as_ref() {
                compact_id(&info.node_public_key)
            } else {
                logger.error("No local node information available for announcement".to_string());
                return;
            };
            drop(local_node_guard);

            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        logger.debug(format!(
                            "Received multicast message from {src}, size: {len}",
                        ));
                        match MulticastMessage::decode(&buf[..len]) {
                            Ok(message) => {
                                // Use helper method to check sender ID
                                let mut skip = false;
                                if let Some(sender_node_id) = message.sender_id() {
                                    if *sender_node_id == local_peer_node_id {
                                        skip = true; // Skip message from self
                                        logger.debug("Skipping message from self".to_string());
                                    }
                                }
                                if !skip {
                                    Self::process_message(
                                        message,
                                        src,
                                        &discovered_nodes,
                                        &listeners,
                                        &socket_for_process,
                                        &local_node,
                                        &logger,
                                    )
                                    .await;
                                }
                            }
                            Err(e) => logger
                                .error(format!("Failed to deserialize multicast message: {e}")),
                        }
                    }
                    Err(e) => {
                        logger.error(format!("Failed to receive multicast message: {e}"));
                        // Brief pause to avoid tight loop on error
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        })
    }

    /// Start the announce task for periodically announcing our presence
    fn start_announce_task(
        &self,
        tx: Sender<MulticastMessage>,
        info: NodeInfo,
        interval: Duration,
    ) -> JoinHandle<()> {
        let logger = self.logger.clone();

        tokio::spawn(async move {
            let mut ticker = time::interval(interval);

            let peer_info = PeerInfo::new(info.node_public_key, info.addresses.clone());

            loop {
                ticker.tick().await;

                // Send announcement
                logger.debug(format!(
                    "Sending announcement for node {peer_node_id}",
                    peer_node_id = compact_id(&peer_info.public_key)
                ));

                if tx
                    .send(MulticastMessage {
                        announce: Some(peer_info.clone()),
                        goodbye: None,
                    })
                    .await
                    .is_err()
                {
                    logger
                        .warn("Failed to send periodic announcement, channel closed.".to_string());
                    break; // Stop task if channel is closed
                }
            }
        })
    }

    /// Start a task that periodically cleans up stale nodes
    fn start_cleanup_task(
        &self,
        nodes: Arc<RwLock<HashMap<String, PeerInfo>>>,
        ttl: Duration,
    ) -> JoinHandle<()> {
        let logger = self.logger.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60)); // Check every 60s
            loop {
                interval.tick().await;
                Self::cleanup_stale_nodes(&nodes, ttl, &logger).await;
            }
        })
    }

    /// Helper function to clean up stale nodes
    async fn cleanup_stale_nodes(
        _nodes: &Arc<RwLock<HashMap<String, PeerInfo>>>,
        _ttl: Duration,
        logger: &Logger,
    ) {
        // Implementation is simplified since we don't track last_seen in DiscoveryMessage
        // This is a placeholder to satisfy the call in start_cleanup_task
        logger
            .debug("Cleanup stale nodes called - not implemented for DiscoveryMessage".to_string());
        // In a complete implementation, we would:
        // 1. Iterate through all nodes
        // 2. Remove those whose last_seen is older than now - ttl
    }

    /// Task to send outgoing messages (announcements, requests)
    fn start_sender_task(&self) -> (JoinHandle<()>, Sender<MulticastMessage>) {
        let (tx, mut rx) = mpsc::channel::<MulticastMessage>(100);
        let socket = Arc::clone(&self.socket);
        let local_node = Arc::clone(&self.local_node);
        let multicast_addr_arc = Arc::clone(&self.multicast_addr);
        let logger = self.logger.clone();

        let task: JoinHandle<()> = tokio::spawn(async move {
            let target_addr = *multicast_addr_arc.lock().await;

            // Get local node info once, outside the loop
            let local_node_guard = local_node.read().await;
            let local_node_info = match local_node_guard.as_ref() {
                Some(info) => info.clone(),
                None => {
                    logger.error("No local node information available".to_string());
                    return;
                }
            };
            drop(local_node_guard);

            while let Some(mut message) = rx.recv().await {
                // Update announce message with our local info
                if let Some(ref mut discovery_msg) = message.announce {
                    discovery_msg.public_key = local_node_info.node_public_key.clone();
                    discovery_msg.addresses = local_node_info.addresses.clone();
                }
                // Update goodbye message with our local ID
                if let Some(ref mut id) = message.goodbye {
                    *id = compact_id(&local_node_info.node_public_key);
                }

                let mut data = Vec::new();
                match message.encode(&mut data) {
                    Ok(_) => {
                        logger.debug(format!(
                            "Sending multicast message to {}, size: {}",
                            target_addr,
                            data.len()
                        ));
                        if let Err(e) = socket.send_to(&data, target_addr).await {
                            logger.error(format!("Failed to send multicast message: {e}"));
                        }
                    }
                    Err(e) => logger.error(format!("Failed to serialize multicast message: {e}")),
                }
            }
        });

        (task, tx)
    }

    /// Process a received multicast message
    async fn process_message(
        message: MulticastMessage,
        src: SocketAddr,
        nodes: &Arc<RwLock<HashMap<String, PeerInfo>>>,
        listeners: &Arc<RwLock<Vec<DiscoveryListener>>>,
        socket: &Arc<UdpSocket>,
        local_node: &Arc<RwLock<Option<NodeInfo>>>,
        logger: &Logger,
    ) {
        // Get local node info once at the beginning
        let local_node_guard = local_node.read().await;
        let local_node_info = match local_node_guard.as_ref() {
            Some(info) => info.clone(),
            None => {
                logger.error(
                    "No local node information available for processing message".to_string(),
                );
                return;
            }
        };
        drop(local_node_guard);

        let local_peer_node_id = compact_id(&local_node_info.node_public_key);
        let local_addresses = local_node_info.addresses.clone();

        if let Some(peer_info) = &message.announce {
            // Announce: Store info and notify listeners
            let peer_node_id = compact_id(&peer_info.public_key);
            //ignore messages from self
            if local_peer_node_id == peer_node_id {
                return;
            }

            logger.debug(format!("Processing announce message from {peer_node_id}"));

            // Check if this is a new peer before responding
            let is_new_peer = {
                let nodes_read = nodes.read().await;
                !nodes_read.contains_key(&peer_node_id)
            };

            // Store the peer info - clone peer_public_key before using it outside this block
            {
                let mut nodes_write = nodes.write().await;
                nodes_write.insert(peer_node_id.clone(), peer_info.clone());
            }

            // Notify listeners
            {
                let listeners_read = listeners.read().await;
                for listener in listeners_read.iter() {
                    let fut = listener(peer_info.clone());
                    fut.await;
                }
            }

            // Only respond if this is a new peer we haven't seen before
            if is_new_peer {
                // Build a discovery message with our own info
                let local_info_msg = PeerInfo::new(
                    local_node_info.node_public_key.clone(),
                    local_addresses.clone(),
                );

                logger.debug(format!(
                    "Auto-responding to new peer announcement with our own info: {local_peer_node_id}"
                ));
                let response_msg = MulticastMessage {
                    announce: Some(local_info_msg),
                    goodbye: None,
                };
                let mut data = Vec::new();
                if response_msg.encode(&mut data).is_ok() {
                    // Small delay to avoid collision
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    // Respond directly to the sender
                    if let Err(e) = socket.send_to(&data, src).await {
                        logger.error(format!("Failed to send auto-response to {src}: {e}"));
                    }
                }
            } else {
                logger.debug(format!(
                    "Skipping auto-response for already known peer: {peer_node_id}"
                ));
            }
        } else if let Some(identifier) = &message.goodbye {
            // Goodbye: Remove node
            logger.debug(format!("Processing goodbye message from {identifier}"));
            let key = identifier.to_string();
            let mut nodes_write = nodes.write().await;
            nodes_write.remove(&key);
        } else {
            // No message content
            logger.warn("Received multicast message with no content".to_string());
        }
    }
}

#[async_trait]
impl NodeDiscovery for MulticastDiscovery {
    async fn init(&self, options: DiscoveryOptions) -> Result<()> {
        self.logger.info(format!(
            "Initializing MulticastDiscovery with options: {options:?}"
        ));
        // Update options
        *self.options.write().await = options.clone();

        // Re-parse the multicast address from options to ensure it's valid
        let (multicast_addr, port) = if options.multicast_group.contains(':') {
            // Parse as a SocketAddr "IP:PORT"
            let addr: SocketAddr = options
                .multicast_group
                .parse()
                .map_err(|e| anyhow!("Invalid multicast address format: {e}"))?;
            (addr.ip(), addr.port())
        } else {
            // Parse as just an IP, use default port
            let ip: Ipv4Addr = options
                .multicast_group
                .parse()
                .map_err(|e| anyhow!("Invalid multicast address: {e}"))?;
            (IpAddr::V4(ip), DEFAULT_MULTICAST_PORT)
        };

        // Create valid socket address and store it
        let socket_addr = SocketAddr::new(multicast_addr, port);
        *self.multicast_addr.lock().await = socket_addr;
        self.logger
            .info(format!("Using multicast address: {socket_addr}"));

        // Tasks are already initialized in the constructor, no need to duplicate here

        Ok(())
    }

    async fn start_announcing(&self) -> Result<()> {
        let local_info_guard = self.local_node.read().await;
        let local_info = match local_info_guard.as_ref() {
            Some(info) => info.clone(),
            None => {
                return Err(anyhow!(
                    "No local node information available for announcement"
                ))
            }
        };
        let local_peer_node_id = compact_id(&local_info.node_public_key);
        self.logger
            .info(format!("Starting to announce node: {local_peer_node_id}"));

        let tx_opt = self.tx.lock().await;
        let tx = match tx_opt.as_ref() {
            Some(tx_channel) => tx_channel.clone(),
            None => return Err(anyhow!("Discovery sender task not initialized")),
        };
        drop(tx_opt);

        let interval = {
            let options_guard = self.options.read().await;
            options_guard.announce_interval
        };

        // Send initial announcement and return Result
        self.logger.info("Sending initial announcement".to_string());

        // Create a discovery message from the NodeInfo
        let peer_info = PeerInfo::new(
            local_info.node_public_key.clone(),
            local_info.addresses.clone(),
        );

        tx.send(MulticastMessage {
            announce: Some(peer_info),
            goodbye: None,
        })
        .await
        .map_err(|e| anyhow!("Failed to send initial announcement: {e}"))?;

        let task = self.start_announce_task(tx.clone(), local_info.clone(), interval);
        *self.announce_task.lock().await = Some(task);

        Ok(())
    }

    async fn stop_announcing(&self) -> Result<()> {
        // Stop announce task
        if let Some(task) = self.announce_task.lock().await.take() {
            task.abort();
        }
        Ok(())
    }

    async fn set_discovery_listener(&self, listener: DiscoveryListener) -> Result<()> {
        self.logger.debug("Adding discovery listener".to_string());
        self.listeners.write().await.push(listener);
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        self.logger
            .info("Shutting down MulticastDiscovery".to_string());

        // Stop announcing if we are
        if let Err(e) = self.stop_announcing().await {
            self.logger
                .warn(format!("Error stopping announcements during shutdown: {e}"));
        }

        Ok(())
    }
}
