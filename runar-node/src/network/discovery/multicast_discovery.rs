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
use runar_common::compact_ids::compact_id;
use runar_common::logging::{Component, Logger};
use runar_macros_common::{log_debug, log_error, log_info, log_warn};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
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
use super::{DiscoveryEvent, DiscoveryListener, DiscoveryOptions, NodeDiscovery, NodeInfo};

// Default multicast address and port
const DEFAULT_MULTICAST_PORT: u16 = 45678;

/// Unique identifier for a node in the network
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerInfo {
    pub public_key: Vec<u8>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulticastMessage {
    pub announce: Option<PeerInfo>,
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
    local_node: Arc<RwLock<Option<NodeInfo>>>,
    socket: Arc<UdpSocket>,
    listeners: Arc<RwLock<Vec<DiscoveryListener>>>,
    tx: Arc<Mutex<Option<Sender<MulticastMessage>>>>,
    // Task fields
    announce_task: Mutex<Option<JoinHandle<()>>>,
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
        let logger = logger.with_component(Component::NetworkDiscovery);

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
        log_info!(logger, "Successfully created multicast socket with address: {socket_addr}");

        let instance = Self {
            options: Arc::new(RwLock::new(options)),
            local_node: Arc::new(RwLock::new(Some(local_node))),
            socket: Arc::new(socket),
            listeners: Arc::new(RwLock::new(Vec::new())),
            tx: Arc::new(Mutex::new(None)),
            multicast_addr: Arc::new(Mutex::new(socket_addr)),
            announce_task: Mutex::new(None),
            logger: logger.clone(),
        };

        // Initialize the tasks
        instance.start_listener_task();

        // Call start_sender_task and store results
        let (_sender_handle, tx) = instance.start_sender_task();
        *instance.tx.lock().await = Some(tx);

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

        log_info!(
            logger,
            "Created multicast socket bound to {}:{} and joined multicast group {}",
            Ipv4Addr::UNSPECIFIED,
            port,
            multicast_ip
        );

        Ok(udp_socket)
    }

    /// Start the receive task for listening to multicast messages
    fn start_listener_task(&self) -> JoinHandle<()> {
        let socket = Arc::clone(&self.socket);
        let local_node = Arc::clone(&self.local_node);
        let listeners = Arc::clone(&self.listeners);
        let logger = self.logger.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];

            // Get local node info once, outside the loop
            let local_node_guard = local_node.read().await;
            let local_peer_node_id = if let Some(info) = local_node_guard.as_ref() {
                compact_id(&info.node_public_key)
            } else {
                log_error!(logger, "No local node information available for announcement");
                return;
            };
            drop(local_node_guard);

            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        logger.debug(format!(
                            "Received multicast message from {src}, size: {len}",
                        ));
                        match serde_cbor::from_slice::<MulticastMessage>(&buf[..len]) {
                            Ok(message) => {
                                // Use helper method to check sender ID
                                let mut skip = false;
                                if let Some(sender_node_id) = message.sender_id() {
                                    if *sender_node_id == local_peer_node_id {
                                        skip = true; // Skip message from self
                        log_debug!(logger, "Skipping message from self");
                                    }
                                }
                                if !skip {
                                    Self::process_message(
                                        message,
                                        &local_node,
                                        &listeners,
                        &logger,
                                    )
                                    .await;
                                }
                            }
            Err(e) => log_error!(logger, "Failed to deserialize multicast message: {e}"),
                        }
                    }
                    Err(e) => {
        log_error!(logger, "Failed to receive multicast message: {e}");
                        // Brief pause to avoid tight loop on error
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        })
    }

    /// Start the announce task for periodically announcing our presence
    fn start_announce_task(&self, interval: Duration) -> JoinHandle<()> {
        let socket = Arc::clone(&self.socket);
        let multicast_addr = Arc::clone(&self.multicast_addr);
        let local_node = Arc::clone(&self.local_node);
        let logger = self.logger.clone();

        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);
            loop {
                interval_timer.tick().await;

                // Get local node info
                let local_node_info = match local_node.read().await.as_ref() {
                    Some(info) => info.clone(),
                    None => {
                        logger.warn("No local node info available for announcement");
                        continue;
                    }
                };

                // Create announcement message
                let peer_info = PeerInfo::new(
                    local_node_info.node_public_key.clone(),
                    local_node_info.addresses.clone(),
                );

                let message = MulticastMessage {
                    announce: Some(peer_info),
                    goodbye: None,
                };

                // Serialize and send
                match serde_cbor::to_vec(&message) {
                    Ok(data) => {
                        if let Err(e) = socket.send_to(&data, *multicast_addr.lock().await).await {
                            log_error!(logger, "Failed to send announcement: {e}");
                        }
                    }
                    Err(e) => log_error!(logger, "Failed to serialize announcement: {e}"),
                }
            }
        })
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
                    log_error!(logger, "No local node information available");
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

                match serde_cbor::to_vec(&message) {
                    Ok(data) => {
                        log_debug!(
                            logger,
                            "Sending multicast message to {}, size: {}",
                            target_addr,
                            data.len()
                        );
                        if let Err(e) = socket.send_to(&data, target_addr).await {
                            log_error!(logger, "Failed to send multicast message: {e}");
                        }
                    }
                    Err(e) => log_error!(logger, "Failed to serialize multicast message: {e}"),
                }
            }
        });

        (task, tx)
    }

    /// Process a received multicast message
    #[allow(clippy::too_many_arguments)]
    async fn process_message(
        message: MulticastMessage,
        local_node: &Arc<RwLock<Option<NodeInfo>>>,
        listeners: &Arc<RwLock<Vec<DiscoveryListener>>>,
        logger: &Logger,
    ) {
        // Skip if we don't have local node info
        let local_node_info = match local_node.read().await.as_ref() {
            Some(info) => info.clone(),
            None => {
                logger.warn("No local node info available for discovery");
                return;
            }
        };

        // Skip messages from ourselves
        if let Some(announce) = &message.announce {
            let sender_id = compact_id(&announce.public_key);
            let local_id = compact_id(&local_node_info.node_public_key);
            if sender_id == local_id {
                log_debug!(logger, "Ignoring discovery message from self");
                return;
            }
        }

        // Process the message and emit appropriate events
        match &message {
            MulticastMessage {
                announce: Some(peer_info),
                goodbye: None,
            } => {
                log_debug!(logger, "Processing announce message from peer");

                // Emit Discovered event to all listeners
                let listeners_read = listeners.read().await;
                for listener in listeners_read.iter() {
                    let event = DiscoveryEvent::Discovered(peer_info.clone());
                    let _ = listener(event).await;
                }
            }
            MulticastMessage {
                announce: None,
                goodbye: Some(identifier),
            } => {
                log_debug!(logger, "Processing goodbye message from {identifier}");

                // Emit Lost event to all listeners
                let listeners_read = listeners.read().await;
                for listener in listeners_read.iter() {
                    let event = DiscoveryEvent::Lost(identifier.clone());
                    let _ = listener(event).await;
                }
            }
            _ => {
                log_debug!(logger, "Ignoring malformed discovery message");
            }
        }
    }
}

#[async_trait]
impl NodeDiscovery for MulticastDiscovery {
    async fn init(&self, options: DiscoveryOptions) -> Result<()> {
        log_info!(
            self.logger,
            "Initializing MulticastDiscovery with options: {options:?}"
        );
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
        log_info!(self.logger, "Using multicast address: {socket_addr}");

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
        log_info!(self.logger, "Starting to announce node: {local_peer_node_id}");

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
        log_info!(self.logger, "Sending initial announcement");

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

        let task = self.start_announce_task(interval);
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

    async fn subscribe(&self, listener: DiscoveryListener) -> Result<()> {
        log_debug!(self.logger, "Adding discovery listener");
        self.listeners.write().await.push(listener);
        Ok(())
    }

    async fn update_local_node_info(&self, new_node_info: NodeInfo) -> Result<()> {
        let mut local_node_guard = self.local_node.write().await;
        *local_node_guard = Some(new_node_info);
        drop(local_node_guard);

        log_debug!(
            self.logger,
            "Updated local node information for multicast discovery"
        );
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        log_info!(self.logger, "Shutting down MulticastDiscovery");

        // Stop announcing if we are
        if let Err(e) = self.stop_announcing().await {
            log_warn!(
                self.logger,
                "Error stopping announcements during shutdown: {e}"
            );
        }

        Ok(())
    }

    // Stateless interface: no remove_discovered_peer
}
