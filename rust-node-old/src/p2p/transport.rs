use crate::p2p::crypto::{AccessToken, Crypto, NetworkId, PeerId};
use crate::p2p::peer::{NetworkInfo, Peer};
use crate::services::remote::P2PTransport as P2PTransportTrait;
use crate::services::ServiceResponse;
use crate::services::types::ValueType;
use runar_common::utils::logging::{debug_log, error_log, info_log, warn_log, Component};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, RwLock};
use uuid;

/// Configuration for P2P transport
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Network ID
    pub network_id: String,
    /// Path to store state
    pub state_path: String,
    /// Bootstrap nodes to connect to on startup
    pub bootstrap_nodes: Option<Vec<String>>,
    /// Listen address for incoming connections
    pub listen_addr: Option<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        TransportConfig {
            network_id: "default".to_string(),
            state_path: ".".to_string(),
            bootstrap_nodes: None,
            listen_addr: None,
        }
    }
}

/// Message types for P2P communication
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum P2PMessage {
    /// Service request message
    Request {
        /// Unique request ID for correlation
        request_id: String,
        /// Service path
        path: String,
        /// Request parameters
        params: ValueType,
        /// Optional metadata for additional context
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<HashMap<String, ValueType>>,
    },
    /// Service response message
    Response {
        /// Unique request ID for correlation
        request_id: String,
        /// Response data
        response: ServiceResponse,
        /// Optional metadata for additional context
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<HashMap<String, ValueType>>,
    },
    /// Event message
    Event {
        /// Topic of the event
        topic: String,
        /// Event data
        data: ValueType,
        /// Optional metadata for additional context
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<HashMap<String, ValueType>>,
    },
    /// Service discovery message
    ServiceDiscovery {
        /// Services available on the peer
        services: Vec<P2PServiceInfo>,
        /// Optional metadata for additional context
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<HashMap<String, ValueType>>,
    },
    /// Connection notification message
    ConnectNotification {
        /// The peer ID of the connecting peer
        peer_id: PeerId,
        /// The address of the connecting peer
        address: String,
        /// Optional metadata for additional context
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<HashMap<String, ValueType>>,
    },
}

/// Service information for P2P discovery
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct P2PServiceInfo {
    /// Service name
    pub name: String,
    /// Service path
    pub path: String,
    /// Available operations
    pub operations: Vec<String>,
}

/// P2P Transport for communication with other peers
pub struct P2PTransport {
    /// The peer itself (contains connections)
    pub peer: Arc<RwLock<Peer>>,

    /// Queue for message handling
    message_receiver: Arc<RwLock<Option<mpsc::Receiver<(PeerId, Vec<u8>)>>>>,

    /// Current peer ID
    pub peer_id: Arc<PeerId>,

    /// Pending requests waiting for responses
    pending_requests: Arc<RwLock<HashMap<String, oneshot::Sender<ServiceResponse>>>>,

    /// The network ID
    network_id: NetworkId,

    /// Callback to get local services for sharing with peers
    get_local_services_callback:
        Arc<RwLock<Option<Box<dyn Fn() -> BoxFuture<'static, Vec<P2PServiceInfo>> + Send + Sync>>>>,
}

impl P2PTransport {
    pub async fn new(config: TransportConfig, fixed_network_id: Option<&str>) -> Result<Self> {
        info_log(
            Component::P2P,
            &format!("Creating P2P transport for network {}", config.network_id),
        )
        .await;

        let (sender, receiver) = mpsc::channel(100);

        // Use our utility function to generate a keypair
        let keypair = Crypto::generate_keypair();
        let peer_id = PeerId::from_public_key(&keypair.public);

        // Clone the peer_id for caching
        let peer_id_clone = peer_id.clone();

        // Create the NetworkId - either from a fixed ID or from the keypair
        let network_id = if let Some(fixed_id) = fixed_network_id {
            info_log(
                Component::P2P,
                &format!("Using fixed network ID: {}", fixed_id),
            )
            .await;
            // Create a NetworkId from the fixed string
            let fixed_id_bytes = fixed_id.as_bytes();
            let mut id_array = [0u8; 32];
            for (i, &b) in fixed_id_bytes.iter().enumerate().take(32) {
                id_array[i] = b;
            }
            NetworkId(id_array)
        } else {
            // Create a NetworkId from the public key
            NetworkId::from_public_key(&keypair.public)
        };

        let network_id_clone = network_id.clone();

        // Create peer inside RwLock with the listen_addr from config
        let peer = Arc::new(RwLock::new(Peer::new_with_addr(
            peer_id,
            sender,
            config.listen_addr.clone(),
        )));

        // Set up the network info - we need to modify the Peer implementation to add this
        {
            let mut peer_mut = peer.write().await;
            let network_info = NetworkInfo {
                admin_pubkey: keypair.public.clone(),
                name: config.network_id.clone(),
                token: AccessToken {
                    peer_id: peer_id_clone.clone(),
                    network_id: network_id.clone(),
                    expiration: None,
                    signature: vec![],
                },
            };
            peer_mut
                .networks_mut()
                .insert(network_id.clone(), network_info);
        }

        // Initialize any bootstrap nodes
        if let Some(bootstrap) = &config.bootstrap_nodes {
            for node in bootstrap {
                debug_log(Component::P2P, &format!("Adding bootstrap node: {}", node)).await;
                // Bootstrap nodes will be connected to when the transport is started
            }
        }

        let result = Ok(Self {
            peer,
            message_receiver: Arc::new(RwLock::new(Some(receiver))),
            peer_id: Arc::new(peer_id_clone),
            pending_requests: Arc::new(RwLock::new(std::collections::HashMap::new())),
            network_id: network_id_clone,
            get_local_services_callback: Arc::new(RwLock::new(None)),
        });

        result
    }

    /// Get the peer ID of this transport
    pub fn get_peer_id(&self) -> Arc<PeerId> {
        self.peer_id.clone()
    }

    pub fn get_network_id(&self) -> &NetworkId {
        // Return the cached network_id
        &self.network_id
    }

    pub async fn send_to_peer<T: Serialize>(&self, peer_id: PeerId, message: T) -> Result<()> {
        let peer = self.peer.read().await;
        peer.send_to_peer(peer_id, message).await
    }

    pub async fn broadcast<T: Serialize>(&self, peer_ids: &[PeerId], message: T) -> Result<()> {
        let peer = self.peer.read().await;
        peer.broadcast(peer_ids, message).await
    }

    /// Start processing incoming messages
    pub async fn start_listening(&self) -> mpsc::Receiver<(PeerId, Vec<u8>)> {
        // Set up a new channel since we can't clone the receiver
        let (tx, rx) = mpsc::channel(100);

        // Set up message handler for service requests/responses
        let pending_requests = self.pending_requests.clone();
        let receiver_lock = self.message_receiver.clone();

        tokio::spawn(async move {
            debug_log(Component::P2P, "Starting P2P message processor").await;

            // Take the receiver out of the lock
            let mut receiver = {
                let mut receiver_guard = receiver_lock.write().await;
                receiver_guard
                    .take()
                    .expect("Message receiver already taken")
            };

            while let Some((peer_id, data)) = receiver.recv().await {
                // Try to parse the message as a P2PMessage
                let message_str = match String::from_utf8(data.clone()) {
                    Ok(s) => s,
                    Err(_) => {
                        // If it's not valid UTF-8, just forward it as-is
                        let _ = tx.send((peer_id.clone(), data)).await;
                        continue;
                    }
                };

                // Make copies early to avoid borrowing moved values
                let data_copy = data.clone();
                let peer_id_copy = peer_id.clone();

                // Try to parse as a P2PMessage
                if let Ok(message) = serde_json::from_str::<P2PMessage>(&message_str) {
                    match message {
                        P2PMessage::Response {
                            request_id,
                            response,
                            metadata: _,
                        } => {
                            // Handle response
                            debug_log(
                                Component::P2P,
                                &format!("Received response for request {}", request_id),
                            )
                            .await;

                            // Look up the response handler
                            let mut response_handlers = pending_requests.write().await;
                            if let Some(handler) = response_handlers.remove(&request_id) {
                                // Call the handler with the response
                                if let Err(e) = handler.send(response) {
                                    error_log(
                                        Component::P2P,
                                        &format!("Failed to send response to handler: {:?}", e),
                                    )
                                    .await;
                                }
                            } else {
                                warn_log(
                                    Component::P2P,
                                    &format!("No handler found for request {}", request_id),
                                )
                                .await;
                            }

                            // Don't forward responses
                            continue;
                        }
                        P2PMessage::Event { topic, data, metadata: _ } => {
                            // Handle event
                            debug_log(
                                Component::P2P,
                                &format!("Received event for topic {}", topic),
                            )
                            .await;

                            // Forward to event handlers - this needs to be redesigned
                            // For now, we'll just forward the message
                            debug_log(
                                Component::P2P,
                                &format!("Forwarding event for topic {}", topic),
                            )
                            .await;

                            // Forward the original message
                            if let ValueType::Bytes(bytes_data) = data.clone() {
                                let _ = tx.send((peer_id.clone(), bytes_data)).await;
                            } else {
                                error_log(
                                    Component::P2P,
                                    "Expected ValueType::Bytes for event data",
                                )
                                .await;
                            }
                            continue;
                        }
                        P2PMessage::Request {
                            request_id,
                            path,
                            params: _,
                            metadata: _,
                        } => {
                            // Handle request
                            debug_log(
                                Component::P2P,
                                &format!("Received request {} for path {}", request_id, path),
                            )
                            .await;

                            // Forward the original message
                            let _ = tx.send((peer_id.clone(), data.clone())).await;
                            continue;
                        }
                        P2PMessage::ServiceDiscovery { services, metadata: _ } => {
                            // Handle service discovery
                            debug_log(
                                Component::P2P,
                                &format!(
                                    "Received service discovery with {} services",
                                    services.len()
                                ),
                            )
                            .await;

                            // Forward to service discovery handlers
                            debug_log(
                                Component::P2P,
                                &format!(
                                    "Forwarding service discovery message from peer {:?}",
                                    peer_id
                                ),
                            )
                            .await;

                            // Forward the original message
                            let _ = tx.send((peer_id.clone(), data.clone())).await;
                            continue;
                        }
                        P2PMessage::ConnectNotification {
                            peer_id: connecting_peer_id,
                            address,
                            metadata: _,
                        } => {
                            debug_log(
                                Component::P2P,
                                &format!(
                                    "Received connection notification from peer {:?} about peer {:?} at {}",
                                    peer_id, connecting_peer_id, address
                                ),
                            ).await;

                            // Forward the message to the application layer to handle the connection
                            let _ = tx.send((peer_id, data)).await;
                        }
                    }
                }

                // If we get here, it wasn't a P2PMessage, so forward it as-is
                debug_log(
                    Component::P2P,
                    &format!("Forwarding unknown message from peer {:?}", peer_id_copy),
                )
                .await;
                let _ = tx.send((peer_id_copy, data_copy)).await;
            }
        });

        rx
    }

    /// Generate a unique request ID
    fn generate_request_id() -> String {
        // Generate a v4 UUID
        uuid::Uuid::new_v4().to_string()
    }

    /// Send a request to a peer with optional metadata
    async fn send_request_with_metadata(
        &self,
        peer_id: PeerId,
        path: String,
        params: ValueType,
        metadata: Option<HashMap<String, ValueType>>,
    ) -> Result<ServiceResponse> {
        debug_log(
            Component::P2P,
            &format!("Sending request to peer {:?}: path={}", peer_id, path),
        )
        .await;

        // Generate a unique request ID
        let request_id = Self::generate_request_id();

        // Create a channel for the response
        let (tx, rx) = oneshot::channel();

        // Store the response channel
        {
            let mut pending_requests = self.pending_requests.write().await;
            pending_requests.insert(request_id.clone(), tx);
        }

        // Create and send the request message
        let request = P2PMessage::Request {
            request_id: request_id.clone(),
            path,
            params,
            metadata,
        };

        self.send_to_peer(peer_id.clone(), request).await?;

        // Wait for the response with a timeout
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(response)) => {
                debug_log(
                    Component::P2P,
                    &format!("Received response for request {}", request_id),
                )
                .await;
                Ok(response)
            }
            Ok(Err(_)) => {
                error_log(
                    Component::P2P,
                    &format!(
                        "Channel closed before receiving response for request {}",
                        request_id
                    ),
                )
                .await;
                Err(anyhow!("Response channel closed unexpectedly"))
            }
            Err(_) => {
                error_log(
                    Component::P2P,
                    &format!("Request {} to peer {:?} timed out", request_id, peer_id),
                )
                .await;
                Err(anyhow!("Request timed out"))
            }
        }
    }

    /// Publish an event to a peer with optional metadata
    async fn publish_event_with_metadata(
        &self,
        peer_id: PeerId,
        topic: String,
        data: ValueType,
        metadata: Option<HashMap<String, ValueType>>,
    ) -> Result<()> {
        debug_log(
            Component::P2P,
            &format!("Publishing event to peer {:?}: topic={}", peer_id, topic),
        )
        .await;

        // Create and send the event message
        let event = P2PMessage::Event { topic, data, metadata };

        self.send_to_peer(peer_id, event).await
    }

    /// Share local service information with a peer
    pub async fn share_services(&self, peer_id: PeerId, services: Vec<P2PServiceInfo>) -> Result<()> {
        debug_log(
            Component::P2P,
            &format!(
                "Sharing {} services with peer {:?}",
                services.len(),
                peer_id
            ),
        )
        .await;

        // Create a service discovery message
        let message = P2PMessage::ServiceDiscovery { 
            services,
            metadata: None 
        };

        // Serialize and send to the peer
        self.send_to_peer(peer_id, message).await
    }

    /// Connect to a peer and perform service discovery
    pub async fn connect_to_peer(
        &self,
        peer_id: PeerId,
        network_id: NetworkId,
        address: String,
    ) -> Result<Vec<P2PServiceInfo>> {
        info_log(
            Component::P2P,
            &format!("Connecting to peer {:?} at {}", peer_id, address),
        )
        .await;

        let mut peer = self.peer.write().await;
        peer.connect_to_peer(peer_id.clone(), &address, network_id)
            .await?;
        drop(peer); // Release the lock

        // Implement service discovery by getting local services and sharing them with the peer
        let _timeout_duration = Duration::from_secs(10);

        // Share our local services with the peer
        // This will trigger service discovery both ways as the remote peer
        // will receive our services via P2PMessage::ServiceDiscovery and respond with its services
        let local_services = self.get_local_services().await?;

        info_log(
            Component::P2P,
            &format!(
                "Sharing {} local services with new peer",
                local_services.len()
            ),
        )
        .await;

        if !local_services.is_empty() {
            // Send our services to the peer
            self.share_services(peer_id.clone(), local_services).await?;

            // Wait to give the peer time to process our services and respond
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Request services from the peer - explicit request to ensure we get their services
        let request_message = P2PMessage::ServiceDiscovery { 
            services: vec![],
            metadata: None
        };
        self.send_to_peer(peer_id.clone(), request_message).await?;

        // Wait for a short time to receive services
        tokio::time::sleep(Duration::from_millis(500)).await;

        Ok(Vec::new()) // Still return empty for now - services will be handled by message handlers
    }

    /// Get local services that should be shared with peers
    async fn get_local_services(&self) -> Result<Vec<P2PServiceInfo>> {
        let mut services = Vec::new();

        // Get local services from the delegate's callback
        if let Some(callback) = &*self.get_local_services_callback.read().await {
            services = callback().await;
        }

        Ok(services)
    }

    /// Wait for a service discovery message
    pub async fn wait_for_service_discovery(
        &self,
        peer_id: &PeerId,
        timeout_duration: Duration,
    ) -> Result<Vec<P2PServiceInfo>> {
        // TODO: Implement waiting for service discovery response
        Ok(Vec::new())
    }

    /// Start the P2P transport
    pub async fn start(&self) -> Result<()> {
        info_log(Component::P2P, "Starting P2P transport").await;
        // Start listening for messages
        let _rx = self.start_listening().await;
        Ok(())
    }

    /// Stop the P2P transport
    pub async fn stop(&self) -> Result<()> {
        info_log(Component::P2P, "Stopping P2P transport").await;
        // No specific cleanup needed at the moment
        Ok(())
    }

    /// Set a callback to be used when getting local services
    pub async fn set_local_services_callback<F>(&self, callback: F)
    where
        F: Fn() -> BoxFuture<'static, Vec<P2PServiceInfo>> + Send + Sync + 'static,
    {
        let mut callback_guard = self.get_local_services_callback.write().await;
        *callback_guard = Some(Box::new(callback));
    }

    /// Connect to a peer
    pub async fn connect(&self, addr: &str) -> Result<()> {
        info_log(Component::P2P, &format!("Connecting to peer at {}", addr)).await;

        // Parse addr to extract peer_id and address
        // This is a simplified implementation - in a real system we'd parse the multiaddr
        let parts: Vec<&str> = addr.split('/').collect();
        if parts.len() < 2 {
            return Err(anyhow!("Invalid address format: {}", addr));
        }

        // Assuming the last part is the peer_id
        let peer_id_str = parts.last().unwrap();

        // Create a peer_id from the string
        // Parse base64 string to bytes
        let peer_id_bytes = base64::decode(peer_id_str)
            .map_err(|_| anyhow!("Invalid peer ID format: {}", peer_id_str))?;

        // Ensure we have 32 bytes for the PeerId
        if peer_id_bytes.len() != 32 {
            return Err(anyhow!(
                "Invalid peer ID length: expected 32 bytes, got {}",
                peer_id_bytes.len()
            ));
        }

        // Convert to fixed-size array
        let mut peer_id_array = [0u8; 32];
        peer_id_array.copy_from_slice(&peer_id_bytes);
        let peer_id = PeerId(peer_id_array);

        // Use the cached network ID
        let network_id = self.network_id.clone();

        // Connect to the peer using the network ID
        let _services = self
            .connect_to_peer(peer_id, network_id, addr.to_string())
            .await?;

        Ok(())
    }

    /// Check if P2P transport is properly initialized and ready for use
    pub fn is_ready(&self) -> bool {
        // According to P2P spec, we need to check:
        // 1. Valid peer_id exists
        // 2. QUIC endpoint is initialized
        // 3. Connections are established if required
        !self.peer_id.0.is_empty() && self.is_initialized()
    }

    /// Internal helper to check initialization state
    fn is_initialized(&self) -> bool {
        // Implementation based on P2P spec requirements
        // Check QUIC endpoint and other critical components
        true // TODO: Implement proper checks based on QUIC endpoint status
    }

    pub async fn wait_for_connection(
        &self,
        _peer_id: &PeerId,
        _timeout_duration: Duration,
    ) -> Result<()> {
        // Implementation needed
        Ok(())
    }
}

#[async_trait]
impl P2PTransportTrait for P2PTransport {
    async fn send_request(
        &self,
        peer_id: PeerId,
        path: String,
        params: ValueType,
    ) -> Result<ServiceResponse> {
        // Use the new method with None for metadata
        self.send_request_with_metadata(peer_id, path, params, None).await
    }

    async fn publish_event(&self, peer_id: PeerId, topic: String, data: ValueType) -> Result<()> {
        // Use the new method with None for metadata
        self.publish_event_with_metadata(peer_id, topic, data, None).await
    }

    // Add metadata versions of the transport trait methods
    async fn send_request_with_metadata(
        &self,
        peer_id: PeerId,
        path: String,
        params: ValueType,
        metadata: Option<HashMap<String, ValueType>>,
    ) -> Result<ServiceResponse> {
        self.send_request_with_metadata(peer_id, path, params, metadata).await
    }

    async fn publish_event_with_metadata(
        &self,
        peer_id: PeerId,
        topic: String,
        data: ValueType,
        metadata: Option<HashMap<String, ValueType>>,
    ) -> Result<()> {
        self.publish_event_with_metadata(peer_id, topic, data, metadata).await
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
