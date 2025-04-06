use crate::db::SqliteDatabase;
use crate::p2p::crypto::{AccessToken, NetworkId, PeerId};
use crate::p2p::transport::{P2PMessage, P2PTransport, TransportConfig};
use crate::services::abstract_service::{AbstractService, ServiceMetadata, ServiceState};
use crate::services::registry::ServiceRegistry;
use crate::services::remote::P2PTransport as P2PTransportTrait;
use crate::services::{RequestContext, ResponseStatus, ServiceRequest, ServiceResponse, ValueType};
use runar_common::utils::logging::{debug_log, error_log, info_log, warn_log, Component};
use crate::vmap;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bincode;
use futures::future::BoxFuture;
use log::{debug, error, info};
use serde_json::json;
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use uuid;

/// Events when a message is received
#[derive(Debug, Clone)]
pub struct P2PMessageEvent {
    /// The peer ID that sent the message
    pub peer_id: PeerId,
    /// The network ID on which the message was received
    pub network_id: NetworkId,
    /// The message content
    pub message: String,
    /// Timestamp when the message was received
    pub timestamp: Instant,
}

/// Events when a peer connects or disconnects
#[derive(Debug, Clone)]
pub struct P2PConnectionEvent {
    /// The peer ID that connected/disconnected
    pub peer_id: PeerId,
    /// The network ID on which the connection was established
    pub network_id: NetworkId,
    /// Whether this is a connection (true) or disconnection (false)
    pub connected: bool,
    /// The peer's address
    pub address: String,
    /// Timestamp when the event occurred
    pub timestamp: Instant,
}

/// Type for message event handlers
pub type MessageEventHandler = Arc<dyn Fn(P2PMessageEvent) + Send + Sync>;

/// Type for connection event handlers
pub type ConnectionEventHandler = Arc<dyn Fn(P2PConnectionEvent) + Send + Sync>;

/// A delegate for handling remote service communication via P2P
pub struct P2PRemoteServiceDelegate {
    /// The name of the delegate
    name: String,

    /// Current state of the delegate
    state: Mutex<ServiceState>,

    /// P2P transport instance
    pub transport: Arc<RwLock<P2PTransport>>,

    /// Connected peers
    peers: Arc<RwLock<HashMap<PeerId, String>>>,

    /// Delegate uptime
    uptime: Instant,

    /// Network ID
    network_id: NetworkId,

    /// Message event handlers
    message_handlers: Arc<RwLock<Vec<MessageEventHandler>>>,

    /// Connection event handlers
    connection_handlers: Arc<RwLock<Vec<ConnectionEventHandler>>>,

    /// Reference to the service registry
    service_registry: Arc<ServiceRegistry>,
}

impl P2PRemoteServiceDelegate {
    pub async fn new(
        peer_id: Option<PeerId>,
        network_id_str: &str,
        db: Arc<SqliteDatabase>,
    ) -> Result<Self> {
        info_log(
            Component::P2P,
            &format!("Creating P2P delegate for network {}", network_id_str),
        );

        // Create the default P2P transport configuration
        let config = TransportConfig {
            network_id: network_id_str.to_string(),
            state_path: ".".to_string(), // Use the current directory by default
            bootstrap_nodes: None,
            listen_addr: None,
        };

        // Create the P2P transport
        let transport = Arc::new(RwLock::new(
            match P2PTransport::new(config, Some(network_id_str)).await {
                Ok(transport) => transport,
                Err(e) => {
                    error_log(
                        Component::P2P,
                        &format!("Failed to create P2P transport: {:?}", e),
                    );
                    return Err(anyhow!("Failed to create P2P transport: {:?}", e));
                }
            },
        ));

        // Get the peer ID and network ID from the transport
        let transport_peer_id = {
            let transport = transport.read().await;
            // Get Arc<PeerId> and get the inner PeerId
            (*transport.get_peer_id()).clone()
        };

        let transport_network_id = {
            let transport = transport.read().await;
            transport.get_network_id().clone()
        };

        // Use the provided peer_id if available, otherwise use the transport's peer_id
        let effective_peer_id = peer_id.unwrap_or(transport_peer_id);

        // Create the P2P delegate
        let delegate = Self {
            name: format!("p2p_{}", network_id_str),
            state: Mutex::new(ServiceState::Created),
            transport,
            peers: Arc::new(RwLock::new(HashMap::new())),
            uptime: Instant::now(),
            network_id: transport_network_id,
            message_handlers: Arc::new(RwLock::new(Vec::new())),
            connection_handlers: Arc::new(RwLock::new(Vec::new())),
            service_registry: Arc::new(ServiceRegistry::new(network_id_str)),
        };

        // Register a simple message handler that will log messages
        delegate
            .register_message_handler(|event: P2PMessageEvent| {
                tokio::spawn(async move {
                    debug_log(
                        Component::P2P,
                        &format!(
                            "Received message from peer {:?}: {}",
                            event.peer_id, event.message
                        ),
                    )
                    .await;
                });
            })
            .await;

        Ok(delegate)
    }

    /// Create a new P2PRemoteServiceDelegate with a P2P transport
    pub async fn with_transport(
        mut self,
        transport: Arc<dyn P2PTransportTrait>,
        fixed_network_id: Option<&str>,
    ) -> Result<Self> {
        // Convert the abstract transport to a concrete P2PTransport
        // This is a safe cast because we know the concrete type
        let concrete_transport_ref = transport.as_any().downcast_ref::<P2PTransport>();
        let concrete_transport = match concrete_transport_ref {
            Some(transport_ref) => {
                // Create a new P2PTransport by cloning the reference
                let config = TransportConfig::default(); // Use default config as we're just creating a shell
                let cloned_transport = P2PTransport::new(config, fixed_network_id).await?;
                Arc::new(RwLock::new(cloned_transport))
            }
            None => {
                return Err(anyhow!("Failed to downcast P2P transport to concrete type"));
            }
        };

        // Set the P2P transport
        self.transport = concrete_transport.clone();

        // Set a callback for the transport to get local services
        let service_registry_weak: Weak<ServiceRegistry> = Arc::downgrade(&self.service_registry);
        let transport_guard = concrete_transport.read().await;
        transport_guard
            .set_local_services_callback(move || {
                let service_registry_weak_clone = service_registry_weak.clone();
                Box::pin(async move {
                    let mut services = Vec::new();

                    // Get the service registry
                    if let Some(registry) = service_registry_weak_clone.upgrade() {
                        // Get all services
                        let all_services = registry.get_all_services().await;

                        // Create service info for each local service
                        for service in all_services {
                            let metadata = service.metadata();
                            let service_info = crate::p2p::transport::P2PServiceInfo {
                                name: metadata.name,
                                path: metadata.path,
                                operations: metadata.operations,
                            };
                            services.push(service_info);
                        }
                    }

                    services
                })
            })
            .await;

        Ok(self)
    }

    /// Start the P2P delegate
    pub async fn start(&mut self) -> Result<()> {
        info_log(Component::P2P, "Starting P2P delegate").await;

        *self.state.lock().unwrap() = ServiceState::Running;

        // Start the transport
        let transport = self.transport.read().await;
        transport.start().await?;

        Ok(())
    }

    /// Stop the P2P delegate
    pub async fn stop(&mut self) -> Result<()> {
        info_log(Component::P2P, "Stopping P2P delegate").await;

        *self.state.lock().unwrap() = ServiceState::Stopped;

        // Stop the transport
        let transport = self.transport.read().await;
        transport.stop().await?;

        Ok(())
    }

    /// Register a message handler
    pub async fn register_message_handler<F>(&self, handler: F)
    where
        F: Fn(P2PMessageEvent) + Send + Sync + 'static,
    {
        let mut handlers = self.message_handlers.write().await;
        handlers.push(Arc::new(handler));
    }

    /// Register a connection handler
    pub async fn register_connection_handler<F>(&self, handler: F)
    where
        F: Fn(P2PConnectionEvent) + Send + Sync + 'static,
    {
        let mut handlers = self.connection_handlers.write().await;
        handlers.push(Arc::new(handler));
    }

    /// Notify the message handlers of a new message
    async fn notify_message_handlers(&self, event: P2PMessageEvent) {
        debug_log(
            Component::P2P,
            &format!(
                "Notifying message handlers of message from {:?}",
                event.peer_id
            ),
        );

        let handlers = self.message_handlers.read().await;
        for handler in handlers.iter() {
            handler(event.clone());
        }
    }

    /// Notify the connection handlers of a connection event
    async fn notify_connection_handlers(&self, event: P2PConnectionEvent) {
        debug_log(
            Component::P2P,
            &format!(
                "Notifying connection handlers of event for peer {:?}",
                event.peer_id
            ),
        );

        let handlers = self.connection_handlers.read().await;
        for handler in handlers.iter() {
            handler(event.clone());
        }
    }

    /// Connect to a peer
    pub async fn connect_to_peer(&self, peer_id: Arc<PeerId>, address: &str) -> Result<()> {
        info_log(
            Component::P2P,
            &format!("Connecting to peer {:?} at {}", *peer_id, address),
        );

        // Extract the PeerId from Arc<PeerId> to pass to notify_peer_connected
        let peer_id_value = (*peer_id).clone();

        let transport_guard = self.transport.read().await;

        // Connect using the transport (this will error if transport is not initialized)
        transport_guard.connect(address).await?;

        // Map peer address for future use
        let mut addresses = self.peers.write().await;
        addresses.insert(peer_id_value.clone(), address.to_string());

        // Get local peer ID and address for the notification
        let self_peer_id_arc = transport_guard.get_peer_id().clone();
        let self_peer_id = (*self_peer_id_arc).clone();
        let self_address = "127.0.0.1:0";

        // Notify about the new connection with properly extracted PeerId
        self.notify_peer_connected(peer_id_value, self_peer_id, self_address)
            .await?;

        Ok(())
    }

    /// Notify a peer that we've connected to them
    async fn notify_peer_connected(
        &self,
        target_peer_id: PeerId,
        self_peer_id: PeerId,
        self_addr: &str,
    ) -> Result<()> {
        debug_log(
            Component::P2P,
            &format!(
                "Notifying peer {:?} that we've connected to them",
                target_peer_id
            ),
        )
        .await;

        // Create a connection notification message
        let message = P2PMessage::ConnectNotification {
            peer_id: self_peer_id,
            address: self_addr.to_string(),
        };

        // Serialize and send the message
        let message_data = bincode::serialize(&message)?;
        let transport_guard = self.transport.read().await;
        transport_guard
            .send_to_peer(target_peer_id.clone(), message_data)
            .await
            .map_err(|e| anyhow!("Failed to send connection notification: {}", e))?;

        debug_log(
            Component::P2P,
            &format!("Connection notification sent to peer {:?}", target_peer_id),
        )
        .await;

        Ok(())
    }

    /// Send a message to a peer
    pub async fn send_message(&self, peer_id: PeerId, message: String) -> Result<()> {
        debug_log(
            Component::P2P,
            &format!("Sending message to peer {:?}: {}", peer_id, message),
        );

        // Get the P2P transport
        let transport = self.transport.read().await;

        // Try to send the message up to 3 times if the connection is closed
        let mut attempts = 0;
        let max_attempts = 3;

        loop {
            attempts += 1;
            let result = transport
                .send_to_peer(peer_id.clone(), message.clone())
                .await;

            match result {
                Ok(_) => {
                    debug_log(
                        Component::P2P,
                        &format!(
                            "Successfully sent message to peer {:?} on attempt {}",
                            peer_id, attempts
                        ),
                    );
                    return Ok(());
                }
                Err(e) => {
                    if attempts >= max_attempts {
                        error_log(
                            Component::P2P,
                            &format!(
                                "Failed to send message to peer {:?} after {} attempts: {:?}",
                                peer_id, attempts, e
                            ),
                        );
                        return Err(e);
                    }

                    warn_log(
                        Component::P2P,
                        &format!(
                            "Failed to send message to peer {:?} on attempt {}: {:?}. Retrying...",
                            peer_id, attempts, e
                        ),
                    );

                    // Check if the peer is in our connected peers
                    let peer_address = {
                        let peers = self.peers.read().await;
                        peers.get(&peer_id).cloned()
                    };

                    // If we have an address for the peer, try to reconnect
                    if let Some(address) = peer_address {
                        debug_log(
                            Component::P2P,
                            &format!(
                                "Attempting to reconnect to peer {:?} at {}",
                                peer_id, address
                            ),
                        );

                        // Try to reconnect
                        let _reconnect_result = transport
                            .connect_to_peer(
                                peer_id.clone(),
                                self.network_id.clone(),
                                address.clone(),
                            )
                            .await;
                    }

                    // Wait a moment before retrying
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Publish an event to a peer
    pub async fn publish_event(
        &self,
        peer_id: PeerId,
        topic: String,
        data: ValueType,
    ) -> Result<()> {
        debug_log(
            Component::P2P,
            &format!("Publishing event to peer {:?}: topic={}", peer_id, topic),
        );

        // Create an Event message
        let event_message = P2PMessage::Event {
            topic: topic.clone(),
            data: data.clone(),
        };

        // Convert the message to JSON and send
        let transport = self.transport.read().await;
        let result = transport.send_to_peer(peer_id.clone(), event_message).await;

        if result.is_ok() {
            debug_log(
                Component::P2P,
                &format!("Successfully published event to peer {:?}", peer_id),
            );
        } else {
            error_log(
                Component::P2P,
                &format!("Failed to publish event to peer {:?}", peer_id),
            );
        }

        result
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast_message(&self, message: String) -> Result<()> {
        debug_log(Component::P2P, "Broadcasting message to all peers").await;

        // Get the list of peer IDs
        let peers = {
            let peers = self.peers.read().await;
            peers.keys().cloned().collect::<Vec<_>>()
        };

        // Broadcast the message using the transport
        let transport = self.transport.read().await;
        transport.broadcast(&peers, message).await?;

        Ok(())
    }

    /// Get all connected peers
    pub async fn get_peers(&self) -> Vec<(PeerId, String)> {
        let peers = self.peers.read().await;
        peers
            .iter()
            .map(|(peer_id, address)| (peer_id.clone(), address.clone()))
            .collect()
    }

    /// Get our own peer ID
    pub fn get_peer_id(&self) -> PeerId {
        // Synchronous version for ease of use
        let transport = futures::executor::block_on(self.transport.read());
        (*transport.get_peer_id()).clone()
    }

    /// Handle a request for the P2P delegate
    pub async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        debug_log(
            Component::P2P,
            &format!("Processing request: {}", request.action),
        );

        match request.action.as_str() {
            "connect" => {
                // Get the parameters
                let params = request.data;
                
                // Extract the address
                let address = if let Some(ValueType::String(addr)) = params.as_ref().and_then(|p| p.get("address")) {
                    addr.clone()
                } else {
                    return Err(anyhow!("Missing or invalid 'address' parameter"));
                };

                // Extract the peer ID
                let peer_id_base64 = if let Some(ValueType::String(id)) = params.as_ref().and_then(|p| p.get("peer_id")) {
                    id.clone()
                } else {
                    return Err(anyhow!("Missing or invalid 'peer_id' parameter"));
                };

                // Convert the peer ID from base64 to PeerId
                let peer_id_bytes = base64::decode(&peer_id_base64)
                    .map_err(|_| anyhow!("Invalid peer ID format"))?;

                // Ensure we have 32 bytes
                if peer_id_bytes.len() != 32 {
                    return Err(anyhow!("Invalid peer ID length"));
                }

                // Convert to fixed-size array
                let mut peer_id_array = [0u8; 32];
                peer_id_array.copy_from_slice(&peer_id_bytes);
                let peer_id = PeerId(peer_id_array);

                // Connect to the peer
                self.connect_to_peer(Arc::new(peer_id), &address).await?;

                // Return success
                Ok(ServiceResponse::success(
                    "Connected to peer successfully".to_string(),
                    Some(ValueType::Bool(true)),
                ))
            }
            "send" => {
                // Get the parameters
                let params = request.data;
                
                // Extract the peer ID
                let peer_id_base64 = if let Some(ValueType::String(id)) = params.as_ref().and_then(|p| p.get("peer_id")) {
                    id.clone()
                } else {
                    return Err(anyhow!("Missing or invalid 'peer_id' parameter"));
                };
                
                // Extract the message
                let message = if let Some(ValueType::String(msg)) = params.as_ref().and_then(|p| p.get("message")) {
                    msg.clone()
                } else {
                    return Err(anyhow!("Missing or invalid 'message' parameter"));
                };

                // Convert the peer ID from base64 to PeerId
                let peer_id_bytes = base64::decode(&peer_id_base64)
                    .map_err(|_| anyhow!("Invalid peer ID format"))?;

                // Ensure we have 32 bytes
                if peer_id_bytes.len() != 32 {
                    return Err(anyhow!("Invalid peer ID length"));
                }

                // Convert to fixed-size array
                let mut peer_id_array = [0u8; 32];
                peer_id_array.copy_from_slice(&peer_id_bytes);
                let peer_id = PeerId(peer_id_array);

                // Send the message
                self.send_message(peer_id, message.to_string()).await?;

                // Return success
                Ok(ServiceResponse::success(
                    "Message sent".to_string(),
                    Some(ValueType::Bool(true)),
                ))
            }
            "publish_event" => {
                // Extract the peer_id
                let peer_id_base64 = if let Some(ValueType::String(id)) = request.data.as_ref().and_then(|p| p.get("peer_id")) {
                    id.clone()
                } else {
                    return Err(anyhow!("Missing or invalid 'peer_id' parameter"));
                };

                // Extract the topic
                let topic = if let Some(ValueType::String(t)) = request.data.as_ref().and_then(|p| p.get("topic")) {
                    t.clone()
                } else {
                    return Err(anyhow!("Missing or invalid 'topic' parameter"));
                };

                // Extract the data
                let data = if let Some(value) = request.data.as_ref().and_then(|p| p.get("data")) {
                    value.clone()
                } else {
                    return Err(anyhow!("Missing 'data' parameter"));
                };

                // Convert the peer ID from base64 to PeerId
                let peer_id_bytes = base64::decode(&peer_id_base64)
                    .map_err(|_| anyhow!("Invalid peer ID format"))?;

                // Ensure we have 32 bytes
                if peer_id_bytes.len() != 32 {
                    return Err(anyhow!("Invalid peer ID length"));
                }

                // Convert to fixed-size array
                let mut peer_id_array = [0u8; 32];
                peer_id_array.copy_from_slice(&peer_id_bytes);
                let peer_id = PeerId(peer_id_array);

                // Publish the event to the peer
                info_log(
                    Component::P2P,
                    &format!("Publishing event to topic {} for peer {:?}", topic, peer_id),
                );

                let peer_id_clone = peer_id.clone();
                self.publish_event(peer_id_clone, topic.to_string(), data)
                    .await?;

                // Return success
                Ok(ServiceResponse::success(
                    "Event published".to_string(),
                    Some(ValueType::Bool(true)),
                ))
            }
            "info" => {
                // Get our own peer ID
                let peer_id = self.get_peer_id();
                let peer_id_base64 = base64::encode(peer_id.0);

                // Create a JSON response with the peer ID
                let mut info = HashMap::new();
                info.insert(
                    "peer_id".to_string(),
                    ValueType::String(peer_id_base64.clone()),
                );
                info.insert(
                    "uptime".to_string(),
                    ValueType::Number(self.uptime.elapsed().as_secs() as f64),
                );

                let network_id_base64 = base64::encode(self.network_id.0);
                info.insert(
                    "network_id".to_string(),
                    ValueType::String(network_id_base64.clone()),
                );

                // Return the info
                Ok(ServiceResponse::success(
                    "P2P info".to_string(),
                    Some(ValueType::Map(info)),
                ))
            }
            "peers" => {
                // Get all connected peers
                let peers = self.get_peers().await;

                // Convert to a JSON array
                let peers_array = peers
                    .iter()
                    .map(|(peer_id, _address)| ValueType::String(base64::encode(peer_id.0)))
                    .collect();

                // Create a JSON response
                let mut result = HashMap::new();
                result.insert("peers".to_string(), ValueType::Array(peers_array));

                // Return the peers
                Ok(ServiceResponse::success(
                    "Connected peers".to_string(),
                    Some(ValueType::Map(result)),
                ))
            }
            "discover" => {
                // Discover services on a remote peer
                // Not implemented in this simplified version
                Ok(ServiceResponse::error("Service discovery not implemented"))
            }
            _ => {
                // Unknown operation
                Ok(ServiceResponse::error(format!(
                    "Unknown operation: {}",
                    request.action
                )))
            }
        }
    }

    /// Get a reference to the P2P transport
    pub fn transport(&self) -> Arc<RwLock<P2PTransport>> {
        self.transport.clone()
    }
}

impl Clone for P2PRemoteServiceDelegate {
    fn clone(&self) -> Self {
        debug_log(
            Component::P2P,
            &format!("Cloning P2P Delegate: {}", self.name),
        );
        Self {
            name: self.name.clone(),
            state: Mutex::new(*self.state.lock().unwrap()),
            transport: self.transport.clone(),
            peers: self.peers.clone(),
            uptime: self.uptime,
            network_id: self.network_id.clone(),
            message_handlers: self.message_handlers.clone(),
            connection_handlers: self.connection_handlers.clone(),
            service_registry: self.service_registry.clone(),
        }
    }
}

/// Implementation of the P2PTransport trait for P2PRemoteServiceDelegate
#[async_trait]
impl P2PTransportTrait for P2PRemoteServiceDelegate {
    async fn send_request(
        &self,
        peer_id: PeerId,
        path: String,
        params: ValueType,
    ) -> Result<ServiceResponse> {
        debug_log(
            Component::P2P,
            &format!("Sending request to peer {:?}: {}", peer_id, path),
        );

        // Generate a request ID
        let request_id = uuid::Uuid::new_v4().to_string();

        // Create a Request message
        let request_message = P2PMessage::Request {
            request_id: request_id.clone(),
            path: path.clone(),
            params: params.clone(),
        };

        // Convert the message to a JSON string
        let message_str = serde_json::to_string(&request_message)
            .map_err(|e| anyhow!("Failed to serialize message: {:?}", e))?;

        // Send the message
        self.send_message(peer_id, message_str).await?;

        // In a real implementation, we would wait for the response
        // For now, just return a dummy response
        Ok(ServiceResponse::success(
            "Request sent".to_string(),
            Some(ValueType::Bool(true)),
        ))
    }

    async fn publish_event(&self, peer_id: PeerId, topic: String, data: ValueType) -> Result<()> {
        debug_log(
            Component::P2P,
            &format!("Publishing event to peer {:?}: {}", peer_id, topic),
        );

        // Create an Event message
        let event_message = P2PMessage::Event {
            topic: topic.clone(),
            data: data.clone(),
        };

        // Convert the message to a JSON string
        let message_str = serde_json::to_string(&event_message)
            .map_err(|e| anyhow!("Failed to serialize message: {:?}", e))?;

        // Send the message
        self.send_message(peer_id, message_str).await
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[async_trait]
impl AbstractService for P2PRemoteServiceDelegate {
    fn name(&self) -> &str {
        "p2p"
    }

    fn path(&self) -> &str {
        "/p2p"
    }

    fn state(&self) -> ServiceState {
        ServiceState::Running
    }
    
    fn metadata(&self) -> ServiceMetadata {
        ServiceMetadata {
            name: self.name().to_string(),
            path: self.path().to_string(),
            state: self.state(),
            description: self.description().to_string(),
            operations: vec![
                "connect".to_string(),
                "disconnect".to_string(),
                "send".to_string(),
                "list_peers".to_string(),
                "publish".to_string(),
                "subscribe".to_string(),
                "unsubscribe".to_string(),
            ],
            version: "1.0".to_string(),
        }
    }

    async fn init(&mut self, _context: &RequestContext) -> Result<()> {
        Ok(())
    }

    async fn start(&mut self) -> Result<()> {
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
    
    fn description(&self) -> &str {
        "Peer-to-peer networking service delegate"
    }

    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        // Process the request based on the operation
        match request.action.as_str() {
            "connect" => {
                // Extract peer_id and address from params
                if let Some(data) = &request.data {
                    if let ValueType::Map(map) = data {
                        let peer_id = map
                            .get("peer_id")
                            .and_then(|v| {
                                if let ValueType::String(s) = v {
                                    Some(s)
                                } else {
                                    None
                                }
                            })
                            .ok_or_else(|| anyhow!("Missing peer_id parameter"))?;
                        let address = map
                            .get("address")
                            .and_then(|v| {
                                if let ValueType::String(s) = v {
                                    Some(s)
                                } else {
                                    None
                                }
                            })
                            .ok_or_else(|| anyhow!("Missing address parameter"))?;

                        // Connect to the peer
                        let peer_id = PeerId::from_str(peer_id)?;
                        self.connect_to_peer(Arc::new(peer_id), address).await?;

                        Ok(ServiceResponse {
                            status: crate::services::ResponseStatus::Success,
                            message: "Connected to peer successfully".to_string(),
                            data: Some(ValueType::Bool(true)),
                        })
                    } else {
                        Err(anyhow!("Invalid parameters format"))
                    }
                } else {
                    Err(anyhow!("Missing parameters"))
                }
            }
            _ => Err(anyhow!("Unknown operation: {}", request.action)),
        }
    }
}
