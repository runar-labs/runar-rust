use anyhow::{anyhow, Result};
use crate::db::SqliteDatabase;
use crate::p2p::crypto::{NetworkId, PeerId};
use crate::p2p::transport::{P2PMessage, P2PTransport, TransportConfig};
use crate::services::abstract_service::{AbstractService, ServiceState, ActionMetadata, EventMetadata};
use crate::services::service_registry::ServiceRegistry;
use crate::services::remote::P2PTransport as P2PTransportTrait;
use crate::services::{RequestContext, ServiceRequest, ServiceResponse};
use runar_common::utils::logging::{debug_log, error_log, info_log, Component};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;
use tokio::sync::RwLock;
use uuid;
use libp2p::PeerId as LibP2pPeerId;
use runar_common::types::ValueType;
use crate::p2p::crypto::PeerId as CryptoPeerId;
use crate::p2p::peer_id_convert::{LibP2pToCryptoPeerId, CryptoToLibP2pPeerId};
use chrono;

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
        _db: Arc<SqliteDatabase>,
    ) -> Result<Self> {
        info_log(
            Component::P2P,
            &format!("Creating P2P delegate for network {}", network_id_str),
        ).await;

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
                    ).await;
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
        let _effective_peer_id = peer_id.unwrap_or(transport_peer_id);

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
            Some(_transport_ref) => {
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
    pub async fn stop(&self) -> Result<()> {
        info_log(Component::P2P, "Stopping P2P delegate").await;

        *self.state.lock().unwrap() = ServiceState::Stopped;

        // Stop the transport
        let transport = self.transport.read().await;
        // Transport is already a guard, just directly use it
        (&*transport).stop().await?;

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
        ).await;

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
        ).await;

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
        ).await;

        // Extract the PeerId from Arc<PeerId> to pass to notify_peer_connected
        let peer_id_value = (*peer_id).clone();

        let transport_guard = self.transport.read().await;

        // Connect using the transport (this will error if transport is not initialized)
        transport_guard.connect(address).await?;

        // Map peer address for future use
        let mut addresses = self.peers.write().await;
        addresses.insert(peer_id_value.clone(), address.to_string());

        // Get local peer ID and address for the notification
        let self_crypto_peer_id = transport_guard.get_peer_id().clone();
        let self_libp2p_peer_id = self_crypto_peer_id.to_libp2p_peer_id()
            .map_err(|e| anyhow!("Failed to convert peer ID: {}", e))?;
        let self_address = "127.0.0.1:0".to_string();

        // Notify about the new connection with properly extracted PeerId
        self.notify_peer_connected(peer_id_value, self_libp2p_peer_id, self_address)
            .await?;

        Ok(())
    }

    /// Get our peer ID and notify the peer
    async fn get_peer_id_and_notify(&self, peer_id: PeerId) -> Result<()> {
        // Get our own peer ID
        let self_peer_id = self.get_peer_id()?;
        
        // Convert to LibP2P format for the notification
        let self_libp2p_peer_id = self_peer_id.to_libp2p_peer_id()
            .map_err(|e| anyhow!("Failed to convert peer ID: {}", e))?;
        
        // Set the self address to a default value
        let self_address = "127.0.0.1:0".to_string();

        // Notify listeners that a peer has connected
        self.notify_peer_connected(peer_id.clone(), self_libp2p_peer_id, self_address)
            .await?;

        log::debug!("[{}] Successfully handled peer connected event for {:?}", 
            Component::P2P.as_str(),
            peer_id);

        Ok(())
    }

    /// Notify other components that a peer has connected
    async fn notify_peer_connected(
        &self,
        peer_id: CryptoPeerId,
        self_peer_id: LibP2pPeerId,
        self_address: String,
    ) -> Result<()> {
        // Convert self_peer_id to CryptoPeerId for consistency
        let self_crypto_peer_id = self_peer_id.to_crypto_peer_id()
            .map_err(|e| anyhow!("Failed to convert self peer ID: {}", e))?;

        // Create metadata with peer information
        let mut metadata = HashMap::new();
        metadata.insert("self_peer_id".to_string(), ValueType::String(self_crypto_peer_id.to_string()));
        metadata.insert("self_address".to_string(), ValueType::String(self_address.clone()));
        metadata.insert("connection_time".to_string(), ValueType::String(chrono::Utc::now().to_rfc3339()));

        // Create a message to notify that a peer has connected
        let _message = P2PMessage::ConnectNotification {
            peer_id: peer_id.clone(),
            address: self_address,
            metadata: Some(metadata.clone()),
        };

        // Broadcast to any local subscribers including metadata
        self.broadcast_local_event_with_metadata(
            "peer_connected", 
            ValueType::String(peer_id.to_string()),
            Some(metadata)
        ).await?;

        // Serialize the message
        Ok(())
    }

    /// Send a message to a peer
    pub async fn send_message(&self, peer_id: LibP2pPeerId, message: String) -> Result<()> {
        debug_log(
            Component::P2P,
            &format!("Sending message to peer {:?}", peer_id)
        ).await;

        // Check if transport is initialized
        let transport = self.transport.read().await;
        
        // Convert LibP2pPeerId to our PeerId
        let peer_id_str = peer_id.to_string();
        let crypto_peer_id = PeerId::from_str(&peer_id_str)
            .map_err(|e| anyhow!("Failed to convert peer ID: {}", e))?;
        
        // Send the message - transport is already a guard, use it directly
        (&*transport).send_to_peer(crypto_peer_id, message).await
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
        ).await;

        // Create an Event message
        let event_message = P2PMessage::Event {
            topic: topic.clone(),
            data: data.clone(),
            metadata: None,
        };

        // Convert the message to JSON and send
        let transport = self.transport.read().await;
        let result = (&*transport).send_to_peer(peer_id.clone(), event_message).await;

        if result.is_ok() {
            debug_log(
                Component::P2P,
                &format!("Successfully published event to peer {:?}", peer_id),
            ).await;
        } else {
            error_log(
                Component::P2P,
                &format!("Failed to publish event to peer {:?}", peer_id),
            ).await;
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
        (&*transport).broadcast(&peers, message).await?;

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

    /// Get the peer ID for this delegate
    pub fn get_peer_id(&self) -> Result<PeerId> {
        // Get transport peer ID
        let transport = futures::executor::block_on(self.transport.read());
        
        // Transport is already a guard, use it directly
        let peer_id = (&*transport).get_peer_id();
        Ok((*peer_id).clone())
    }

    /// Get a reference to the P2P transport
    pub fn transport(&self) -> Arc<RwLock<P2PTransport>> {
        self.transport.clone()
    }

    /// Broadcast an event to local subscribers
    async fn broadcast_local_event(&self, topic: &str, data: ValueType) -> Result<()> {
        // Call with empty metadata
        self.broadcast_local_event_with_metadata(topic, data, None).await
    }

    /// Broadcast an event to local subscribers with metadata
    async fn broadcast_local_event_with_metadata(&self, topic: &str, data: ValueType, metadata: Option<HashMap<String, ValueType>>) -> Result<()> {
        // Create an event message
        let event_message = P2PMessage::Event {
            topic: topic.to_string(),
            data: data.clone(),
            metadata,
        };

        // Convert the message to JSON and send
        let transport = self.transport.read().await;
        let result = (&*transport).send_to_peer(self.get_peer_id()?, event_message).await;

        if result.is_ok() {
            debug_log(
                Component::P2P,
                &format!("Published local event for topic: {}", topic)
            ).await;
        }

        result
    }

    /// Handle peer connected event
    async fn handle_peer_connected(&self, peer_id: CryptoPeerId, _address: &str) -> Result<()> {
        debug_log(
            Component::P2P,
            &format!("Handling peer connected event for {:?}", peer_id),
        ).await;

        // Call the get_peer_id_and_notify function
        self.get_peer_id_and_notify(peer_id.clone()).await?;

        debug_log(
            Component::P2P,
            &format!("Successfully handled peer connected event for {:?}", peer_id),
        ).await;

        Ok(())
    }
}

impl Clone for P2PRemoteServiceDelegate {
    fn clone(&self) -> Self {
        log::debug!("[{}] Cloning P2P Delegate: {}", 
            Component::P2P.as_str(),
            self.name);
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
#[async_trait::async_trait]
impl P2PTransportTrait for P2PRemoteServiceDelegate {
    async fn send_request(
        &self,
        peer_id: CryptoPeerId,
        path: String,
        params: ValueType,
    ) -> Result<ServiceResponse> {
        // Call the version with metadata
        self.send_request_with_metadata(peer_id, path, params, None).await
    }

    async fn publish_event(&self, peer_id: CryptoPeerId, topic: String, data: ValueType) -> Result<()> {
        // Call the version with metadata
        self.publish_event_with_metadata(peer_id, topic, data, None).await
    }

    async fn send_request_with_metadata(
        &self,
        peer_id: CryptoPeerId,
        path: String,
        params: ValueType,
        metadata: Option<HashMap<String, ValueType>>,
    ) -> Result<ServiceResponse> {
        // Implementation that doesn't call itself
        self.internal_send_request_with_metadata(peer_id, path, params, metadata).await
    }

    async fn publish_event_with_metadata(
        &self,
        peer_id: CryptoPeerId,
        topic: String,
        data: ValueType,
        metadata: Option<HashMap<String, ValueType>>,
    ) -> Result<()> {
        // Implementation that doesn't call itself
        self.internal_publish_event_with_metadata(peer_id, topic, data, metadata).await
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// Add these new internal methods to P2PRemoteServiceDelegate
impl P2PRemoteServiceDelegate {
    // Internal implementation to avoid recursive calls
    async fn internal_send_request_with_metadata(
        &self,
        peer_id: CryptoPeerId,
        path: String,
        params: ValueType,
        metadata: Option<HashMap<String, ValueType>>,
    ) -> Result<ServiceResponse> {
        log::debug!("[{}] Sending request to peer {:?}: {}", 
            Component::P2P.as_str(),
            peer_id, path);

        // Convert peer_id to libp2p PeerId for internal use
        let libp2p_peer_id = peer_id.to_libp2p_peer_id()
            .map_err(|e| anyhow!("Failed to convert peer ID: {}", e))?;

        // Generate a request ID
        let request_id = uuid::Uuid::new_v4().to_string();

        // Create a Request message
        let request_message = P2PMessage::Request {
            request_id: request_id.clone(),
            path: path.clone(),
            params: params.clone(),
            metadata,
        };

        // Convert the message to a JSON string
        let message_str = serde_json::to_string(&request_message)
            .map_err(|e| anyhow!("Failed to serialize message: {:?}", e))?;

        // Send the message
        self.send_message(libp2p_peer_id, message_str).await?;

        // In a real implementation, we would wait for the response
        // For now, just return a dummy response
        Ok(ServiceResponse::success(
            "Request sent".to_string(),
            Some(ValueType::Bool(true)),
        ))
    }

    // Internal implementation to avoid recursive calls
    async fn internal_publish_event_with_metadata(
        &self,
        peer_id: CryptoPeerId,
        topic: String,
        data: ValueType,
        metadata: Option<HashMap<String, ValueType>>,
    ) -> Result<()> {
        log::debug!("[{}] Publishing event to peer {:?}: {}", 
            Component::P2P.as_str(),
            peer_id, topic);

        // Convert peer_id to libp2p PeerId for internal use
        let libp2p_peer_id = peer_id.to_libp2p_peer_id()
            .map_err(|e| anyhow!("Failed to convert peer ID: {}", e))?;

        // Create an Event message
        let event_message = P2PMessage::Event {
            topic: topic.clone(),
            data: data.clone(),
            metadata,
        };

        // Convert the message to a JSON string
        let message_str = serde_json::to_string(&event_message)
            .map_err(|e| anyhow!("Failed to serialize message: {:?}", e))?;

        // Send the message
        self.send_message(libp2p_peer_id, message_str).await
    }
}

#[async_trait::async_trait]
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
    
    fn version(&self) -> &str {
        "1.0"
    }
    
    fn actions(&self) -> Vec<ActionMetadata> {
        vec![
            ActionMetadata { name: "connect".to_string() },
            ActionMetadata { name: "disconnect".to_string() },
            ActionMetadata { name: "send_message".to_string() },
            ActionMetadata { name: "get_peers".to_string() },
            ActionMetadata { name: "get_peer".to_string() },
            ActionMetadata { name: "add_peer".to_string() },
            ActionMetadata { name: "get_peer_info".to_string() },
        ]
    }

    fn events(&self) -> Vec<EventMetadata> {
        vec![
            EventMetadata { name: "peer_connected".to_string() },
            EventMetadata { name: "peer_disconnected".to_string() },
            EventMetadata { name: "message_received".to_string() },
        ]
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
