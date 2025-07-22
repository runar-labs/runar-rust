use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use prost::Message;
use quinn::{self, Endpoint};
use quinn::{ClientConfig, ServerConfig};
use runar_common::compact_ids::compact_id;
use runar_common::logging::Logger;
use serde_cbor;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::{GeneralName, ParsedExtension};

use crate::network::discovery::{multicast_discovery::PeerInfo, NodeInfo};
use crate::network::transport::{MessageContext, NetworkError, NetworkMessage, NetworkTransport};
use crate::routing::TopicPath;
use runar_serializer::{ArcValue, SerializationContext};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use rustls_pki_types::ServerName;

use super::{
    ConnectionPool, NetworkError, NetworkMessage, NetworkMessagePayloadItem, NetworkTransport,
    PeerState,
};
// Import PeerInfo and NodeInfo consistently with the module structure
use crate::network::discovery::multicast_discovery::PeerInfo;
use crate::network::discovery::NodeInfo;
use crate::network::transport::{
    MessageContext, MESSAGE_TYPE_ANNOUNCEMENT, MESSAGE_TYPE_DISCOVERY, MESSAGE_TYPE_ERROR,
    MESSAGE_TYPE_HANDSHAKE, MESSAGE_TYPE_HEARTBEAT, MESSAGE_TYPE_NODE_INFO_HANDSHAKE_RESPONSE,
    MESSAGE_TYPE_NODE_INFO_UPDATE, MESSAGE_TYPE_REQUEST, MESSAGE_TYPE_RESPONSE,
};

type MessageHandlerFn =
    Box<dyn Fn(NetworkMessage) -> Result<(), NetworkError> + Send + Sync + 'static>;

/// Stream correlation data for tracking request-response pairs
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct StreamCorrelation {
    peer_node_id: String,
    stream_id: u64,
    correlation_id: String,
    created_at: std::time::Instant,
}

/// Bidirectional stream storage for request-response communication
#[derive(Debug)]
#[allow(dead_code)]
struct BidirectionalStream {
    send_stream: quinn::SendStream,
    correlation_id: String,
    peer_node_id: String,
    created_at: std::time::Instant,
}

/// Message communication patterns
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum MessagePattern {
    /// One-way messages that don't expect responses (handshakes, announcements)
    OneWay,
    /// Request messages that expect responses (RPC calls)
    RequestResponse,
    /// Response messages sent back on existing streams
    Response,
}

/// Enhanced message wrapper with pattern information
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TransportMessage {
    message: NetworkMessage,
    pattern: MessagePattern,
    stream_correlation: Option<StreamCorrelation>,
}

/// QuicTransportImpl - Core implementation of QUIC transport
///
/// INTENTION: This component is the core implementation of the QUIC transport,
/// managing connections and stream handling. It contains all the protocol-specific logic.
///
/// ARCHITECTURAL BOUNDARIES:
/// - Only accessed by QuicTransport (public API wrapper) through Arc
/// - Never cloned directly, only the Arc is cloned
/// - Manages ConnectionPool instance and peer states
/// - Handles protocol-specific logic and connection management
/// - Does not manage threads, tasks, or public API surface
/// - Returns task handles to QuicTransport for lifecycle management
struct QuicTransportImpl {
    node_id: String,
    bind_addr: SocketAddr,
    // Using Mutex for proper interior mutability instead of unsafe pointer casting
    endpoint: Mutex<Option<Endpoint>>,
    connection_pool: Arc<ConnectionPool>,
    options: QuicTransportOptions,
    logger: Arc<Logger>,
    message_handler: Arc<StdRwLock<MessageHandlerFn>>,
    local_node: NodeInfo,
    // Channel for sending peer node info updates
    peer_node_info_sender: tokio::sync::broadcast::Sender<NodeInfo>,
    running: Arc<AtomicBool>,
    // Encryption context
    keystore: Arc<dyn runar_serializer::traits::EnvelopeCrypto>,
    label_resolver: Arc<dyn runar_serializer::traits::LabelResolver>,
    // Enhanced stream management for request-response pairs
    bidirectional_streams:
        Arc<tokio::sync::RwLock<std::collections::HashMap<String, BidirectionalStream>>>,
    stream_correlations:
        Arc<tokio::sync::RwLock<std::collections::HashMap<String, StreamCorrelation>>>,
}

/// Main QUIC transport implementation - Public API
///
/// INTENTION: This component provides the public API implementing NetworkTransport.
/// It is a thin wrapper around QuicTransportImpl which contains the actual logic.
///
/// ARCHITECTURAL BOUNDARIES:
/// - Exposes NetworkTransport trait to external callers
/// - Delegates protocol functionality to QuicTransportImpl
/// - Manages the lifecycle of the implementation
/// - Responsible for thread/task management
pub struct QuicTransport {
    // Internal implementation containing the actual logic
    inner: Arc<QuicTransportImpl>,
    // Keep logger and node_id at this level for compatibility
    logger: Arc<Logger>,
    node_id: String,
    // Encryption context owned by this transport
    keystore: Arc<dyn runar_serializer::traits::EnvelopeCrypto>,
    label_resolver: Arc<dyn runar_serializer::traits::LabelResolver>,
    // Background tasks for connection handling and message processing
    background_tasks: Mutex<Vec<JoinHandle<()>>>,
}

/// QUIC-specific transport options
pub struct QuicTransportOptions {
    // Original QUIC/TLS options
    certificates: Option<Vec<CertificateDer<'static>>>,
    private_key: Option<PrivateKeyDer<'static>>,
    root_certificates: Option<Vec<CertificateDer<'static>>>,
    connection_idle_timeout: Duration,
    keep_alive_interval: Duration,

    // New parameters moved from constructor
    local_node_info: Option<NodeInfo>,
    bind_addr: Option<SocketAddr>,
    message_handler: Option<super::MessageHandler>,
    logger: Option<Arc<Logger>>,
    keystore: Option<Arc<dyn runar_serializer::traits::EnvelopeCrypto>>,
    label_resolver: Option<Arc<dyn runar_serializer::traits::LabelResolver>>,
}

impl std::fmt::Debug for QuicTransportOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicTransportOptions")
            .field(
                "certificates",
                &self
                    .certificates
                    .as_ref()
                    .map(|c| format!("{} certificates", c.len())),
            )
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "Some(PrivateKey)"),
            )
            .field(
                "root_certificates",
                &self
                    .root_certificates
                    .as_ref()
                    .map(|c| format!("{} root certificates", c.len())),
            )
            .field("connection_idle_timeout", &self.connection_idle_timeout)
            .field("keep_alive_interval", &self.keep_alive_interval)
            .field("local_node_info", &self.local_node_info)
            .field("bind_addr", &self.bind_addr)
            .field(
                "message_handler",
                &if self.message_handler.is_some() {
                    "Some(MessageHandler)"
                } else {
                    "None"
                },
            )
            .field(
                "logger",
                &if self.logger.is_some() {
                    "Some(Logger)"
                } else {
                    "None"
                },
            )
            .field(
                "keystore",
                &if self.keystore.is_some() {
                    "Some(EnvelopeCrypto)"
                } else {
                    "None"
                },
            )
            .field(
                "label_resolver",
                &if self.label_resolver.is_some() {
                    "Some(LabelResolver)"
                } else {
                    "None"
                },
            )
            .finish()
    }
}

impl QuicTransportOptions {
    pub fn new() -> Self {
        Self::default()
    }

    // Original builder methods
    pub fn with_certificates(mut self, certs: Vec<CertificateDer<'static>>) -> Self {
        self.certificates = Some(certs);
        self
    }

    pub fn with_private_key(mut self, key: PrivateKeyDer<'static>) -> Self {
        self.private_key = Some(key);
        self
    }

    pub fn with_root_certificates(mut self, certs: Vec<CertificateDer<'static>>) -> Self {
        self.root_certificates = Some(certs);
        self
    }

    // New builder methods for moved parameters
    pub fn with_local_node_info(mut self, node_info: NodeInfo) -> Self {
        self.local_node_info = Some(node_info);
        self
    }

    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    pub fn with_message_handler(mut self, handler: super::MessageHandler) -> Self {
        self.message_handler = Some(handler);
        self
    }

    pub fn with_logger(mut self, logger: Arc<Logger>) -> Self {
        self.logger = Some(logger);
        self
    }

    pub fn with_keystore(
        mut self,
        keystore: Arc<dyn runar_serializer::traits::EnvelopeCrypto>,
    ) -> Self {
        self.keystore = Some(keystore);
        self
    }

    pub fn with_label_resolver(
        mut self,
        resolver: Arc<dyn runar_serializer::traits::LabelResolver>,
    ) -> Self {
        self.label_resolver = Some(resolver);
        self
    }

    // Getters for original options
    pub fn certificates(&self) -> Option<&Vec<CertificateDer<'static>>> {
        self.certificates.as_ref()
    }

    pub fn private_key(&self) -> Option<&PrivateKeyDer<'static>> {
        self.private_key.as_ref()
    }

    pub fn root_certificates(&self) -> Option<&Vec<CertificateDer<'static>>> {
        self.root_certificates.as_ref()
    }

    // Getters for new parameters
    pub fn local_node_info(&self) -> Option<&NodeInfo> {
        self.local_node_info.as_ref()
    }

    pub fn bind_addr(&self) -> Option<SocketAddr> {
        self.bind_addr
    }

    pub fn message_handler(&self) -> Option<&super::MessageHandler> {
        self.message_handler.as_ref()
    }

    pub fn logger(&self) -> Option<&Arc<Logger>> {
        self.logger.as_ref()
    }

    pub fn keystore(&self) -> Option<&Arc<dyn runar_serializer::traits::EnvelopeCrypto>> {
        self.keystore.as_ref()
    }

    pub fn label_resolver(&self) -> Option<&Arc<dyn runar_serializer::traits::LabelResolver>> {
        self.label_resolver.as_ref()
    }
}

impl Clone for QuicTransportOptions {
    fn clone(&self) -> Self {
        Self {
            certificates: self.certificates.clone(),
            private_key: self.private_key.as_ref().map(|key| key.clone_key()),
            root_certificates: self.root_certificates.clone(),
            connection_idle_timeout: self.connection_idle_timeout,
            keep_alive_interval: self.keep_alive_interval,
            local_node_info: self.local_node_info.clone(),
            bind_addr: self.bind_addr,
            message_handler: None, // MessageHandler doesn't implement Clone
            logger: self.logger.clone(),
            keystore: self.keystore.clone(),
            label_resolver: self.label_resolver.clone(),
        }
    }
}

/// Simple peer state used by the new transport.
#[derive(Debug)]
struct PeerState {
    connection: Arc<quinn::Connection>,
    node_info_version: i64,
}

impl PeerState {
    fn new(connection: Arc<quinn::Connection>, node_info_version: i64) -> Self {
        Self {
            connection,
            node_info_version,
        }
    }
}

/// Convert a compact ID to a DNS-safe format by replacing invalid characters
fn dns_safe_node_id(node_id: &str) -> String {
    node_id
        .chars()
        .map(|c| match c {
            '-' => 'x',                    // Replace hyphen with 'x'
            '_' => 'y',                    // Replace underscore with 'y'
            c if c.is_alphanumeric() => c, // Keep alphanumeric
            _ => 'z',                      // Replace any other invalid chars with 'z'
        })
    }

    /// Determine the communication pattern for a message
    ///
    /// INTENTION: Classify messages to use appropriate stream types and lifecycle management
    /// NOTE: Now using unidirectional streams for all messages including requests and responses
    fn classify_message_pattern(&self, message: &NetworkMessage) -> MessagePattern {
        match message.message_type {
            // One-way messages that don't expect responses
            MESSAGE_TYPE_HANDSHAKE
            | MESSAGE_TYPE_DISCOVERY
            | MESSAGE_TYPE_ANNOUNCEMENT
            | MESSAGE_TYPE_HEARTBEAT => MessagePattern::OneWay,
            // **CHANGE**: Request messages now use unidirectional streams too
            // The response will come back as a separate unidirectional stream
            MESSAGE_TYPE_REQUEST => MessagePattern::OneWay,
            // Response messages are sent back via separate unidirectional streams
            MESSAGE_TYPE_RESPONSE | MESSAGE_TYPE_ERROR => MessagePattern::OneWay,
            // Default to one-way for unknown message types
            _ => {
                self.logger.warn(format!(
                    "⚠️ [QuicTransport] Unknown message type '{}', treating as one-way",
                    message.message_type
                ));
                MessagePattern::OneWay
            }
        }
    }

    /// Store stream correlation for request-response tracking
    ///
    /// INTENTION: Store send streams for response handling
    async fn store_response_stream(
        &self,
        correlation_id: String,
        peer_node_id: String,
        send_stream: quinn::SendStream,
    ) -> Result<(), NetworkError> {
        let correlation = StreamCorrelation {
            peer_node_id: peer_node_id.clone(),
            stream_id: 0,
            correlation_id: correlation_id.clone(),
            created_at: std::time::Instant::now(),
        };

        self.logger.debug(format!(
            "📝 [QuicTransport] Storing response stream - ID: {correlation_id}, Peer: {peer_node_id}"
        ));

        {
            let mut correlations = self.stream_correlations.write().await;
            correlations.insert(correlation_id.clone(), correlation);
        }

        {
            let mut streams = self.bidirectional_streams.write().await;
            streams.insert(
                correlation_id.clone(),
                BidirectionalStream {
                    send_stream,
                    correlation_id: correlation_id.clone(),
                    peer_node_id,
                    created_at: std::time::Instant::now(),
                },
            );
        }

        Ok(())
    }

    /// Send a request message using bidirectional streams
    ///
    /// INTENTION: Use bidirectional streams and properly handle response receiving
    #[allow(dead_code)]
    async fn send_request_message(
        self: &Arc<Self>,
        peer_node_id: &String,
        message: NetworkMessage,
    ) -> Result<(), NetworkError> {
        self.logger.debug(format!(
            "🔄 [QuicTransport] Sending request message to peer {peer_node_id}"
        ));

        let peer_state = self.get_peer_state(peer_node_id)?;
        if !peer_state.is_connected().await {
            return Err(NetworkError::ConnectionError(format!(
                "Peer {peer_node_id} is not connected"
            )));
        }

        // Get bidirectional stream for request-response
        let connection = peer_state.get_connection().await.ok_or_else(|| {
            NetworkError::ConnectionError(format!("No connection to peer {peer_node_id}"))
        })?;

        let (mut send_stream, recv_stream) = connection.open_bi().await.map_err(|e| {
            NetworkError::ConnectionError(format!("Failed to open bidirectional stream: {e}"))
        })?;

        // Extract correlation ID for concurrent processing
        let correlation_id = message
            .payloads
            .first()
            .map(|p| p.correlation_id.clone())
            .unwrap_or_else(|| "unknown".to_string());

        // let _read_timeout = std::time::Duration::from_millis(5000);
        // let _correlation_id_clone = correlation_id.clone();

        self.logger.debug(format!(
            "🔄 [QuicTransport] Starting concurrent request/response for correlation ID: {correlation_id}"
        ));

        //TODO investive this further. We shoulod not have a contraint on using unidirectional streams.
        //if bidirectinal streams are better for exchaing message with a specific node. we shuold try to use it

        // **ARCHITECTURAL FIX**: Use unidirectional streams instead of bidirectional
        //
        // Key insight: The working quic_transport_test.rs uses separate unidirectional messages
        // for REQUEST and RESPONSE, not bidirectional streams. The Node layer expects this pattern
        // because it uses async oneshot channels for request-response.
        //
        // New flow:
        // 1. Client sends request via unidirectional stream
        // 2. Server receives request, processes it, sends response via separate unidirectional stream
        // 3. Both request and response flow through normal message processing pipeline
        // 4. Node.handle_network_response triggers RemoteService oneshot channel

        // Close the bidirectional streams since we won't use them
        send_stream.finish().map_err(|e| {
            NetworkError::MessageError(format!(
                "Failed to finish unused bidirectional send stream: {e}"
            ))
        })?;
        drop(recv_stream); // Don't need the bidirectional recv stream

        // Send the request via unidirectional stream instead
        self.send_oneway_message(peer_node_id, message).await?;

        self.logger.debug(format!(
            "✅ [QuicTransport] Request sent via unidirectional stream - Correlation ID: {correlation_id} (response will come via separate unidirectional stream)"
        ));

        Ok(())
    }

    /// Send a one-way message using unidirectional streams
    ///
    /// INTENTION: Use unidirectional streams for messages that don't expect responses
    async fn send_oneway_message(
        &self,
        peer_node_id: &String,
        message: NetworkMessage,
    ) -> Result<(), NetworkError> {
        self.logger.debug(format!(
            "📡 [QuicTransport] Sending one-way message to peer {peer_node_id}"
        ));

        let peer_state = self.get_peer_state(peer_node_id)?;
        if !peer_state.is_connected().await {
            return Err(NetworkError::ConnectionError(format!(
                "Peer {peer_node_id} is not connected"
            )));
        }

        // Get unidirectional stream for one-way messages
        let connection = peer_state.get_connection().await.ok_or_else(|| {
            NetworkError::ConnectionError(format!("No connection to peer {peer_node_id}"))
        })?;

        let mut stream = connection.open_uni().await.map_err(|e| {
            NetworkError::ConnectionError(format!("Failed to open unidirectional stream: {e}"))
        })?;

        // Send the message and finish the stream immediately
        self.write_message_to_stream(&mut stream, &message, peer_node_id)
            .await?;

        stream.finish().map_err(|e| {
            NetworkError::MessageError(format!("Failed to finish unidirectional stream: {e}"))
        })?;

        self.logger.debug(format!(
            "✅ [QuicTransport] One-way message sent and stream finished for peer {peer_node_id}"
        ));

        Ok(())
    }

    /// Send a response message using unidirectional streams
    ///
    /// INTENTION: Send responses via separate unidirectional streams, matching the new architecture
    #[allow(dead_code)]
    async fn send_response_message(
        &self,
        peer_node_id: &String,
        message: NetworkMessage,
    ) -> Result<(), NetworkError> {
        self.logger.debug(format!(
            "↩️ [QuicTransport] Sending response message to peer {peer_node_id}"
        ));

        // Extract correlation ID from the first payload
        let correlation_id = message
            .payloads
            .first()
            .map(|p| p.correlation_id.clone())
            .ok_or_else(|| {
                NetworkError::MessageError("Response message has no correlation ID".to_string())
            })?;

        // **NEW APPROACH**: Send response via unidirectional stream
        // This matches the new architecture where requests and responses are separate unidirectional streams
        // and ensures responses flow through the normal message processing pipeline on the client

        self.send_oneway_message(peer_node_id, message).await?;

        self.logger.debug(format!(
            "✅ [QuicTransport] Response sent via unidirectional stream - Correlation ID: {correlation_id}"
        ));

        Ok(())
    }

    /// Handle response stream for bidirectional request-response communication
    ///
    /// INTENTION: Read responses from recv_stream and process them through message handling
    #[allow(dead_code)]
    async fn handle_response_stream(
        self: &Arc<Self>,
        peer_node_id: String,
        recv_stream: quinn::RecvStream,
        correlation_id: String,
    ) -> Result<(), NetworkError> {
        self.logger.debug(format!(
            "🎧 [QuicTransport] Handling response stream for correlation ID: {correlation_id}"
        ));

        // Use the existing receive_message infrastructure to handle the response
        // This will read the message from the stream and process it properly
        self.receive_message(peer_node_id, recv_stream, None)
            .await?;

        self.logger.debug(format!(
            "✅ [QuicTransport] Response stream handled successfully for correlation ID: {correlation_id}"
        ));

        Ok(())
    }

    /// Helper method to get peer state with error handling
    fn get_peer_state(&self, peer_node_id: &String) -> Result<Arc<PeerState>, NetworkError> {
        self.connection_pool
            .get_peer(peer_node_id)
            .ok_or_else(|| NetworkError::ConnectionError(format!("Peer {peer_node_id} not found")))
    }

    /// Helper method to write a message to any stream type
    async fn write_message_to_stream<S>(
        &self,
        stream: &mut S,
        message: &NetworkMessage,
        peer_node_id: &String,
    ) -> Result<(), NetworkError>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        // Serialize the message
        let mut serialized_message = Vec::new();
        message
            .encode(&mut serialized_message)
            .map_err(|e| NetworkError::MessageError(format!("Failed to serialize message: {e}")))?;

        // Write message length first (4 bytes)
        let len_bytes = (serialized_message.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await.map_err(|e| {
            NetworkError::MessageError(format!("Failed to write message length: {e}"))
        })?;

        // Write the serialized message
        stream.write_all(&serialized_message).await.map_err(|e| {
            NetworkError::MessageError(format!("Failed to write message data: {e}"))
        })?;

        self.logger.debug(format!(
            "✅ [QuicTransport] Message written to stream - Peer: {}, Size: {} bytes",
            peer_node_id,
            serialized_message.len()
        ));

        Ok(())
    }

    /// Connect to a peer using the provided discovery message
    ///
    /// INTENTION: Establish a connection to a remote peer using the provided discovery information.
    /// This method will attempt to connect to each address in the discovery message until one succeeds.
    /// Returns a task handle for the message receiver.
    async fn connect_peer(
        self: &Arc<Self>,
        discovery_msg: PeerInfo,
    ) -> Result<JoinHandle<()>, NetworkError> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(NetworkError::TransportError(
                "Transport not running".to_string(),
            ));
        }

        // Ensure we have at least one address to try
        if discovery_msg.addresses.is_empty() {
            return Err(NetworkError::ConnectionError(
                "No addresses found for peer".to_string(),
            ));
        }

        // Get the peer ID based on the public_key from PeerInfo
        let peer_node_id = compact_id(&discovery_msg.public_key);

        // Check if we're already connected to this peer
        if self.connection_pool.is_peer_connected(&peer_node_id).await {
            self.logger
                .info(format!("Already connected to peer {peer_node_id}"));

            // Return a dummy task that does nothing
            let task = tokio::spawn(async {});
            return Ok(task);
        }

        // Get the endpoint
        let endpoint = match self.endpoint.lock().await.as_ref() {
            Some(endpoint) => endpoint.clone(),
            None => {
                return Err(NetworkError::TransportError(
                    "Transport not initialized".to_string(),
                ))
            }
        };

        // Try each address in the discovery message
        let mut last_error = None;

        for peer_addr in &discovery_msg.addresses {
            // Parse the socket address
            let socket_addr = match peer_addr.parse::<SocketAddr>() {
                Ok(addr) => addr,
                Err(e) => {
                    self.logger
                        .warn(format!("Invalid address {peer_addr}: {e}"));
                    last_error = Some(NetworkError::ConnectionError(format!(
                        "Invalid address {peer_addr}: {e}"
                    )));
                    continue; // Try the next address
                }
            };

            // Connect to the peer
            self.logger.info(format!(
                "Connecting to peer {peer_node_id} at {socket_addr}"
            ));

            // Print detailed connection information for debugging
            self.logger.info(format!(
                "Detailed connection attempt - Local node: {}, Remote peer: {}, Socket: {}",
                self.node_id, peer_node_id, socket_addr
            ));

            // Use the peer's node_id as the TLS Server Name so
            // our custom certificate verifier can ensure the presented certificate
            // actually belongs to that node.
            let connect_result = endpoint.connect(socket_addr, &peer_node_id);

            match connect_result {
                Ok(connecting) => {
                    // Wait for the connection to be established
                    match connecting.await {
                        Ok(connection) => {
                            self.logger
                                .info(format!("Connected to peer {peer_node_id} at {socket_addr}"));

                            // Get or create the peer state
                            let peer_state = self.connection_pool.get_or_create_peer(
                                peer_node_id.clone(),
                                peer_addr.clone(),
                                self.options.max_idle_streams_per_peer,
                                self.logger.clone(),
                            );

                            // Set the connection in the peer state
                            peer_state.set_connection(connection).await;

                            // Successfully connected to this address

                            // Start a task to receive incoming messages
                            let task = self
                                .spawn_message_receiver(peer_node_id.clone(), peer_state.clone());

                            // Verify the connection is properly registered
                            let is_connected =
                                self.connection_pool.is_peer_connected(&peer_node_id).await;
                            self.logger.info(format!(
                                "Connection verification for {peer_node_id}: {is_connected}"
                            ));

                            return Ok(task);
                        }
                        Err(e) => {
                            self.logger.warn(format!(
                                "Failed to connect to peer {peer_node_id} at {socket_addr}: {e}"
                            ));
                            last_error = Some(NetworkError::ConnectionError(format!(
                                "Failed to establish connection to {socket_addr}: {e}"
                            )));
                            // Continue to the next address
                        }
                    }
                }
                Err(e) => {
                    self.logger.warn(format!(
                        "Failed to initiate connection to peer {peer_node_id} at {socket_addr}: {e}"
                    ));
                    last_error = Some(NetworkError::ConnectionError(format!(
                        "Failed to initiate connection to {socket_addr}: {e}"
                    )));
                    // Continue to the next address
                }
            }
        }

        // If we get here, all connection attempts failed
        Err(last_error.unwrap_or_else(|| {
            NetworkError::ConnectionError(format!(
                "Failed to connect to peer {peer_node_id} on any address"
            ))
        }))
    }

    async fn update_peers(self: &Arc<Self>, node_info: NodeInfo) -> Result<(), NetworkError> {
        //for each connected peer send a NODE_INFO_UPDATE message
        let peers = self.connection_pool.get_connected_peers().await;
        for peer_node_id in peers {
            let message = NetworkMessage {
                source_node_id: self.node_id.clone(),
                destination_node_id: peer_node_id.clone(),
                message_type: MESSAGE_TYPE_NODE_INFO_UPDATE,
                payloads: vec![NetworkMessagePayloadItem {
                    path: "".to_string(),
                    value_bytes: {
                        let mut bytes = Vec::new();
                        serde_cbor::to_writer(&mut bytes, &node_info).unwrap();
                        bytes
                    },
                    correlation_id: "".to_string(),
                    context: None,
                }],
            };
            self.send_message(message).await?;
            self.logger.info(format!(
                "Sent NODE_INFO_UPDATE message to peer {peer_node_id}"
            ));
        }
        Ok(())
    }

    fn get_local_address(self: &Arc<Self>) -> String {
        self.bind_addr.to_string()
    }

    /// Perform handshake with a peer after connection is established
    ///
    /// INTENTION: Exchange node information with the peer to complete the connection setup.
    /// This is called after a successful connection to exchange node information.
    /// The peer's NodeInfo will be sent through the peer_node_info_sender channel.
    async fn handshake_peer(self: &Arc<Self>, peer_info: PeerInfo) -> Result<(), NetworkError> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(NetworkError::TransportError(
                "Transport not running".to_string(),
            ));
        }

        // Get the peer ID based on the public_key from PeerInfo
        let peer_node_id = compact_id(&peer_info.public_key);

        self.logger
            .info(format!("Starting handshake with peer {peer_node_id}"));

        // Check if we're connected to this peer
        if !self.connection_pool.is_peer_connected(&peer_node_id).await {
            return Err(NetworkError::ConnectionError(format!(
                "Not connected to peer {peer_node_id}, cannot perform handshake"
            )));
        }

        let correlation_id = format!(
            "handshake-{}-{}",
            self.node_id,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        );

        // Create a handshake message containing our node info
        let handshake_message = NetworkMessage {
            source_node_id: self.node_id.clone(),
            destination_node_id: peer_node_id.clone(),
            message_type: MESSAGE_TYPE_HANDSHAKE,
            payloads: vec![NetworkMessagePayloadItem {
                path: "".to_string(),
                value_bytes: {
                    let mut bytes = Vec::new();
                    serde_cbor::to_writer(&mut bytes, &self.local_node).map_err(|e| {
                        NetworkError::MessageError(format!("Failed to serialize node info: {e}"))
                    })?;
                    bytes
                },
                correlation_id,
                context: None,
            }],
        };

        // Send the handshake message
        self.send_message(handshake_message).await?;
        self.logger
            .info(format!("Sent handshake message to peer {peer_node_id}"));

        // The handshake response will be processed in process_incoming_message
        // and the peer_node_info will be sent through the channel there

        // Return success - the actual NodeInfo will be sent via the channel
        Ok(())
    }

    /// Process an incoming message
    ///
    /// INTENTION: Route an incoming message to registered handlers.
    async fn process_incoming_message(
        self: &Arc<Self>,
        message: NetworkMessage,
    ) -> Result<(), NetworkError> {
        // Special handling for handshake messages
        if message.message_type == MESSAGE_TYPE_HANDSHAKE
            || message.message_type == MESSAGE_TYPE_NODE_INFO_HANDSHAKE_RESPONSE
            || message.message_type == MESSAGE_TYPE_NODE_INFO_UPDATE
        {
            self.logger.debug(format!(
                "Received message from {} with type: {}",
                message.source_node_id, message.message_type
            ));

            // Extract the node info from the message
            if let Some(payload) = message.payloads.first() {
                match serde_cbor::from_slice::<NodeInfo>(payload.value_bytes.as_slice()) {
                    Ok(peer_node_info) => {
                        self.logger.debug(format!(
                            "Received node info from {}: {:?}",
                            message.source_node_id, peer_node_info
                        ));

                        // Store the node info in the peer state
                        if let Some(peer_state) =
                            self.connection_pool.get_peer(&message.source_node_id)
                        {
                            peer_state.set_node_info(peer_node_info.clone()).await;

                            if message.message_type == MESSAGE_TYPE_HANDSHAKE {
                                // Create the response message
                                let response = NetworkMessage {
                                    source_node_id: self.node_id.clone(),
                                    destination_node_id: message.source_node_id.clone(),
                                    message_type: MESSAGE_TYPE_NODE_INFO_HANDSHAKE_RESPONSE,
                                    payloads: vec![NetworkMessagePayloadItem {
                                        // Preserve the original path from the request
                                        path: payload.path.clone(),
                                        value_bytes: {
                                            let mut bytes = Vec::new();
                                            serde_cbor::to_writer(&mut bytes, &self.local_node)
                                                .map_err(|e| {
                                                    NetworkError::MessageError(format!(
                                                        "Failed to serialize node info: {e}"
                                                    ))
                                                })?;
                                            bytes
                                        },
                                        correlation_id: payload.correlation_id.clone(),
                                        context: None,
                                    }],
                                };

                                // Send the response
                                self.send_message(response).await?;
                                self.logger.debug(format!(
                                    "Sent handshake response to {}",
                                    message.source_node_id
                                ));
                            }
                        }

                        // Send to the channel - ignore errors if there are no subscribers
                        let _ = self.peer_node_info_sender.send(peer_node_info);
                    }
                    Err(e) => {
                        self.logger.error(format!(
                            "Failed to deserialize node info from {}: {}",
                            message.source_node_id, e
                        ));
                    }
                }
            }
            return Ok(());
        } else {
            self.logger.debug(format!(
                "Received message from {} with type: {}",
                message.source_node_id, message.message_type
            ));
        }

        // Get a read lock on the handlers
        match self.message_handler.read() {
            Ok(handler) => {
                if let Err(e) = handler(message.clone()) {
                    self.logger.error(format!("Error in message handler: {e}"));
                }
                Ok(())
            }
            Err(_) => Err(NetworkError::TransportError(
                "Failed to acquire read lock on message handlers".to_string(),
            )),
        }
    }

    /// Handle a new incoming connection
    ///
    /// INTENTION: Process an incoming connection request and set up the connection state.
    async fn handle_new_connection(
        self: &Arc<Self>,
        connection: quinn::Connection,
    ) -> Result<JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
        self.logger.debug("Handling new incoming connection");

        // Get connection info
        let remote_addr = connection.remote_address();

        self.logger
            .info(format!("New incoming connection from {remote_addr}"));

        // **CRITICAL FIX**: Don't create any peer state until we know the real peer ID
        // Spawn a task that waits for the handshake message to identify the peer
        let task = self.spawn_connection_identifier(connection);

        Ok(task)
    }

    /// Wait for the handshake message to identify the real peer and establish proper connection state
    ///
    /// INTENTION: Handle incoming connections by waiting for the NODE_INFO_HANDSHAKE message
    /// that contains the real peer ID (node public key), then properly manage the connection.
    fn spawn_connection_identifier(
        self: &Arc<Self>,
        connection: quinn::Connection,
    ) -> JoinHandle<()> {
        let inner_arc = self.clone();
        let logger = self.logger.clone();
        let remote_addr = connection.remote_address();

        tokio::spawn(async move {
            logger.debug(format!(
                "🔍 [QuicTransport] Waiting for peer identification from {remote_addr}"
            ));

            // **STEP 1**: Wait for the first unidirectional stream (should be handshake)
            match connection.accept_uni().await {
                Ok(recv_stream) => {
                    logger.debug(format!(
                        "🔄 [QuicTransport] Receiving handshake message from {remote_addr}"
                    ));

                    // **STEP 2**: Read and parse the handshake message to get real peer ID
                    match inner_arc.read_handshake_message(recv_stream).await {
                        Ok(message) => {
                            if message.message_type == MESSAGE_TYPE_HANDSHAKE {
                                // **STEP 3**: Extract the real peer ID from the handshake message
                                let real_peer_node_id = message.source_node_id.clone();

                                logger.info(format!(
                                    "✅ [QuicTransport] Identified peer: {real_peer_node_id} from {remote_addr}"
                                ));

                                // **STEP 4**: Check if we already have a connection to this peer
                                if inner_arc
                                    .connection_pool
                                    .is_peer_connected(&real_peer_node_id)
                                    .await
                                {
                                    logger.warn(format!(
                                        "⚠️  [QuicTransport] Peer {real_peer_node_id} already has active connection, closing duplicate from {remote_addr}"
                                    ));

                                    // Close this duplicate connection gracefully
                                    connection.close(1u32.into(), b"Duplicate connection");
                                } else {
                                    // **STEP 5**: This is the primary connection - establish proper peer state
                                    logger.info(format!(
                                        "🎯 [QuicTransport] Establishing primary connection for peer {real_peer_node_id} from {remote_addr}"
                                    ));

                                    // Create peer state with the real peer ID
                                    let peer_state = inner_arc.connection_pool.get_or_create_peer(
                                        real_peer_node_id.clone(),
                                        remote_addr.to_string(),
                                        inner_arc.options.max_idle_streams_per_peer,
                                        inner_arc.logger.clone(),
                                    );

                                    // Set the connection for the real peer
                                    peer_state.set_connection(connection.clone()).await;

                                    // **STEP 6**: Process the handshake message
                                    if let Err(e) =
                                        inner_arc.process_incoming_message(message).await
                                    {
                                        logger.error(format!("Error processing handshake: {e}"));
                                        return;
                                    }

                                    // **STEP 7**: Start the persistent message receiver for this peer
                                    logger.info(format!(
                                        "🔄 [QuicTransport] Starting message receiver for peer {real_peer_node_id}"
                                    ));

                                    // The message receiver will handle the connection from now on
                                    inner_arc
                                        .spawn_message_receiver_task(
                                            real_peer_node_id,
                                            peer_state,
                                            connection,
                                        )
                                        .await;
                                }
                            } else {
                                logger.warn(format!(
                                    "⚠️  [QuicTransport] Expected NODE_INFO_HANDSHAKE but got: {} from {}",
                                    message.message_type, remote_addr
                                ));
                                connection.close(2u32.into(), b"Invalid handshake");
                            }
                        }
                        Err(e) => {
                            logger.error(format!(
                                "❌ [QuicTransport] Failed to read handshake from {remote_addr}: {e}"
                            ));
                            connection.close(3u32.into(), b"Handshake failed");
                        }
                    }
                }
                Err(e) => {
                    logger.error(format!(
                        "❌ [QuicTransport] Failed to accept handshake stream from {remote_addr}: {e}"
                    ));
                }
            }
        })
    }

    /// Read a handshake message from a stream
    ///
    /// INTENTION: Parse the initial handshake message to identify the real peer
    async fn read_handshake_message(
        &self,
        mut recv_stream: quinn::RecvStream,
    ) -> Result<NetworkMessage, NetworkError> {
        // Read message length (4 bytes)
        let mut len_bytes = [0u8; 4];
        recv_stream.read_exact(&mut len_bytes).await.map_err(|e| {
            NetworkError::MessageError(format!("Failed to read handshake message length: {e}"))
        })?;

        let message_len = u32::from_be_bytes(len_bytes) as usize;
        if message_len > 1024 * 1024 {
            // 1MB limit
            return Err(NetworkError::MessageError(format!(
                "Handshake message too large: {message_len} bytes"
            )));
        }

        // Read the message data
        let mut message_data = vec![0u8; message_len];
        recv_stream
            .read_exact(&mut message_data)
            .await
            .map_err(|e| {
                NetworkError::MessageError(format!("Failed to read handshake message data: {e}"))
            })?;

        // Deserialize the message
        NetworkMessage::decode(message_data.as_slice()).map_err(|e| {
            NetworkError::MessageError(format!("Failed to deserialize handshake message: {e}"))
        })
    }

    /// Start the persistent message receiver task for an identified peer
    ///
    /// INTENTION: Handle ongoing message processing for a peer with known identity
    async fn spawn_message_receiver_task(
        self: &Arc<Self>,
        peer_node_id: String,
        peer_state: Arc<PeerState>,
        connection: quinn::Connection,
    ) {
        let inner_arc = self.clone();
        let logger = self.logger.clone();
        let peer_node_id_clone = peer_node_id.clone();

        // Spawn the message receiver as a background task
        tokio::spawn(async move {
            logger.info(format!(
                "🔄 [QuicTransport] Starting persistent message receiver for peer {peer_node_id_clone}"
            ));

            // **QUIC BEST PRACTICE**: Keep connection alive and process multiple streams
            loop {
                // **CRITICAL FIX**: Check connection health first
                if let Some(close_reason) = connection.close_reason() {
                    logger.info(format!(
                            "🔚 [QuicTransport] Connection to peer {peer_node_id_clone} closed: {close_reason:?}"
                        ));
                    break;
                }

                // Use tokio::select! to listen for both uni and bidirectional streams
                tokio::select! {
                    // Listen for unidirectional streams (handshakes, announcements, etc.)
                    uni_result = connection.accept_uni() => {
                        match uni_result {
                            Ok(recv_stream) => {
                                logger.debug(format!(
                                    "🔄 [QuicTransport] Accepting unidirectional stream from peer {peer_node_id_clone}"
                                ));

                                // Process unidirectional message (no send stream for response)
                                if let Err(e) = inner_arc
                                    .receive_message(peer_node_id_clone.clone(), recv_stream, None)
                                    .await
                                {
                                    logger.error(format!(
                                        "Error receiving unidirectional message from {peer_node_id_clone}: {e}"
                                    ));
                                }
                            }
                            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                                logger.info(format!("Connection closed by peer {peer_node_id_clone}"));
                                break;
                            }
                            Err(e) => {
                                logger.error(format!("Unidirectional connection error from {peer_node_id_clone}: {e}"));
                                break;
                            }
                        }
                    }
                    // Listen for bidirectional streams (requests, responses)
                    bi_result = connection.accept_bi() => {
                        match bi_result {
                            Ok((send_stream, recv_stream)) => {
                                logger.debug(format!(
                                    "🔄 [QuicTransport] Accepting bidirectional stream from peer {peer_node_id_clone}"
                                ));

                                // Process bidirectional message with send stream for responses
                                if let Err(e) = inner_arc
                                    .receive_message(peer_node_id_clone.clone(), recv_stream, Some(send_stream))
                                    .await
                                {
                                    logger.error(format!(
                                        "Error receiving bidirectional message from {peer_node_id_clone}: {e}"
                                    ));
                                }
                            }
                            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                                logger.info(format!("Connection closed by peer {peer_node_id_clone}"));
                                break;
                            }
                            Err(e) => {
                                logger.error(format!("Bidirectional connection error from {peer_node_id_clone}: {e}"));
                                break;
                            }
                        }
                    }
                    // **CRITICAL**: Add a keep-alive mechanism to prevent connection timeout
                    _ = tokio::time::sleep(inner_arc.options.keep_alive_interval) => {
                        // Update activity to keep connection alive
                        peer_state.update_activity().await;

                        // Check connection health
                        if !peer_state.is_connected().await {
                            logger.warn(format!(
                                "⚠️  [QuicTransport] Connection health check failed for peer {peer_node_id_clone}"
                            ));
                            break;
                        }
                    }
                }
            }

            logger.info(format!(
                "🔚 [QuicTransport] Message receiver stopped for peer {peer_node_id_clone}"
            ));

            // Clean up peer state when connection ends
            inner_arc
                .connection_pool
                .remove_peer(&peer_node_id_clone)
                .await
                .ok();
        });
    }

    fn spawn_message_receiver(
        self: &Arc<Self>,
        peer_node_id: String,
        peer_state: Arc<PeerState>,
    ) -> JoinHandle<()> {
        // This is the legacy method that's still called in some places
        // It should get the connection from peer_state and delegate to the new method
        let inner_arc = self.clone();
        let logger = self.logger.clone();
        let peer_node_id_clone = peer_node_id.clone();

        tokio::spawn(async move {
            if let Some(connection) = peer_state.get_connection().await {
                // Delegate to the new method
                inner_arc
                    .spawn_message_receiver_task(peer_node_id_clone, peer_state, connection)
                    .await;
            } else {
                logger.warn(format!(
                    "❌ [QuicTransport] No connection available for peer {peer_node_id_clone}"
                ));
            }
        })
    }

    /// Receive and process a message from a stream
    ///
    /// INTENTION: Process incoming messages on both unidirectional and bidirectional streams
    /// For bidirectional streams, store the send stream for potential responses
    async fn receive_message(
        self: &Arc<Self>,
        peer_node_id: String,
        mut recv_stream: quinn::RecvStream,
        send_stream: Option<quinn::SendStream>,
    ) -> Result<(), NetworkError> {
        self.logger.debug(format!(
            "📥 [QuicTransport] Processing message from peer {peer_node_id}"
        ));

        // Read message length (4 bytes)
        let mut len_bytes = [0u8; 4];
        recv_stream.read_exact(&mut len_bytes).await.map_err(|e| {
            NetworkError::MessageError(format!("Failed to read message length: {e}"))
        })?;

        let message_len = u32::from_be_bytes(len_bytes) as usize;
        if message_len > 1024 * 1024 {
            // 1MB limit
            return Err(NetworkError::MessageError(format!(
                "Message too large: {message_len} bytes"
            )));
        }

        // Read the message data
        let mut message_data = vec![0u8; message_len];
        recv_stream
            .read_exact(&mut message_data)
            .await
            .map_err(|e| NetworkError::MessageError(format!("Failed to read message data: {e}")))?;

        // Deserialize the message
        let message = NetworkMessage::decode(message_data.as_slice()).map_err(|e| {
            NetworkError::MessageError(format!("Failed to deserialize message: {e}"))
        })?;

        self.logger.debug(format!(
            "📥 [QuicTransport] Received message from {} - Type: {}, Path: {}",
            peer_node_id,
            message.message_type,
            message
                .payloads
                .first()
                .map(|p| &p.path)
                .unwrap_or(&"".to_string())
        ));

        // For bidirectional streams with requests, store the send stream for direct response
        if let Some(send_stream) = send_stream {
            if let Some(payload) = message.payloads.first() {
                // Only store if this is a request (expects a response)
                if message.message_type == MESSAGE_TYPE_REQUEST {
                    self.logger.debug(format!(
                        "🔗 [QuicTransport] Storing send stream for incoming request - Correlation ID: {}, From: {}",
                        payload.correlation_id, peer_node_id
                    ));

                    // Store the send stream using the correlation ID for direct response
                    self.store_response_stream(
                        payload.correlation_id.clone(),
                        peer_node_id.clone(),
                        send_stream,
                    )
                    .await?;
                }
            }
        }

        // CRITICAL FIX: Call process_incoming_message which handles handshake messages properly
        // This ensures NODE_INFO_HANDSHAKE messages are processed in the transport layer
        // and only non-handshake messages are passed to the node via message_handler
        self.process_incoming_message(message).await?;

        Ok(())
    }

    /// Retrieve and remove a stored stream for sending a response
    ///
    /// INTENTION: Get the original stream associated with a request to send the response back
    #[allow(dead_code)]
    async fn get_response_stream(&self, correlation_id: &str) -> Option<BidirectionalStream> {
        self.logger.debug(format!(
            "🔍 [QuicTransport] Looking for response stream for correlation ID: {correlation_id}"
        ));

        let stream = {
            let mut streams = self.bidirectional_streams.write().await;
            streams.remove(correlation_id)
        };

        if stream.is_some() {
            // Also remove the correlation metadata
            let mut correlations = self.stream_correlations.write().await;
            correlations.remove(correlation_id);

            self.logger.debug(format!(
                "✅ [QuicTransport] Found and removed response stream for correlation ID: {correlation_id}"
            ));
        } else {
            self.logger.warn(format!(
                "❌ [QuicTransport] No response stream found for correlation ID: {correlation_id}"
            ));
        }

        stream
    }

    /// Clean up expired stream correlations
    ///
    /// INTENTION: Remove old correlations to prevent memory leaks
    async fn cleanup_expired_correlations(&self) {
        let now = std::time::Instant::now();
        let timeout = Duration::from_secs(300); // 5 minutes

        let mut expired_ids = Vec::new();

        {
            let correlations = self.stream_correlations.read().await;
            for (id, correlation) in correlations.iter() {
                if now.duration_since(correlation.created_at) > timeout {
                    expired_ids.push(id.clone());
                }
            }
        }

        if !expired_ids.is_empty() {
            self.logger.debug(format!(
                "🧹 [QuicTransport] Cleaning up {} expired stream correlations",
                expired_ids.len()
            ));

            let mut streams = self.bidirectional_streams.write().await;
            let mut correlations = self.stream_correlations.write().await;

            for id in expired_ids {
                streams.remove(&id);
                correlations.remove(&id);
            }
        }
    }

    /// Create QUIC server and client configurations
    ///
    /// INTENTION: Set up the TLS and transport configurations for QUIC connections.
    fn create_quinn_configs(
        self: &Arc<Self>,
    ) -> Result<(ServerConfig, ClientConfig), NetworkError> {
        self.logger
            .info("Creating Quinn configurations with certificates");

        // Install default crypto provider for rustls 0.23.x if not already installed
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("Failed to install default crypto provider");
        }

        // Get certificates, private key, and verifier from options
        let certificates = self.options.certificates().ok_or_else(|| {
            NetworkError::ConfigurationError("No certificates provided".to_string())
        })?;

        let private_key = self.options.private_key().ok_or_else(|| {
            NetworkError::ConfigurationError("No private key provided".to_string())
        })?;

        self.logger.info(format!(
            "Using {} certificates for QUIC with proper private key",
            certificates.len()
        ));

        // **CRITICAL FIX**: Create custom TransportConfig with our timeout settings
        let mut transport_config = quinn::TransportConfig::default();

        // Apply our connection idle timeout (convert Duration to milliseconds for VarInt)
        let idle_timeout_ms = self.options.connection_idle_timeout.as_millis() as u64;
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(
            quinn::VarInt::from_u64(idle_timeout_ms).unwrap(),
        )));

        // Apply our keep-alive interval
        transport_config.keep_alive_interval(Some(self.options.keep_alive_interval));

        self.logger.info(format!(
            "🔧 [QuicTransport] Configured transport timeouts - Idle: {}ms, Keep-alive: {}ms",
            idle_timeout_ms,
            self.options.keep_alive_interval.as_millis()
        ));

        let transport_config = Arc::new(transport_config);

        // Create server configuration using Quinn 0.11.x API with custom transport config
        let mut server_config =
            ServerConfig::with_single_cert(certificates.clone(), private_key.clone_key()).map_err(
                |e| {
                    NetworkError::ConfigurationError(format!("Failed to create server config: {e}"))
                },
            )?;

        // Apply the transport config to server
        server_config.transport_config(transport_config.clone());

        // Create client configuration using custom server name verifier for node IDs
        let rustls_client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NodeIdServerNameVerifier))
            .with_no_client_auth();

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client_config).map_err(
                |e| {
                    NetworkError::ConfigurationError(format!(
                        "Failed to convert rustls config: {e}"
                    ))
                },
            )?,
        ));

        // Apply the transport config to client
        client_config.transport_config(transport_config);

        self.logger.info(
            "Successfully created Quinn server and client configurations with custom timeouts",
        );

        Ok((server_config, client_config))
    }

    /// Start the QUIC transport
    ///
    /// INTENTION: Initialize the endpoint and start accepting connections.
    async fn start(
        self: &Arc<Self>,
        background_tasks: &Mutex<Vec<JoinHandle<()>>>,
    ) -> Result<(), NetworkError> {
        if self.running.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.logger.info(format!(
            "Starting QUIC transport on {bind_addr}",
            bind_addr = self.bind_addr
        ));

        // Create configurations for the QUIC endpoint
        let (server_config, client_config) = self.create_quinn_configs()?;

        // Create the endpoint with the server configuration
        let bind_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), self.bind_addr.port());
        self.logger
            .info(format!("Creating endpoint bound to {bind_addr}"));

        let mut endpoint = Endpoint::server(server_config, bind_addr)
            .map_err(|e| NetworkError::TransportError(format!("Failed to create endpoint: {e}")))?;

        endpoint.set_default_client_config(client_config);

        self.logger
            .info("Endpoint created successfully with server and client configs");

        let mut endpoint_guard = self.endpoint.lock().await;
        *endpoint_guard = Some(endpoint.clone());

        let inner_arc = Arc::clone(self);
        let task = tokio::spawn(async move {
            inner_arc.accept_connections(endpoint).await;
        });

        let mut tasks = background_tasks.lock().await;
        tasks.push(task);

        self.running.store(true, Ordering::Relaxed);
        self.logger.info("QUIC transport started successfully");

        Ok(())
    }

    /// Accept incoming connections
    ///
    /// INTENTION: Listen for and handle incoming QUIC connections.
    async fn accept_connections(self: &Arc<Self>, endpoint: Endpoint) {
        self.logger.info("Accepting incoming connections");

        while self.running.load(Ordering::Relaxed) {
            match endpoint.accept().await {
                Some(incoming) => {
                    let inner_arc = Arc::clone(self);
                    let logger = self.logger.clone();
                    tokio::spawn(async move {
                        match incoming.await {
                            Ok(connection) => {
                                match inner_arc.handle_new_connection(connection).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        logger.error(format!("Error handling connection: {e}"))
                                    }
                                }
                            }
                            Err(e) => logger.error(format!("Error accepting connection: {e}")),
                        }
                    });
                }
                None => {
                    self.logger
                        .info("Endpoint closed, no longer accepting connections");
                    break;
                }
            }
        }
    }

    /// Stop the QUIC transport
    ///
    /// INTENTION: Gracefully shut down the transport and clean up resources.
    async fn stop(
        self: &Arc<Self>,
        background_tasks: &Mutex<Vec<JoinHandle<()>>>,
    ) -> Result<(), NetworkError> {
        if !self.running.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.running.store(false, Ordering::Relaxed);

        let endpoint_guard = self.endpoint.lock().await;
        if let Some(endpoint) = &*endpoint_guard {
            endpoint.close(0u32.into(), b"Transport stopped");
        }

        let mut tasks = background_tasks.lock().await;
        for task in tasks.drain(..) {
            let _ = task.await;
        }

        self.logger.info("QUIC transport stopped");
        Ok(())
    }

    /// Disconnect from a peer
    ///
    /// INTENTION: Properly clean up resources when disconnecting from a peer.
    async fn disconnect(self: &Arc<Self>, peer_node_id: String) -> Result<(), NetworkError> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(NetworkError::TransportError(
                "Transport not running".to_string(),
            ));
        }

        self.connection_pool.remove_peer(&peer_node_id).await
    }

    /// Check if connected to a specific peer
    ///
    /// INTENTION: Determine if there's an active connection to the specified peer.
    async fn is_connected(self: &Arc<Self>, peer_node_id: String) -> bool {
        self.connection_pool.is_peer_connected(&peer_node_id).await
    }

    async fn send_request(
        self: &Arc<Self>,
        topic_path: &TopicPath,
        params: Option<ArcValue>,
        request_id: &str,
        peer_node_id: &str,
        context: MessageContext,
    ) -> Result<(), NetworkError> {
        let network_id = topic_path.network_id();

        let profile_id = compact_id(&context.profile_public_key);

        // Create serialization context for encryption
        let serialization_context = runar_serializer::traits::SerializationContext::new(
            self.keystore.clone(),
            self.label_resolver.clone(),
            network_id,
            profile_id,
        );

        let payload_vec: Vec<u8> = if let Some(params) = params {
            params
                .serialize(Some(&serialization_context))
                .map_err(|e| {
                    NetworkError::TransportError(format!("Failed to serialize params: {e}"))
                })?
        } else {
            ArcValue::null()
                .serialize(Some(&serialization_context))
                .map_err(|e| {
                    NetworkError::TransportError(format!("Failed to serialize params: {e}"))
                })?
        };

        // Create the network message
        let message = NetworkMessage {
            source_node_id: self.node_id.clone(),
            destination_node_id: peer_node_id.to_string(),
            message_type: MESSAGE_TYPE_REQUEST,
            payloads: vec![NetworkMessagePayloadItem {
                path: topic_path.as_str().to_string(),
                value_bytes: payload_vec,
                correlation_id: request_id.to_string(),
                context: Some(context),
            }],
        };

        // Send the message using the existing send_message infrastructure
        self.send_message(message).await
    }

    /// Send a message to a peer using appropriate stream patterns
    ///
    /// INTENTION: Route messages through proper stream types based on communication patterns
    async fn send_message(self: &Arc<Self>, message: NetworkMessage) -> Result<(), NetworkError> {
        if !self.running.load(Ordering::Relaxed) {
            self.logger
                .error("🚫 [QuicTransport] Transport not running - cannot send message");
            return Err(NetworkError::TransportError(
                "Transport not running".to_string(),
            ));
        }

        let peer_node_id = message.destination_node_id.clone();
        let message_pattern = self.classify_message_pattern(&message);

        self.logger.info(format!(
            "📤 [QuicTransport] Sending message - To: {}, Type: {}, Pattern: {:?}, Payloads: {}",
            peer_node_id,
            message.message_type,
            message_pattern,
            message.payloads.len()
        ));

        // Cleanup expired correlations periodically
        tokio::spawn({
            let transport = Arc::clone(self);
            async move {
                transport.cleanup_expired_correlations().await;
            }
        });

        // Handle different message patterns with appropriate strategies
        match message_pattern {
            MessagePattern::OneWay => self.send_oneway_message(&peer_node_id, message).await,
            MessagePattern::RequestResponse => {
                // This pattern should no longer be used since we changed classification
                // But keeping for safety - treat as one-way
                self.logger.warn(
                    "⚠️ [QuicTransport] RequestResponse pattern should not be used anymore, treating as OneWay".to_string()
                );
                self.send_oneway_message(&peer_node_id, message).await
            }
            MessagePattern::Response => {
                // Responses now use unidirectional streams too
                self.send_oneway_message(&peer_node_id, message).await
            }
        }
    }

    /// Read a response from a bidirectional stream following proper Quinn lifecycle
    ///
    /// INTENTION: Read response data from the receive side of a bidirectional stream
    /// after the client has finished sending the request. This follows Quinn's expected
    /// pattern where the server finishes their send side after writing the response.
    /// Handle a single response stream (for responses to requests we initiated)
    #[allow(dead_code)]
    async fn handle_single_stream_response(
        self: &Arc<Self>,
        peer_node_id: String,
        recv_stream: quinn::RecvStream,
        correlation_id: String,
    ) -> Result<(), NetworkError> {
        // This is similar to the logic in receive_message but specifically for response streams
        self.logger.debug(format!(
            "🔄 [QuicTransport] Processing response stream for correlation ID: {correlation_id}"
        ));

        // Use the existing receive_message infrastructure to handle the response
        // Pass None for send_stream since this is just a response, not a new bidirectional stream
        self.receive_message(peer_node_id, recv_stream, None).await
    }

    #[allow(dead_code)]
    async fn read_response_from_stream(
        &self,
        recv_stream: &mut quinn::RecvStream,
        correlation_id: &str,
    ) -> Result<NetworkMessage, NetworkError> {
        Self::read_response_from_stream_static(recv_stream, correlation_id, &self.logger).await
    }

    /// Static version for use in spawned tasks
    #[allow(dead_code)]
    async fn read_response_from_stream_static(
        recv_stream: &mut quinn::RecvStream,
        correlation_id: &str,
        logger: &Arc<Logger>,
    ) -> Result<NetworkMessage, NetworkError> {
        logger.debug(format!(
            "📖 [QuicTransport] Reading response from stream for correlation ID: {correlation_id}"
        ));

        // Read message length (4 bytes)
        let mut len_bytes = [0u8; 4];
        match recv_stream.read_exact(&mut len_bytes).await {
            Ok(_) => {}
            Err(e) => {
                // Handle Quinn-specific errors - ReadExactError doesn't have kind() method
                return Err(NetworkError::MessageError(format!(
                    "Failed to read response length for {correlation_id}: {e}"
                )));
            }
        }

        let message_len = u32::from_be_bytes(len_bytes) as usize;
        if message_len > 1024 * 1024 {
            // 1MB limit
            return Err(NetworkError::MessageError(format!(
                  "Response message too large: {message_len} bytes for correlation ID: {correlation_id}"
              )));
        }

        // Read the message data
        let mut message_data = vec![0u8; message_len];
        recv_stream
            .read_exact(&mut message_data)
            .await
            .map_err(|e| {
                NetworkError::MessageError(format!(
                    "Failed to read response data for {correlation_id}: {e}"
                ))
            })?;

        // Deserialize the response message
        let message = NetworkMessage::decode(message_data.as_slice()).map_err(|e| {
            NetworkError::MessageError(format!(
                "Failed to deserialize response for {correlation_id}: {e}"
            ))
        })?;

        logger.debug(format!(
            "✅ [QuicTransport] Successfully read response from stream - Correlation ID: {}, Message Type: {}, Size: {} bytes",
            correlation_id, message.message_type, message_len
        ));

        Ok(message)
    }
}

#[derive(Clone, Debug)]
struct SharedState {
    peers: PeerMap,
    connection_id_to_peer_id: ConnectionIdToPeerIdMap,
}
type PeerMap = Arc<RwLock<HashMap<String, PeerState>>>;
type ConnectionIdToPeerIdMap = Arc<RwLock<HashMap<usize, String>>>;

    async fn stop(&self) -> Result<(), NetworkError> {
        self.inner.stop(&self.background_tasks).await
    }

    async fn disconnect(&self, peer_node_id: String) -> Result<(), NetworkError> {
        self.inner.disconnect(peer_node_id).await
    }

    async fn is_connected(&self, peer_node_id: String) -> bool {
        self.inner.is_connected(peer_node_id).await
    }

    async fn send_message(&self, message: NetworkMessage) -> Result<(), NetworkError> {
        self.inner.send_message(message).await
    }

    async fn send_request(
        &self,
        topic_path: &TopicPath,
        params: Option<ArcValue>,
        request_id: &str,
        peer_node_id: &str,
        context: MessageContext,
    ) -> Result<(), NetworkError> {
        self.inner
            .send_request(topic_path, params, request_id, peer_node_id, context)
            .await
    }

    async fn connect_peer(&self, discovery_msg: PeerInfo) -> Result<(), NetworkError> {
        // Call the inner implementation which returns a task handle
        match self.inner.connect_peer(discovery_msg.clone()).await {
            Ok(task) => {
                // Store the task handle for proper lifecycle management
                let mut tasks = self.background_tasks.lock().await;
                tasks.push(task);

                // After connection is established, start the handshake process
                // Send the node info to the peer and wait for the response
                match self.inner.handshake_peer(discovery_msg).await {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        self.logger
                            .error(format!("Handshake failed after successful connection: {e}"));
                        Err(e)
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Update the list of connected peers with the latest node info
    async fn update_peers(&self, node_info: NodeInfo) -> Result<(), NetworkError> {
        self.inner.update_peers(node_info).await
    }

    fn get_local_address(&self) -> String {
        self.inner.get_local_address()
    }

    /// Subscribe to peer node info updates
    ///
    /// INTENTION: Allow callers to subscribe to peer node info updates when they are received
    /// during handshakes. This is used by the Node to create RemoteService instances.
    async fn subscribe_to_peer_node_info(&self) -> tokio::sync::broadcast::Receiver<NodeInfo> {
        self.inner.peer_node_info_sender.subscribe()
    }

    fn keystore(&self) -> Arc<dyn runar_serializer::traits::EnvelopeCrypto> {
        self.keystore.clone()
    }

    fn label_resolver(&self) -> Arc<dyn runar_serializer::traits::LabelResolver> {
        self.label_resolver.clone()
    }
}

#[derive(Debug)]
struct NodeIdServerNameVerifier;

impl rustls::client::danger::ServerCertVerifier for NodeIdServerNameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // DNS names are our chunked representation; remove dots to compare with raw node_id.
        let expected_chunked = match server_name {
            ServerName::DnsName(dns) => dns.as_ref(),
            _ => {
                return Err(rustls::Error::General(
                    "Unsupported server name type in verifier".into(),
                ));
            }
        };

        // The server name is already in DNS-safe format, and certificates now contain DNS-safe format
        // So we can compare directly without conversion
        let expected_raw = expected_chunked.to_string();

        // Parse end-entity certificate DER to inspect subject/SAN
        let (_, parsed) = parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("Unable to parse X509 certificate".into()))?;

        // Check SubjectAlternativeName DNS entries
        let san_match = parsed
            .extensions()
            .iter()
            .filter_map(|ext| {
                if let ParsedExtension::SubjectAlternativeName(san) = &ext.parsed_extension() {
                    Some(san.general_names.iter().any(|gn| match gn {
                        GeneralName::DNSName(name) => {
                            let candidate: String = name.chars().filter(|c| *c != '.').collect();
                            candidate == expected_raw
                        }
                        _ => false,
                    }))
                } else {
                    None
                }
            })
            .any(|b| b);

        // Check CommonName as fallback (legacy)
        let cn_match = parsed
            .subject()
            .iter_common_name()
            .any(|cn| cn.as_str().map(|s| s == expected_raw).unwrap_or(false));

        if !(san_match || cn_match) {
            return Err(rustls::Error::General(
                "Certificate subject/SAN does not match node_id".into(),
            ));
        }

        // Further chain validation can be added here (TODO) – currently handled at
        // the application layer after handshake.

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

pub struct QuicTransport {
    // immutable configuration
    local_node_info: NodeInfo,
    bind_addr: SocketAddr,
    options: QuicTransportOptions,

    // runtime state
    endpoint: Arc<RwLock<Option<Endpoint>>>,
    logger: Arc<Logger>,

    // callback into Node layer
    message_handler: super::MessageHandler,

    // crypto helpers
    keystore: Arc<dyn runar_serializer::traits::EnvelopeCrypto>,
    label_resolver: Arc<dyn runar_serializer::traits::LabelResolver>,

    // shared runtime state (peers + broadcast)
    state: SharedState,

    // background tasks
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,

    running: tokio::sync::RwLock<bool>,
}

impl QuicTransport {
    pub fn new(
        mut options: QuicTransportOptions,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Extract required parameters from options
        let local_node_info = options
            .local_node_info
            .take()
            .ok_or("local_node_info is required")?;
        let bind_addr = options.bind_addr.take().ok_or("bind_addr is required")?;
        let message_handler = options
            .message_handler
            .take()
            .ok_or("message_handler is required")?;
        let logger = (options.logger.take().ok_or("logger is required")?)
            .with_component(runar_common::Component::Transporter);
        let keystore = options.keystore.take().ok_or("keystore is required")?;
        let label_resolver = options
            .label_resolver
            .take()
            .ok_or("label_resolver is required")?;

        if rustls::crypto::CryptoProvider::get_default().is_none() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("Failed to install default crypto provider");
        }

        Ok(Self {
            local_node_info,
            bind_addr,
            options,
            endpoint: Arc::new(RwLock::new(None)),
            logger: Arc::new(logger),
            message_handler,
            keystore,
            label_resolver,
            state: Self::shared_state(),
            tasks: Mutex::new(Vec::new()),
            running: tokio::sync::RwLock::new(false),
        })
    }

    fn build_quinn_configs(&self) -> Result<(ServerConfig, ClientConfig), NetworkError> {
        let certs = self
            .options
            .certificates()
            .ok_or(NetworkError::ConfigurationError("no certs".into()))?;
        let key = self
            .options
            .private_key()
            .ok_or(NetworkError::ConfigurationError("no key".into()))?
            .clone_key();

        let mut transport_config = quinn::TransportConfig::default();

        // Apply our connection idle timeout (convert Duration to milliseconds for VarInt)
        let idle_timeout_ms = self.options.connection_idle_timeout.as_millis() as u64;
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(
            quinn::VarInt::from_u64(idle_timeout_ms).unwrap(),
        )));

        // Apply our keep-alive interval
        transport_config.keep_alive_interval(Some(self.options.keep_alive_interval));

        self.logger.info(format!(
            "Configured transport timeouts - Idle: {}ms, Keep-alive: {}ms",
            idle_timeout_ms,
            self.options.keep_alive_interval.as_millis()
        ));

        let transport_config = Arc::new(transport_config);

        // Create server configuration using Quinn 0.11.x API with custom transport config
        let server_config = ServerConfig::with_single_cert(certs.clone(), key.clone_key())
            .map_err(|e| {
                NetworkError::ConfigurationError(format!("Failed to create server config: {e}"))
            })?;

        let rustls_client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NodeIdServerNameVerifier))
            .with_no_client_auth();

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client_config).map_err(
                |e| {
                    NetworkError::ConfigurationError(format!(
                        "Failed to convert rustls config: {e}"
                    ))
                },
            )?,
        ));

        // Apply the transport config to client
        client_config.transport_config(transport_config);

        self.logger.info(
            "Successfully created Quinn server and client configurations with custom timeouts",
        );

        Ok((server_config, client_config))
    }

    fn spawn_accept_loop(self: Arc<Self>, endpoint: Endpoint) -> tokio::task::JoinHandle<()> {
        let endpoint = Arc::new(RwLock::new(Some(endpoint)));
        let self_clone = self.clone();
        tokio::spawn(async move {
            loop {
                let connecting = {
                    let guard = endpoint.read().await;
                    if let Some(ep) = guard.as_ref() {
                        ep.accept().await
                    } else {
                        break;
                    }
                };
                if let Some(connecting) = connecting {
                    match connecting.await {
                        Ok(conn) => {
                            // For inbound, we don't have peer_id yet; handshake will identify.
                            // Spawn tasks anyway and let first bi-stream be handshake.
                            let task = self_clone
                                .clone()
                                .spawn_connection_tasks("inbound".to_string(), Arc::new(conn));
                            self_clone.tasks.lock().await.push(task);
                        }
                        Err(e) => self_clone.logger.error(format!("accept failed: {e}")),
                    }
                }
            }
        })
    }

    fn spawn_connection_tasks(
        self: Arc<Self>,
        peer_id: String,
        conn: Arc<quinn::Connection>,
    ) -> tokio::task::JoinHandle<()> {
        let self_clone = self.clone();

        tokio::spawn(async move {
            let needs_to_correlate_peer_id = peer_id == "inbound";
            tokio::select! {
                res = self_clone.uni_accept_loop(conn.clone()) => if let Err(e) = res { self_clone.logger.error(format!("uni loop failed: {e}")) },
                res = self_clone.bi_accept_loop(conn.clone(), needs_to_correlate_peer_id) => if let Err(e) = res { self_clone.logger.error(format!("bi loop failed: {e}")) },
            }
            let resolved_peer_id = if needs_to_correlate_peer_id {
                let connection_id = conn.stable_id();
                match self_clone
                    .state
                    .connection_id_to_peer_id
                    .read()
                    .await
                    .get(&connection_id)
                {
                    Some(peer_id) => peer_id.clone(),
                    None => {
                        self_clone.logger.error(format!("Connection id {connection_id} not found in connection id to peer id map"));
                        return;
                    }
                }
            } else {
                peer_id
            };
            // remove from peers on exit
            self_clone
                .state
                .peers
                .write()
                .await
                .remove(&resolved_peer_id);
            self_clone.logger.debug(format!("connection tasks exited for peer_node_id: {resolved_peer_id} - local node_id: {local_node_id}", local_node_id=compact_id(&self_clone.local_node_info.node_public_key)));
        })
    }

    async fn uni_accept_loop(&self, conn: Arc<quinn::Connection>) -> Result<(), NetworkError> {
        loop {
            let mut recv = conn
                .accept_uni()
                .await
                .map_err(|e| NetworkError::TransportError(e.to_string()))?;
            let msg = self.read_message(&mut recv).await?;
            let response = (self.message_handler)(msg).await?;
            if response.is_some() {
                // Handle response if needed
                self.logger
                    .warn("Received response from message handler when it shuold not have been");
            }
        }
    }

    async fn write_message<S: tokio::io::AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        msg: &NetworkMessage,
    ) -> Result<(), NetworkError> {
        use tokio::io::AsyncWriteExt;

        self.logger.debug(format!(
            "🔍 [write_message] Encoding message: type={}, source={}, dest={}",
            msg.message_type, msg.source_node_id, msg.destination_node_id
        ));

        let framed = encode_message(msg)?;
        self.logger.debug(format!(
            "🔍 [write_message] Encoded message size: {} bytes",
            framed.len()
        ));

        match stream.write_all(&framed).await {
            Ok(_) => {
                self.logger
                    .debug("✅ [write_message] Successfully wrote message to stream");
                Ok(())
            }
            Err(e) => {
                self.logger
                    .error(format!("❌ [write_message] Failed to write message: {e}"));
                Err(NetworkError::MessageError(format!(
                    "failed to write message: {e}"
                )))
            }
        }
    }

    // Read a length-prefixed `NetworkMessage` fully from a RecvStream.
    async fn read_message(
        &self,
        recv: &mut quinn::RecvStream,
    ) -> Result<NetworkMessage, NetworkError> {
        self.logger
            .debug("🔍 [read_message] Reading message from stream");

        let mut len_buf = [0u8; 4];

        match recv.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) => {
                return Err(NetworkError::MessageError(format!(
                    "failed to read length prefix: {e}"
                )));
            }
        }

        let len = u32::from_be_bytes(len_buf) as usize;

        if len > 1024 * 1024 {
            return Err(NetworkError::MessageError("message too large".into()));
        }

        let mut msg_buf = vec![0u8; len];

        self.logger.debug(format!(
            "🔍 [read_message] Reading message payload of length {len}"
        ));

        match recv.read_exact(&mut msg_buf).await {
            Ok(_) => {}
            Err(e) => {
                return Err(NetworkError::MessageError(format!(
                    "failed to read message payload: {e}"
                )));
            }
        }

        match serde_cbor::from_slice::<NetworkMessage>(&msg_buf) {
            Ok(msg) => {
                self.logger.debug(format!("🔍 [read_message] Decoded message: type={type}, source={source}, dest={dest}", 
                     type=msg.message_type, source=msg.source_node_id, dest=msg.destination_node_id));
                Ok(msg)
            }
            Err(e) => Err(NetworkError::MessageError(format!(
                "failed to decode cbor: {e}"
            ))),
        }
    }

    async fn bi_accept_loop(
        &self,
        conn: Arc<quinn::Connection>,
        needs_to_correlate_peer_id: bool,
    ) -> Result<(), NetworkError> {
        loop {
            let (mut send, mut recv) = conn
                .accept_bi()
                .await
                .map_err(|e| NetworkError::TransportError(e.to_string()))?;
            let msg = self.read_message(&mut recv).await?;

            self.logger.debug(format!("🔍 [bi_accept_loop] Received message: type={type}, source={source}, dest={dest}", 
                     type=msg.message_type, source=msg.source_node_id, dest=msg.destination_node_id));

            if msg.message_type == super::MESSAGE_TYPE_HANDSHAKE {
                self.logger
                    .debug("🔍 [bi_accept_loop] Processing handshake message");

                if let Some(payload) = msg.payloads.first() {
                    match serde_cbor::from_slice::<NodeInfo>(&payload.value_bytes) {
                        Ok(node_info) => {
                            let peer_node_id = msg.source_node_id.clone();
                            let node_info_version = node_info.version;

                            self.logger.debug(format!("🔍 [bi_accept_loop] Handshake NodeInfo peer_node_id: {peer_node_id} node info version: {node_info_version}"));
                            {
                                //check if we already know about this peer
                                let mut peers = self.state.peers.write().await;
                                if let Some(peer) = peers.get(&peer_node_id) {
                                    if peer.node_info_version >= node_info_version {
                                        self.logger.debug(format!("🔍 [bi_accept_loop] Known peer_node_id: {peer_node_id} with version: {node_info_version} did not increase - no update needed -  we will skip sending the handshake response"));
                                        //skip sending the handshake response - not a first time handshake
                                        continue;
                                    } else {
                                        peers.insert(
                                            peer_node_id.clone(),
                                            PeerState::new(conn.clone(), node_info_version),
                                        );
                                    }
                                } else {
                                    self.logger.debug(format!(
                                        "🔍 [bi_accept_loop] New peer peer_node_id: {peer_node_id}"
                                    ));
                                    peers.insert(
                                        peer_node_id.clone(),
                                        PeerState::new(conn.clone(), node_info_version),
                                    );
                                }
                            }
                            let _ = (self.message_handler)(msg.clone()).await;
                            if needs_to_correlate_peer_id {
                                self.state
                                    .connection_id_to_peer_id
                                    .write()
                                    .await
                                    .insert(conn.stable_id(), peer_node_id);
                            }
                        }
                        Err(e) => {
                            self.logger.error(format!(
                                "❌ [bi_accept_loop] Failed to parse NodeInfo: {e}"
                            ));
                        }
                    }
                }

                // Send handshake response
                self.logger
                    .debug("🔍 [bi_accept_loop] Sending handshake response");
                let response_msg = NetworkMessage {
                    source_node_id: compact_id(&self.local_node_info.node_public_key),
                    destination_node_id: msg.source_node_id,
                    message_type: super::MESSAGE_TYPE_HANDSHAKE,
                    payloads: vec![super::NetworkMessagePayloadItem {
                        path: "handshake".to_string(),
                        value_bytes: serde_cbor::to_vec(&self.local_node_info).unwrap_or_default(),
                        correlation_id: msg
                            .payloads
                            .first()
                            .map(|p| p.correlation_id.clone())
                            .unwrap_or_default(),
                        context: None,
                    }],
                };

                self.write_message(&mut send, &response_msg).await?;
                send.finish()
                    .map_err(|e| NetworkError::TransportError(e.to_string()))?;
                self.logger
                    .debug("✅ [bi_accept_loop] Handshake response sent");
                continue;
            }

            // Extract fields needed for error handling before moving msg
            let source_node_id = msg.source_node_id.clone();
            let payloads = msg.payloads.clone();

            match (self.message_handler)(msg).await {
                Ok(Some(reply)) => {
                    self.write_message(&mut send, &reply).await?;
                    send.finish()
                        .map_err(|e| NetworkError::TransportError(e.to_string()))?;
                }
                Ok(None) => {
                    self.logger
                        .warn("Expected response from message handler but got None");
                }
                Err(e) => {
                    self.logger.error(format!("Handler error: {e}"));
                    // Send error response back to caller - one error per payload
                    let error_payloads: Vec<super::NetworkMessagePayloadItem> = payloads
                        .iter()
                        .map(|payload| super::NetworkMessagePayloadItem {
                            path: payload.path.clone(),
                            value_bytes: serde_cbor::to_vec(&format!("Error: {e}"))
                                .unwrap_or_default(),
                            correlation_id: payload.correlation_id.clone(),
                            context: payload.context.clone(),
                        })
                        .collect();

                    let error_msg = NetworkMessage {
                        source_node_id: compact_id(&self.local_node_info.node_public_key),
                        destination_node_id: source_node_id,
                        message_type: super::MESSAGE_TYPE_RESPONSE,
                        payloads: error_payloads,
                    };
                    self.write_message(&mut send, &error_msg).await?;
                    send.finish()
                        .map_err(|e| NetworkError::TransportError(e.to_string()))?;
                }
            }
        }
    }

    async fn handshake_outbound(
        &self,
        peer_id: &str,
        conn: &quinn::Connection,
    ) -> Result<(), NetworkError> {
        self.logger.debug(format!(
            "🔍 [handshake_outbound] Starting handshake with peer: {peer_id}"
        ));

        self.logger
            .debug("🔍 [handshake_outbound] Serializing local NodeInfo");
        let payload_bytes = serde_cbor::to_vec(&self.local_node_info).map_err(|e| {
            self.logger.error(format!(
                "❌ [handshake_outbound] Failed to serialize NodeInfo: {e}"
            ));
            NetworkError::MessageError(e.to_string())
        })?;

        let payloads = vec![super::NetworkMessagePayloadItem {
            path: "handshake".to_string(),
            value_bytes: payload_bytes,
            correlation_id: uuid::Uuid::new_v4().to_string(),
            context: None,
        }];

        let msg = NetworkMessage {
            source_node_id: compact_id(&self.local_node_info.node_public_key),
            destination_node_id: peer_id.to_string(),
            message_type: super::MESSAGE_TYPE_HANDSHAKE,
            payloads,
        };

        self.logger
            .debug("🔍 [handshake_outbound] Sending handshake message via request_inner");

        // Send handshake and wait for response
        let reply = self.request_inner(conn, &msg).await?;

        self.logger
            .debug("🔍 [handshake_outbound] Received handshake response, processing...");

        //send to node to handle handshake response and store peer node info
        let _ = (self.message_handler)(reply).await;

        Ok(())
    }

    async fn request_inner(
        &self,
        conn: &quinn::Connection,
        msg: &NetworkMessage,
    ) -> Result<NetworkMessage, NetworkError> {
        self.logger
            .debug("🔍 [request_inner] Opening bidirectional stream");

        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| {
            self.logger.error(format!(
                "❌ [request_inner] Failed to open bidirectional stream: {e}"
            ));
            NetworkError::TransportError(e.to_string())
        })?;

        self.logger
            .debug("🔍 [request_inner] Bidirectional stream opened successfully");

        self.logger
            .debug("🔍 [request_inner] Writing message to stream");
        self.write_message(&mut send, msg).await?;

        self.logger
            .debug("🔍 [request_inner] Finishing send stream");
        send.finish().map_err(|e| {
            self.logger.error(format!(
                "❌ [request_inner] Failed to finish send stream: {e}"
            ));
            NetworkError::TransportError(e.to_string())
        })?;

        self.logger
            .debug("🔍 [request_inner] Reading response message");
        // Read the response message first
        let response_msg = self.read_message(&mut recv).await?;

        self.logger.debug(
            "🔍 [request_inner] Response message read successfully, draining remaining data",
        );

        // Then spawn a task to drain any remaining data from the stream
        let drain_task =
            tokio::spawn(async move { while recv.read(&mut [0u8; 0]).await.is_ok() {} });

        // Abort the drain task since we've already read what we need
        drain_task.abort();
        let _ = drain_task.await;

        self.logger
            .debug("✅ [request_inner] Request completed successfully");
        Ok(response_msg)
    }

    fn shared_state() -> SharedState {
        SharedState {
            peers: Arc::new(RwLock::new(HashMap::new())),
            connection_id_to_peer_id: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl NetworkTransport for QuicTransport {
    async fn start(self: Arc<Self>) -> Result<(), NetworkError> {
        self.logger.info(format!(
            "Starting QUIC transport node id: {node_id}",
            node_id = compact_id(&self.local_node_info.node_public_key)
        ));

        let mut running_guard = self.running.write().await;
        if *running_guard {
            return Ok(());
        }

        // Create Quinn server & client configs
        let (server_cfg, client_cfg) = self.build_quinn_configs()?;

        let mut endpoint = Endpoint::server(server_cfg, self.bind_addr)
            .map_err(|e| NetworkError::TransportError(format!("failed to create endpoint: {e}")))?;
        endpoint.set_default_client_config(client_cfg);

        // store endpoint
        {
            let mut guard = self.endpoint.write().await;
            *guard = Some(endpoint.clone());
        }

        // spawn accept loops
        let accept_task: tokio::task::JoinHandle<()> = self.clone().spawn_accept_loop(endpoint);
        self.tasks.lock().await.push(accept_task);

        *running_guard = true;
        Ok(())
    }

    async fn stop(&self) -> Result<(), NetworkError> {
        self.logger.info(format!(
            "Stopping QUIC transport node id: {node_id}",
            node_id = compact_id(&self.local_node_info.node_public_key)
        ));

        {
            let mut run = self.running.write().await;
            if !*run {
                self.logger
                    .debug("QUIC transport is not running - skipping stop");
                return Ok(());
            }
            *run = false;
        }

        self.logger.debug("Closing endpoint");
        if let Some(ep) = self.endpoint.write().await.take() {
            ep.close(0u32.into(), b"shutdown");
        }

        self.logger.debug("Closing all connections");
        let peers = self.state.peers.read().await;
        for peer in peers.values() {
            peer.connection.close(0u32.into(), b"shutdown");
        }

        self.logger.debug("canceling all remaining tasks");
        let mut tasks = self.tasks.lock().await;
        while let Some(t) = tasks.pop() {
            t.abort();
            let _ = t.await;
        }
        Ok(())
    }

    async fn disconnect(&self, node_id: String) -> Result<(), NetworkError> {
        // Remove peer from the peers map
        let mut peers = self.state.peers.write().await;
        if let Some(peer_state) = peers.remove(&node_id) {
            // Close the connection gracefully
            peer_state.connection.close(0u32.into(), b"disconnect");
            self.logger
                .info(format!("Disconnected from peer: {node_id}"));
        } else {
            self.logger.warn(format!(
                "Attempted to disconnect from unknown peer: {node_id}"
            ));
        }
        Ok(())
    }

    async fn is_connected(&self, peer_node_id: String) -> bool {
        let peers = self.state.peers.read().await;
        peers.contains_key(&peer_node_id)
    }

    async fn request(
        &self,
        topic_path: &TopicPath,
        params: Option<ArcValue>,
        peer_node_id: &str,
        context: MessageContext,
    ) -> Result<ArcValue, NetworkError> {
        self.logger.info(format!(
            "🔍 [request] Starting request to peer: {peer_node_id}"
        ));

        let peers = self.state.peers.read().await;
        let peer = peers.get(peer_node_id).ok_or_else(|| {
            self.logger
                .error(format!("❌ [request] Not connected to peer {peer_node_id}"));
            NetworkError::ConnectionError(format!("not connected to peer {peer_node_id}"))
        })?;

        self.logger
            .info("🔍 [request] Opening bidirectional stream");
        let (mut send, mut recv) = peer.connection.open_bi().await.map_err(|e| {
            self.logger.error(format!(
                "❌ [request] Failed to open bidirectional stream: {e}"
            ));
            NetworkError::TransportError(format!("open_bi failed: {e}"))
        })?;

        self.logger
            .info("🔍 [request] Bidirectional stream opened successfully");

        let network_id = topic_path.network_id();

        let correlation_id = uuid::Uuid::new_v4().to_string();

        let profile_public_key = context.profile_public_key.clone();

        let serialization_context = SerializationContext {
            keystore: self.keystore.clone(),
            resolver: self.label_resolver.clone(),
            network_id,
            profile_public_key,
        };

        // build message
        let msg = NetworkMessage {
            source_node_id: compact_id(&self.local_node_info.node_public_key),
            destination_node_id: peer_node_id.to_string(),
            message_type: super::MESSAGE_TYPE_REQUEST,
            payloads: vec![super::NetworkMessagePayloadItem {
                path: topic_path.as_str().to_string(),
                value_bytes: if let Some(v) = params {
                    v.serialize(Some(&serialization_context))
                        .map_err(|e| NetworkError::MessageError(e.to_string()))?
                } else {
                    ArcValue::null()
                        .serialize(Some(&serialization_context))
                        .map_err(|e| NetworkError::MessageError(e.to_string()))?
                },
                correlation_id,
                context: Some(context),
            }],
        };

        self.logger
            .info("🔍 [request] Writing request message to stream");
        self.write_message(&mut send, &msg).await?;

        self.logger.info("🔍 [request] Finishing send stream");
        send.finish().map_err(|e| {
            self.logger
                .error(format!("❌ [request] Failed to finish send stream: {e}"));
            NetworkError::TransportError(format!("finish send failed: {e}"))
        })?;

        self.logger.info("🔍 [request] Reading response message");
        let response_msg = self.read_message(&mut recv).await?;
        self.logger.info(format!(
            "🔍 [request] Received response message: type={}, payloads={}",
            response_msg.message_type,
            response_msg.payloads.len()
        ));

        // assume first payload contains ArcValue bytes
        let bytes = &response_msg.payloads[0].value_bytes;
        self.logger.info(format!(
            "🔍 [request] Deserializing response payload of {} bytes",
            bytes.len()
        ));
        let av = ArcValue::deserialize(bytes, Some(serialization_context.keystore.clone()))
            .map_err(|e| {
                self.logger
                    .error(format!("❌ [request] Failed to deserialize response: {e}"));
                NetworkError::MessageError(format!("deserialize response: {e}"))
            })?;

        self.logger
            .info("✅ [request] Request completed successfully");
        Ok(av)
    }

    async fn publish(&self, message: NetworkMessage) -> Result<(), NetworkError> {
        let peer_id = &message.destination_node_id;
        let peers = self.state.peers.read().await;
        let peer = peers.get(peer_id).ok_or_else(|| {
            NetworkError::ConnectionError(format!("not connected to peer {peer_id}"))
        })?;

        let mut send = peer
            .connection
            .open_uni()
            .await
            .map_err(|e| NetworkError::TransportError(format!("open_uni failed: {e}")))?;
        self.write_message(&mut send, &message).await?;
        send.finish()
            .map_err(|e| NetworkError::TransportError(format!("finish uni failed: {e}")))?;
        Ok(())
    }

    async fn connect_peer(self: Arc<Self>, discovery_msg: PeerInfo) -> Result<(), NetworkError> {
        //check if transport is running
        {
            let running = self.running.read().await;
            if !*running {
                self.logger.error("❌ [connect_peer] Transport not running");
                return Err(NetworkError::TransportError("transport not running".into()));
            }
        }

        let peer_node_id = compact_id(&discovery_msg.public_key);
        self.logger.debug(format!(
            "🔍 [connect_peer] Starting connection to peer: {peer_node_id}"
        ));
        // check we already know about this peer
        {
            let peers = self.state.peers.read().await;
            if peers.contains_key(&peer_node_id) {
                self.logger.debug(format!(
                    "🔍 [connect_peer] Peer already connected: {peer_node_id}"
                ));
                return Ok(());
            }
        }

        let endpoint = {
            let guard = self.endpoint.read().await;
            guard.as_ref().cloned().ok_or_else(|| {
                self.logger.error("❌ [connect_peer] Endpoint not started");
                NetworkError::TransportError("endpoint not started".into())
            })?
        };

        if discovery_msg.addresses.is_empty() {
            self.logger
                .error("❌ [connect_peer] No addresses in PeerInfo");
            return Err(NetworkError::ConfigurationError(
                "no addresses in PeerInfo".into(),
            ));
        }

        let addr = discovery_msg.addresses[0] // take first
            .parse::<std::net::SocketAddr>()
            .map_err(|e| {
                self.logger
                    .error(format!("❌ [connect_peer] Bad address: {e}"));
                NetworkError::ConfigurationError(format!("bad addr: {e}"))
            })?;

        let dns_safe_peer_id = dns_safe_node_id(&peer_node_id);
        self.logger.debug(format!("🔍 [connect_peer] Connecting to {peer_node_id} (DNS-safe: {dns_safe_peer_id}) at {addr}"));

        let connecting = endpoint.connect(addr, &dns_safe_peer_id).map_err(|e| {
            self.logger
                .error(format!("❌ [connect_peer] Connect failed: {e}"));
            NetworkError::ConnectionError(format!("connect: {e}"))
        })?;

        self.logger
            .debug("🔍 [connect_peer] Connection initiated, waiting for handshake...");

        let conn = connecting.await.map_err(|e| {
            self.logger
                .error(format!("❌ [connect_peer] Handshake failed: {e}"));
            NetworkError::ConnectionError(format!("handshake failed: {e}"))
        })?;

        self.logger
            .debug("[connect_peer] QUIC connection established successfully");

        // wrap connection in Arc for sharing
        let conn_arc = Arc::new(conn);

        // store peer
        {
            let mut peers = self.state.peers.write().await;
            peers.insert(peer_node_id.clone(), PeerState::new(conn_arc.clone(), 0));
            self.logger
                .debug("🔍 [connect_peer] Peer stored in peer map");
        }

        // spawn stream accept loops for that connection
        let task = self
            .clone()
            .spawn_connection_tasks(peer_node_id.clone(), conn_arc.clone());
        self.tasks.lock().await.push(task);
        self.logger
            .debug("🔍 [connect_peer] Connection tasks spawned");

        // do handshake on a fresh bi stream
        self.logger
            .debug("🔍 [connect_peer] Starting application-level handshake...");
        if let Err(e) = self.handshake_outbound(&peer_node_id, &conn_arc).await {
            self.logger.error(format!(
                "❌ [connect_peer] Application handshake failed: {e}"
            ));
            self.logger.error(format!("handshake failed: {e}"));
            // cleanup
            self.state.peers.write().await.remove(&peer_node_id);
            return Err(e);
        }

        self.logger
            .debug("[connect_peer] Application handshake completed successfully");
        Ok(())
    }

    fn get_local_address(&self) -> String {
        self.bind_addr.to_string()
    }

    async fn update_peers(&self, node_info: NodeInfo) -> Result<(), NetworkError> {
        // Get all connected peers
        let peers = self.state.peers.read().await;

        if peers.is_empty() {
            self.logger
                .debug("No peers connected, skipping peer update");
            return Ok(());
        }

        // Create handshake message with updated node info
        let payload_bytes = serde_cbor::to_vec(&node_info).map_err(|e| {
            NetworkError::MessageError(format!("Failed to serialize node info: {e}"))
        })?;

        let message = NetworkMessage {
            source_node_id: compact_id(&self.local_node_info.node_public_key),
            destination_node_id: String::new(), // Will be set per peer
            message_type: super::MESSAGE_TYPE_HANDSHAKE,
            payloads: vec![super::NetworkMessagePayloadItem {
                path: "handshake".to_string(),
                value_bytes: payload_bytes,
                correlation_id: uuid::Uuid::new_v4().to_string(),
                context: None,
            }],
        };

        // Send to each connected peer
        for (peer_id, peer_state) in peers.iter() {
            let mut send = peer_state.connection.open_uni().await.map_err(|e| {
                NetworkError::TransportError(format!("Failed to open uni stream to {peer_id}: {e}"))
            })?;

            self.write_message(&mut send, &message).await?;
            send.finish().map_err(|e| {
                NetworkError::TransportError(format!("Failed to finish send to {peer_id}: {e}"))
            })?;

            self.logger
                .debug(format!("Updated peer {peer_id} with new node info"));
        }

        self.logger
            .info(format!("Updated {} peers with new node info", peers.len()));
        Ok(())
    }

    fn keystore(&self) -> Arc<dyn runar_serializer::traits::EnvelopeCrypto> {
        self.keystore.clone()
    }

    fn label_resolver(&self) -> Arc<dyn runar_serializer::traits::LabelResolver> {
        self.label_resolver.clone()
    }
}
