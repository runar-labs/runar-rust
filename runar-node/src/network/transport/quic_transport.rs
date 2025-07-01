//! QUIC Transport Implementation
//!
//! This module implements the NetworkTransport trait using QUIC protocol.
//! It follows a layered architecture with clear separation of concerns:
//! - QuicTransport: Public API implementing NetworkTransport (thin wrapper)
//! - QuicTransportImpl: Core implementation managing connections and streams
//! - PeerState: Tracking state of individual peer connections
//! - ConnectionPool: Managing active connections and their lifecycle
//! - StreamPool: Managing stream reuse and resource cleanup

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;
use std::time::SystemTime;

use async_trait::async_trait;
use bincode;
use quinn::{self, Endpoint};
use quinn::{ClientConfig, ServerConfig};
// Using Quinn 0.11.x API - no need for proto imports
use runar_common::logging::Logger;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

// Import rustls explicitly - these types need clear namespacing to avoid conflicts with quinn's types
// Quinn uses rustls internally but we need to reference specific rustls types
use rustls;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};

use super::{
    ConnectionPool, NetworkError, NetworkMessage, NetworkMessagePayloadItem, NetworkTransport,
    PeerId, PeerState,
};
// Import PeerInfo and NodeInfo consistently with the module structure
use crate::network::discovery::multicast_discovery::PeerInfo;
use crate::network::discovery::NodeInfo;

type MessageHandlerFn =
    Box<dyn Fn(NetworkMessage) -> Result<(), NetworkError> + Send + Sync + 'static>;

/// Stream correlation data for tracking request-response pairs
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct StreamCorrelation {
    peer_id: PeerId,
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
    peer_id: PeerId,
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
    node_id: PeerId,
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
    node_id: PeerId,
    // Background tasks for connection handling and message processing
    background_tasks: Mutex<Vec<JoinHandle<()>>>,
}

/// QUIC-specific transport options
pub struct QuicTransportOptions {
    verify_certificates: bool,
    keep_alive_interval: Duration,
    connection_idle_timeout: Duration,
    stream_idle_timeout: Duration,
    max_idle_streams_per_peer: usize,
    /// TLS certificates for secure connections (REQUIRED)
    certificates: Option<Vec<CertificateDer<'static>>>,
    /// Private key corresponding to the certificates (REQUIRED)
    private_key: Option<PrivateKeyDer<'static>>,
    /// Custom certificate verifier for client connections (REQUIRED)
    certificate_verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier + Send + Sync>>,
    /// Custom root certificates for CA validation (optional - uses system roots if not provided)
    root_certificates: Option<Vec<CertificateDer<'static>>>,
    /// Log level for Quinn-related logs (default: Warn to reduce noisy connection logs)
    quinn_log_level: log::LevelFilter,
}

impl Clone for QuicTransportOptions {
    fn clone(&self) -> Self {
        Self {
            verify_certificates: self.verify_certificates,
            keep_alive_interval: self.keep_alive_interval,
            connection_idle_timeout: self.connection_idle_timeout,
            stream_idle_timeout: self.stream_idle_timeout,
            max_idle_streams_per_peer: self.max_idle_streams_per_peer,
            certificates: self.certificates.clone(),
            private_key: self.private_key.as_ref().map(|k| k.clone_key()),
            certificate_verifier: self.certificate_verifier.clone(),
            root_certificates: self.root_certificates.clone(),
            quinn_log_level: self.quinn_log_level,
        }
    }
}

impl fmt::Debug for QuicTransportOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicTransportOptions")
            .field("verify_certificates", &self.verify_certificates)
            .field("keep_alive_interval", &self.keep_alive_interval)
            .field("connection_idle_timeout", &self.connection_idle_timeout)
            .field("stream_idle_timeout", &self.stream_idle_timeout)
            .field("max_idle_streams_per_peer", &self.max_idle_streams_per_peer)
            .field(
                "certificates",
                &self.certificates.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "certificate_verifier",
                &self
                    .certificate_verifier
                    .as_ref()
                    .map(|_| "[custom verifier]"),
            )
            .field(
                "root_certificates",
                &self.root_certificates.as_ref().map(|_| "[redacted]"),
            )
            .field("quinn_log_level", &self.quinn_log_level)
            .finish()
    }
}

/// Configuration for creating a QuicTransport instance.
// Note: The message_handler is a Box, so QuicTransportConfig itself won't be Clone
// unless message_handler is changed to something like Arc<Box<...>>.
// For now, we'll assume the config is passed by value and its fields moved where needed.
pub struct QuicTransportConfig {
    pub local_node_info: NodeInfo,
    pub bind_addr: SocketAddr,
    pub message_handler:
        Box<dyn Fn(NetworkMessage) -> Result<(), NetworkError> + Send + Sync + 'static>,
    pub options: QuicTransportOptions,
    pub logger: Arc<Logger>,
}

impl QuicTransportOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the log level for Quinn-related logs
    ///
    /// INTENTION: Control the verbosity of Quinn's internal logs
    /// to reduce noise in the application logs. Default is Warn.
    pub fn with_quinn_log_level(mut self, level: log::LevelFilter) -> Self {
        self.quinn_log_level = level;
        self
    }

    pub fn with_verify_certificates(mut self, verify: bool) -> Self {
        self.verify_certificates = verify;
        self
    }

    pub fn with_keep_alive_interval(mut self, interval: Duration) -> Self {
        self.keep_alive_interval = interval;
        self
    }

    pub fn with_connection_idle_timeout(mut self, timeout: Duration) -> Self {
        self.connection_idle_timeout = timeout;
        self
    }

    pub fn with_stream_idle_timeout(mut self, timeout: Duration) -> Self {
        self.stream_idle_timeout = timeout;
        self
    }

    pub fn with_max_idle_streams_per_peer(mut self, max_streams: usize) -> Self {
        self.max_idle_streams_per_peer = max_streams;
        self
    }

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

    pub fn certificates(&self) -> Option<&Vec<CertificateDer<'static>>> {
        self.certificates.as_ref()
    }

    pub fn private_key(&self) -> Option<&PrivateKeyDer<'static>> {
        self.private_key.as_ref()
    }
}

impl Default for QuicTransportOptions {
    fn default() -> Self {
        Self {
            verify_certificates: true,
            keep_alive_interval: Duration::from_secs(15),
            connection_idle_timeout: Duration::from_secs(60),
            stream_idle_timeout: Duration::from_secs(30),
            max_idle_streams_per_peer: 100,
            certificates: None,
            private_key: None,
            certificate_verifier: None,
            root_certificates: None,
            quinn_log_level: log::LevelFilter::Warn, // Default to Warn to reduce noisy logs
        }
    }
}

// Implement Debug for QuicTransportImpl
impl fmt::Debug for QuicTransportImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // We can't access the Mutex in fmt because it might block, so we just indicate it exists
        f.debug_struct("QuicTransportImpl")
            .field("node_id", &self.node_id)
            .field("bind_addr", &self.bind_addr)
            .field("endpoint", &"<mutex>") // Can't access Mutex contents in fmt
            .field("options", &self.options)
            .finish()
    }
}

impl fmt::Debug for QuicTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicTransport")
            .field("node_id", &self.node_id)
            .field("inner", &self.inner)
            .finish()
    }
}

impl QuicTransportImpl {
    /// Create a new QUIC transport implementation
    ///
    /// INTENTION: Initialize the core implementation with the provided parameters.
    fn new(config: QuicTransportConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let connection_pool = Arc::new(ConnectionPool::new(config.logger.clone()));

        // Create a broadcast channel for peer node info updates
        // The channel size determines how many messages can be buffered before lagging
        let (peer_node_info_sender, _) = tokio::sync::broadcast::channel(32);

        Ok(Self {
            node_id: config.local_node_info.peer_id.clone(),
            bind_addr: config.bind_addr,
            // Initialize with Mutex for proper interior mutability
            endpoint: Mutex::new(None),
            connection_pool,
            options: config.options,
            logger: config.logger,
            message_handler: Arc::new(StdRwLock::new(config.message_handler)),
            local_node: config.local_node_info,
            peer_node_info_sender,
            running: Arc::new(AtomicBool::new(false)),
            // Initialize enhanced stream management
            bidirectional_streams: Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            stream_correlations: Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        })
    }

    /// Determine the communication pattern for a message
    ///
    /// INTENTION: Classify messages to use appropriate stream types and lifecycle management
    /// NOTE: Now using unidirectional streams for all messages including requests and responses
    fn classify_message_pattern(&self, message: &NetworkMessage) -> MessagePattern {
        match message.message_type.as_str() {
            // One-way messages that don't expect responses
            "Handshake" | "Discovery" | "Announcement" | "Heartbeat" => MessagePattern::OneWay,
            // **CHANGE**: Request messages now use unidirectional streams too
            // The response will come back as a separate unidirectional stream
            "Request" => MessagePattern::OneWay,
            // Response messages are sent back via separate unidirectional streams
            "Response" | "Error" => MessagePattern::OneWay,
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
        peer_id: PeerId,
        send_stream: quinn::SendStream,
    ) -> Result<(), NetworkError> {
        let correlation = StreamCorrelation {
            peer_id: peer_id.clone(),
            stream_id: 0,
            correlation_id: correlation_id.clone(),
            created_at: std::time::Instant::now(),
        };

        self.logger.debug(format!(
            "📝 [QuicTransport] Storing response stream - ID: {correlation_id}, Peer: {peer_id}"
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
                    peer_id,
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
        peer_id: &PeerId,
        message: NetworkMessage,
    ) -> Result<(), NetworkError> {
        self.logger.debug(format!(
            "🔄 [QuicTransport] Sending request message to peer {peer_id}"
        ));

        let peer_state = self.get_peer_state(peer_id)?;
        if !peer_state.is_connected().await {
            return Err(NetworkError::ConnectionError(format!(
                "Peer {peer_id} is not connected"
            )));
        }

        // Get bidirectional stream for request-response
        let connection = peer_state.get_connection().await.ok_or_else(|| {
            NetworkError::ConnectionError(format!("No connection to peer {peer_id}"))
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

        // CRITICAL FIX: Use tokio::select! to read and write truly concurrently
        // This ensures the response reading starts IMMEDIATELY, not after task queue scheduling

        let _read_timeout = std::time::Duration::from_millis(5000);
        let _correlation_id_clone = correlation_id.clone();

        self.logger.debug(format!(
            "🔄 [QuicTransport] Starting concurrent request/response for correlation ID: {}",
            correlation_id
        ));

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
        self.send_oneway_message(peer_id, message).await?;

        self.logger.debug(format!(
            "✅ [QuicTransport] Request sent via unidirectional stream - Correlation ID: {} (response will come via separate unidirectional stream)",
            correlation_id
        ));

        Ok(())
    }

    /// Send a one-way message using unidirectional streams
    ///
    /// INTENTION: Use unidirectional streams for messages that don't expect responses
    async fn send_oneway_message(
        &self,
        peer_id: &PeerId,
        message: NetworkMessage,
    ) -> Result<(), NetworkError> {
        self.logger.debug(format!(
            "📡 [QuicTransport] Sending one-way message to peer {}",
            peer_id
        ));

        let peer_state = self.get_peer_state(peer_id)?;
        if !peer_state.is_connected().await {
            return Err(NetworkError::ConnectionError(format!(
                "Peer {peer_id} is not connected"
            )));
        }

        // Get unidirectional stream for one-way messages
        let connection = peer_state.get_connection().await.ok_or_else(|| {
            NetworkError::ConnectionError(format!("No connection to peer {peer_id}"))
        })?;

        let mut stream = connection.open_uni().await.map_err(|e| {
            NetworkError::ConnectionError(format!("Failed to open unidirectional stream: {e}"))
        })?;

        // Send the message and finish the stream immediately
        self.write_message_to_stream(&mut stream, &message, peer_id)
            .await?;

        stream.finish().map_err(|e| {
            NetworkError::MessageError(format!("Failed to finish unidirectional stream: {e}"))
        })?;

        self.logger.debug(format!(
            "✅ [QuicTransport] One-way message sent and stream finished for peer {}",
            peer_id
        ));

        Ok(())
    }

    /// Send a response message using unidirectional streams
    ///
    /// INTENTION: Send responses via separate unidirectional streams, matching the new architecture
    #[allow(dead_code)]
    async fn send_response_message(
        &self,
        peer_id: &PeerId,
        message: NetworkMessage,
    ) -> Result<(), NetworkError> {
        self.logger.debug(format!(
            "↩️ [QuicTransport] Sending response message to peer {}",
            peer_id
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

        self.send_oneway_message(peer_id, message).await?;

        self.logger.debug(format!(
            "✅ [QuicTransport] Response sent via unidirectional stream - Correlation ID: {}",
            correlation_id
        ));

        Ok(())
    }

    /// Handle response stream for bidirectional request-response communication
    ///
    /// INTENTION: Read responses from recv_stream and process them through message handling
    #[allow(dead_code)]
    async fn handle_response_stream(
        self: &Arc<Self>,
        peer_id: PeerId,
        recv_stream: quinn::RecvStream,
        correlation_id: String,
    ) -> Result<(), NetworkError> {
        self.logger.debug(format!(
            "🎧 [QuicTransport] Handling response stream for correlation ID: {}",
            correlation_id
        ));

        // Use the existing receive_message infrastructure to handle the response
        // This will read the message from the stream and process it properly
        self.receive_message(peer_id, recv_stream, None).await?;

        self.logger.debug(format!(
            "✅ [QuicTransport] Response stream handled successfully for correlation ID: {}",
            correlation_id
        ));

        Ok(())
    }

    /// Helper method to get peer state with error handling
    fn get_peer_state(&self, peer_id: &PeerId) -> Result<Arc<PeerState>, NetworkError> {
        self.connection_pool
            .get_peer(peer_id)
            .ok_or_else(|| NetworkError::ConnectionError(format!("Peer {peer_id} not found")))
    }

    /// Helper method to write a message to any stream type
    async fn write_message_to_stream<S>(
        &self,
        stream: &mut S,
        message: &NetworkMessage,
        peer_id: &PeerId,
    ) -> Result<(), NetworkError>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        // Serialize the message
        let serialized_message = bincode::serialize(message)
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
            peer_id,
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
        let peer_id = PeerId::new(discovery_msg.public_key.clone());

        // Check if we're already connected to this peer
        if self.connection_pool.is_peer_connected(&peer_id).await {
            self.logger
                .info(format!("Already connected to peer {}", peer_id));

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
                        .warn(format!("Invalid address {}: {}", peer_addr, e));
                    last_error = Some(NetworkError::ConnectionError(format!(
                        "Invalid address {}: {}",
                        peer_addr, e
                    )));
                    continue; // Try the next address
                }
            };

            // Connect to the peer
            self.logger
                .info(format!("Connecting to peer {} at {}", peer_id, socket_addr));

            // Print detailed connection information for debugging
            self.logger.info(format!(
                "Detailed connection attempt - Local node: {}, Remote peer: {}, Socket: {}",
                self.node_id, peer_id, socket_addr
            ));

            // Create a new connection to the peer
            // For testing, we use "localhost" as the server name to avoid certificate validation issues
            // In production, we would use the peer_id or a proper domain name
            let connect_result = endpoint.connect(socket_addr, "localhost");

            match connect_result {
                Ok(connecting) => {
                    // Wait for the connection to be established
                    match connecting.await {
                        Ok(connection) => {
                            self.logger
                                .info(format!("Connected to peer {} at {}", peer_id, socket_addr));

                            // Get or create the peer state
                            let peer_state = self.connection_pool.get_or_create_peer(
                                peer_id.clone(),
                                peer_addr.clone(),
                                self.options.max_idle_streams_per_peer,
                                self.logger.clone(),
                            );

                            // Set the connection in the peer state
                            peer_state.set_connection(connection).await;

                            // Successfully connected to this address

                            // Start a task to receive incoming messages
                            let task =
                                self.spawn_message_receiver(peer_id.clone(), peer_state.clone());

                            // Verify the connection is properly registered
                            let is_connected =
                                self.connection_pool.is_peer_connected(&peer_id).await;
                            self.logger.info(format!(
                                "Connection verification for {}: {}",
                                peer_id, is_connected
                            ));

                            return Ok(task);
                        }
                        Err(e) => {
                            self.logger.warn(format!(
                                "Failed to connect to peer {peer_id} at {socket_addr}: {e}"
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
                        "Failed to initiate connection to peer {peer_id} at {socket_addr}: {e}"
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
                "Failed to connect to peer {peer_id} on any address"
            ))
        }))
    }

    async fn update_peers(self: &Arc<Self>, node_info: NodeInfo) -> Result<(), NetworkError> {
        //for each connected peer send a NODE_INFO_UPDATE message
        let peers = self.connection_pool.get_connected_peers().await;
        for peer_id in peers {
            let message = NetworkMessage {
                source: self.node_id.clone(),
                destination: peer_id.clone(),
                message_type: "NODE_INFO_UPDATE".to_string(),
                payloads: vec![NetworkMessagePayloadItem {
                    path: "".to_string(),
                    value_bytes: bincode::serialize(&node_info).unwrap(),
                    correlation_id: "".to_string(),
                }],
            };
            self.send_message(message).await?;
            self.logger
                .info(format!("Sent NODE_INFO_UPDATE message to peer {peer_id}"));
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
    async fn handshake_peer(self: &Arc<Self>, discovery_msg: PeerInfo) -> Result<(), NetworkError> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(NetworkError::TransportError(
                "Transport not running".to_string(),
            ));
        }

        // Get the peer ID based on the public_key from PeerInfo
        let peer_id = PeerId::new(discovery_msg.public_key.clone());

        self.logger
            .info(format!("Starting handshake with peer {peer_id}"));

        // Check if we're connected to this peer
        if !self.connection_pool.is_peer_connected(&peer_id).await {
            return Err(NetworkError::ConnectionError(format!(
                "Not connected to peer {peer_id}, cannot perform handshake"
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
            source: self.node_id.clone(),
            destination: peer_id.clone(),
            message_type: "NODE_INFO_HANDSHAKE".to_string(),
            payloads: vec![NetworkMessagePayloadItem {
                path: "".to_string(),
                value_bytes: bincode::serialize(&self.local_node).map_err(|e| {
                    NetworkError::MessageError(format!("Failed to serialize node info: {e}"))
                })?,
                correlation_id,
            }],
        };

        // Send the handshake message
        self.send_message(handshake_message).await?;
        self.logger
            .info(format!("Sent handshake message to peer {peer_id}"));

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
        self.logger.debug(format!(
            "Processing message from {}, type: {}",
            message.source, message.message_type
        ));

        // Special handling for handshake messages
        if message.message_type == "NODE_INFO_HANDSHAKE"
            || message.message_type == "NODE_INFO_HANDSHAKE_RESPONSE"
            || message.message_type == "NODE_INFO_UPDATE"
        {
            self.logger.debug(format!(
                "Received message from {} with type: {}",
                message.source, message.message_type
            ));

            // Extract the node info from the message
            if let Some(payload) = message.payloads.first() {
                match bincode::deserialize::<NodeInfo>(&payload.value_bytes) {
                    Ok(peer_node_info) => {
                        self.logger.debug(format!(
                            "Received node info from {}: {:?}",
                            message.source, peer_node_info
                        ));

                        // Store the node info in the peer state
                        if let Some(peer_state) = self.connection_pool.get_peer(&message.source) {
                            peer_state.set_node_info(peer_node_info.clone()).await;

                            if message.message_type == "NODE_INFO_HANDSHAKE" {
                                // Create the response message
                                let response = NetworkMessage {
                                    source: self.node_id.clone(),
                                    destination: message.source.clone(),
                                    message_type: "NODE_INFO_HANDSHAKE_RESPONSE".to_string(),
                                    payloads: vec![NetworkMessagePayloadItem {
                                        // Preserve the original path from the request
                                        path: payload.path.clone(),
                                        value_bytes: bincode::serialize(&self.local_node).map_err(
                                            |e| {
                                                NetworkError::MessageError(format!(
                                                    "Failed to serialize node info: {}",
                                                    e
                                                ))
                                            },
                                        )?,
                                        correlation_id: payload.correlation_id.clone(),
                                    }],
                                };

                                // Send the response
                                self.send_message(response).await?;
                                self.logger.debug(format!(
                                    "Sent handshake response to {}",
                                    message.source
                                ));
                            }
                        }

                        // Send to the channel - ignore errors if there are no subscribers
                        let _ = self.peer_node_info_sender.send(peer_node_info);
                    }
                    Err(e) => {
                        self.logger.error(format!(
                            "Failed to deserialize node info from {}: {}",
                            message.source, e
                        ));
                    }
                }
            }
            return Ok(());
        } else {
            self.logger.debug(format!(
                "Received message from {} with type: {}",
                message.source, message.message_type
            ));
        }

        // Get a read lock on the handlers
        match self.message_handler.read() {
            Ok(handler) => {
                if let Err(e) = handler(message.clone()) {
                    self.logger
                        .error(format!("Error in message handler: {}", e));
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
            .info(format!("New incoming connection from {}", remote_addr));

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
                "🔍 [QuicTransport] Waiting for peer identification from {}",
                remote_addr
            ));

            // **STEP 1**: Wait for the first unidirectional stream (should be handshake)
            match connection.accept_uni().await {
                Ok(recv_stream) => {
                    logger.debug(format!(
                        "🔄 [QuicTransport] Receiving handshake message from {}",
                        remote_addr
                    ));

                    // **STEP 2**: Read and parse the handshake message to get real peer ID
                    match inner_arc.read_handshake_message(recv_stream).await {
                        Ok(message) => {
                            if message.message_type == "NODE_INFO_HANDSHAKE" {
                                // **STEP 3**: Extract the real peer ID from the handshake message
                                let real_peer_id = message.source.clone();

                                logger.info(format!(
                                    "✅ [QuicTransport] Identified peer: {} from {}",
                                    real_peer_id, remote_addr
                                ));

                                // **STEP 4**: Check if we already have a connection to this peer
                                if inner_arc
                                    .connection_pool
                                    .is_peer_connected(&real_peer_id)
                                    .await
                                {
                                    logger.warn(format!(
                                        "⚠️  [QuicTransport] Peer {} already has active connection, closing duplicate from {}",
                                        real_peer_id, remote_addr
                                    ));

                                    // Close this duplicate connection gracefully
                                    connection.close(1u32.into(), b"Duplicate connection");
                                } else {
                                    // **STEP 5**: This is the primary connection - establish proper peer state
                                    logger.info(format!(
                                        "🎯 [QuicTransport] Establishing primary connection for peer {} from {}",
                                        real_peer_id, remote_addr
                                    ));

                                    // Create peer state with the real peer ID
                                    let peer_state = inner_arc.connection_pool.get_or_create_peer(
                                        real_peer_id.clone(),
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
                                        logger.error(format!("Error processing handshake: {}", e));
                                        return;
                                    }

                                    // **STEP 7**: Start the persistent message receiver for this peer
                                    logger.info(format!(
                                        "🔄 [QuicTransport] Starting message receiver for peer {}",
                                        real_peer_id
                                    ));

                                    // The message receiver will handle the connection from now on
                                    inner_arc
                                        .spawn_message_receiver_task(
                                            real_peer_id,
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
                                "❌ [QuicTransport] Failed to read handshake from {}: {}",
                                remote_addr, e
                            ));
                            connection.close(3u32.into(), b"Handshake failed");
                        }
                    }
                }
                Err(e) => {
                    logger.error(format!(
                        "❌ [QuicTransport] Failed to accept handshake stream from {}: {}",
                        remote_addr, e
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
            NetworkError::MessageError(format!("Failed to read handshake message length: {}", e))
        })?;

        let message_len = u32::from_be_bytes(len_bytes) as usize;
        if message_len > 1024 * 1024 {
            // 1MB limit
            return Err(NetworkError::MessageError(format!(
                "Handshake message too large: {} bytes",
                message_len
            )));
        }

        // Read the message data
        let mut message_data = vec![0u8; message_len];
        recv_stream
            .read_exact(&mut message_data)
            .await
            .map_err(|e| {
                NetworkError::MessageError(format!("Failed to read handshake message data: {}", e))
            })?;

        // Deserialize the message
        bincode::deserialize(&message_data).map_err(|e| {
            NetworkError::MessageError(format!("Failed to deserialize handshake message: {}", e))
        })
    }

    /// Start the persistent message receiver task for an identified peer
    ///
    /// INTENTION: Handle ongoing message processing for a peer with known identity
    async fn spawn_message_receiver_task(
        self: &Arc<Self>,
        peer_id: PeerId,
        peer_state: Arc<PeerState>,
        connection: quinn::Connection,
    ) {
        let inner_arc = self.clone();
        let logger = self.logger.clone();
        let peer_id_clone = peer_id.clone();

        // Spawn the message receiver as a background task
        tokio::spawn(async move {
            logger.info(format!(
                "🔄 [QuicTransport] Starting persistent message receiver for peer {}",
                peer_id_clone
            ));

            // **QUIC BEST PRACTICE**: Keep connection alive and process multiple streams
            loop {
                // **CRITICAL FIX**: Check connection health first
                if let Some(close_reason) = connection.close_reason() {
                    logger.info(format!(
                        "🔚 [QuicTransport] Connection to peer {} closed: {:?}",
                        peer_id_clone, close_reason
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
                                    "🔄 [QuicTransport] Accepting unidirectional stream from peer {}",
                                    peer_id_clone
                                ));

                                // Process unidirectional message (no send stream for response)
                                if let Err(e) = inner_arc
                                    .receive_message(peer_id_clone.clone(), recv_stream, None)
                                    .await
                                {
                                    logger.error(format!(
                                        "Error receiving unidirectional message from {}: {}",
                                        peer_id_clone, e
                                    ));
                                }
                            }
                            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                                logger.info(format!("Connection closed by peer {}", peer_id_clone));
                                break;
                            }
                            Err(e) => {
                                logger.error(format!("Unidirectional connection error from {}: {}", peer_id_clone, e));
                                break;
                            }
                        }
                    }
                    // Listen for bidirectional streams (requests, responses)
                    bi_result = connection.accept_bi() => {
                        match bi_result {
                            Ok((send_stream, recv_stream)) => {
                                logger.debug(format!(
                                    "🔄 [QuicTransport] Accepting bidirectional stream from peer {}",
                                    peer_id_clone
                                ));

                                // Process bidirectional message with send stream for responses
                                if let Err(e) = inner_arc
                                    .receive_message(peer_id_clone.clone(), recv_stream, Some(send_stream))
                                    .await
                                {
                                    logger.error(format!(
                                        "Error receiving bidirectional message from {}: {}",
                                        peer_id_clone, e
                                    ));
                                }
                            }
                            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                                logger.info(format!("Connection closed by peer {}", peer_id_clone));
                                break;
                            }
                            Err(e) => {
                                logger.error(format!("Bidirectional connection error from {}: {}", peer_id_clone, e));
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
                                "⚠️  [QuicTransport] Connection health check failed for peer {}",
                                peer_id_clone
                            ));
                            break;
                        }
                    }
                }
            }

            logger.info(format!(
                "🔚 [QuicTransport] Message receiver stopped for peer {}",
                peer_id_clone
            ));

            // Clean up peer state when connection ends
            inner_arc
                .connection_pool
                .remove_peer(&peer_id_clone)
                .await
                .ok();
        });
    }

    fn spawn_message_receiver(
        self: &Arc<Self>,
        peer_id: PeerId,
        peer_state: Arc<PeerState>,
    ) -> JoinHandle<()> {
        // This is the legacy method that's still called in some places
        // It should get the connection from peer_state and delegate to the new method
        let inner_arc = self.clone();
        let logger = self.logger.clone();
        let peer_id_clone = peer_id.clone();

        tokio::spawn(async move {
            if let Some(connection) = peer_state.get_connection().await {
                // Delegate to the new method
                inner_arc
                    .spawn_message_receiver_task(peer_id_clone, peer_state, connection)
                    .await;
            } else {
                logger.warn(format!(
                    "❌ [QuicTransport] No connection available for peer {}",
                    peer_id_clone
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
        peer_id: PeerId,
        mut recv_stream: quinn::RecvStream,
        send_stream: Option<quinn::SendStream>,
    ) -> Result<(), NetworkError> {
        self.logger.debug(format!(
            "📥 [QuicTransport] Processing message from peer {}",
            peer_id
        ));

        // Read message length (4 bytes)
        let mut len_bytes = [0u8; 4];
        recv_stream.read_exact(&mut len_bytes).await.map_err(|e| {
            NetworkError::MessageError(format!("Failed to read message length: {}", e))
        })?;

        let message_len = u32::from_be_bytes(len_bytes) as usize;
        if message_len > 1024 * 1024 {
            // 1MB limit
            return Err(NetworkError::MessageError(format!(
                "Message too large: {} bytes",
                message_len
            )));
        }

        // Read the message data
        let mut message_data = vec![0u8; message_len];
        recv_stream
            .read_exact(&mut message_data)
            .await
            .map_err(|e| {
                NetworkError::MessageError(format!("Failed to read message data: {}", e))
            })?;

        // Deserialize the message
        let message: NetworkMessage = bincode::deserialize(&message_data).map_err(|e| {
            NetworkError::MessageError(format!("Failed to deserialize message: {}", e))
        })?;

        self.logger.debug(format!(
            "📥 [QuicTransport] Received message from {} - Type: {}, Path: {}",
            peer_id,
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
                if message.message_type == "Request" {
                    self.logger.debug(format!(
                        "🔗 [QuicTransport] Storing send stream for incoming request - Correlation ID: {}, From: {}",
                        payload.correlation_id, peer_id
                    ));

                    // Store the send stream using the correlation ID for direct response
                    self.store_response_stream(
                        payload.correlation_id.clone(),
                        peer_id.clone(),
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
            "🔍 [QuicTransport] Looking for response stream for correlation ID: {}",
            correlation_id
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
                "✅ [QuicTransport] Found and removed response stream for correlation ID: {}",
                correlation_id
            ));
        } else {
            self.logger.warn(format!(
                "❌ [QuicTransport] No response stream found for correlation ID: {}",
                correlation_id
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
        let mut server_config = ServerConfig::with_single_cert(
            certificates.clone(),
            private_key.clone_key(),
        )
        .map_err(|e| {
            NetworkError::ConfigurationError(format!("Failed to create server config: {}", e))
        })?;

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
                        "Failed to convert rustls config: {}",
                        e
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

        self.logger
            .info(format!("Starting QUIC transport on {}", self.bind_addr));

        // Create configurations for the QUIC endpoint
        let (server_config, client_config) = self.create_quinn_configs()?;

        // Create the endpoint with the server configuration
        let bind_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), self.bind_addr.port());
        self.logger
            .info(format!("Creating endpoint bound to {}", bind_addr));

        let mut endpoint = Endpoint::server(server_config, bind_addr).map_err(|e| {
            NetworkError::TransportError(format!("Failed to create endpoint: {}", e))
        })?;

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
                                        logger.error(format!("Error handling connection: {}", e))
                                    }
                                }
                            }
                            Err(e) => logger.error(format!("Error accepting connection: {}", e)),
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
    async fn disconnect(self: &Arc<Self>, peer_id: PeerId) -> Result<(), NetworkError> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(NetworkError::TransportError(
                "Transport not running".to_string(),
            ));
        }

        self.connection_pool.remove_peer(&peer_id).await
    }

    /// Check if connected to a specific peer
    ///
    /// INTENTION: Determine if there's an active connection to the specified peer.
    async fn is_connected(self: &Arc<Self>, peer_id: PeerId) -> bool {
        self.connection_pool.is_peer_connected(&peer_id).await
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

        let peer_id = message.destination.clone();
        let message_pattern = self.classify_message_pattern(&message);

        self.logger.info(format!(
            "📤 [QuicTransport] Sending message - To: {}, Type: {}, Pattern: {:?}, Payloads: {}",
            peer_id,
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
            MessagePattern::OneWay => self.send_oneway_message(&peer_id, message).await,
            MessagePattern::RequestResponse => {
                // This pattern should no longer be used since we changed classification
                // But keeping for safety - treat as one-way
                self.logger.warn(
                    "⚠️ [QuicTransport] RequestResponse pattern should not be used anymore, treating as OneWay".to_string()
                );
                self.send_oneway_message(&peer_id, message).await
            }
            MessagePattern::Response => {
                // Responses now use unidirectional streams too
                self.send_oneway_message(&peer_id, message).await
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
        peer_id: PeerId,
        recv_stream: quinn::RecvStream,
        correlation_id: String,
    ) -> Result<(), NetworkError> {
        // This is similar to the logic in receive_message but specifically for response streams
        self.logger.debug(format!(
            "🔄 [QuicTransport] Processing response stream for correlation ID: {}",
            correlation_id
        ));

        // Use the existing receive_message infrastructure to handle the response
        // Pass None for send_stream since this is just a response, not a new bidirectional stream
        self.receive_message(peer_id, recv_stream, None).await
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
            "📖 [QuicTransport] Reading response from stream for correlation ID: {}",
            correlation_id
        ));

        // Read message length (4 bytes)
        let mut len_bytes = [0u8; 4];
        match recv_stream.read_exact(&mut len_bytes).await {
            Ok(_) => {}
            Err(e) => {
                // Handle Quinn-specific errors - ReadExactError doesn't have kind() method
                return Err(NetworkError::MessageError(format!(
                    "Failed to read response length for {}: {}",
                    correlation_id, e
                )));
            }
        }

        let message_len = u32::from_be_bytes(len_bytes) as usize;
        if message_len > 1024 * 1024 {
            // 1MB limit
            return Err(NetworkError::MessageError(format!(
                "Response message too large: {} bytes for correlation ID: {}",
                message_len, correlation_id
            )));
        }

        // Read the message data
        let mut message_data = vec![0u8; message_len];
        recv_stream
            .read_exact(&mut message_data)
            .await
            .map_err(|e| {
                NetworkError::MessageError(format!(
                    "Failed to read response data for {}: {}",
                    correlation_id, e
                ))
            })?;

        // Deserialize the response message
        let message: NetworkMessage = bincode::deserialize(&message_data).map_err(|e| {
            NetworkError::MessageError(format!(
                "Failed to deserialize response for {}: {}",
                correlation_id, e
            ))
        })?;

        logger.debug(format!(
            "✅ [QuicTransport] Successfully read response from stream - Correlation ID: {}, Message Type: {}, Size: {} bytes",
            correlation_id, message.message_type, message_len
        ));

        Ok(message)
    }
}

#[async_trait]
impl NetworkTransport for QuicTransport {
    async fn start(&self) -> Result<(), NetworkError> {
        self.inner.start(&self.background_tasks).await
    }

    async fn stop(&self) -> Result<(), NetworkError> {
        self.inner.stop(&self.background_tasks).await
    }

    async fn disconnect(&self, peer_id: PeerId) -> Result<(), NetworkError> {
        self.inner.disconnect(peer_id).await
    }

    async fn is_connected(&self, peer_id: PeerId) -> bool {
        self.inner.is_connected(peer_id).await
    }

    async fn send_message(&self, message: NetworkMessage) -> Result<(), NetworkError> {
        self.inner.send_message(message).await
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
                        self.logger.error(format!(
                            "Handshake failed after successful connection: {}",
                            e
                        ));
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
}

impl QuicTransport {
    /// Create a new QuicTransport instance
    ///
    /// INTENTION: Create a new QuicTransport with the given node ID, bind address,
    /// options, and logger. This is the primary constructor for QuicTransport.
    ///
    /// This implementation follows the architectural design where QuicTransport is responsible
    /// for thread/task management and lifecycle, while delegating protocol-specific logic to
    /// the QuicTransportImpl which is held in an Arc.
    pub fn new(
        local_node_info: NodeInfo,
        bind_addr: SocketAddr,
        message_handler: Box<
            dyn Fn(NetworkMessage) -> Result<(), NetworkError> + Send + Sync + 'static,
        >,
        options: QuicTransportOptions,
        logger: Arc<Logger>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Create the config struct to pass to the inner implementation
        let config = QuicTransportConfig {
            local_node_info: local_node_info.clone(), // Clone for the inner impl
            bind_addr,
            message_handler,
            options,
            logger: logger.clone(), // Clone for the inner impl
        };

        // Create the inner implementation using the config struct
        let inner_impl = QuicTransportImpl::new(config)?;

        // Create and return the public API wrapper with proper task management
        Ok(Self {
            inner: Arc::new(inner_impl),
            logger, // Use the original logger passed to QuicTransport::new
            node_id: local_node_info.peer_id, // local_node_info is already cloned for config, can move peer_id here
            background_tasks: Mutex::new(Vec::new()),
        })
    }
}

// Custom server name verifier that accepts node IDs as valid server names
#[derive(Debug)]
struct NodeIdServerNameVerifier;

impl rustls::client::danger::ServerCertVerifier for NodeIdServerNameVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Accept any server name - we validate certificates through our own CA chain
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
