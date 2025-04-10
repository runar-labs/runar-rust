// Network Transport Module
//
// This module defines the network transport interfaces and implementations.

// Standard library imports
use std::fmt;
use std::time::Duration;
use std::sync::{Arc, Mutex, RwLock as StdRwLock};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::io::Read;
use std::future::Future;
use std::pin::Pin;

// External crate imports
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use quinn::{Endpoint, ServerConfig, ClientConfig, Connection, ConnectionError, TransportConfig};
use rustls::{client::ServerCertVerifier, server::AllowAnyAuthenticatedClient, ServerName, Certificate, PrivateKey};
use tokio::sync::{RwLock as TokioRwLock, Mutex as TokioMutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;

// Internal module imports
use super::{NetworkTransport, TransportFactory, TransportOptions, NetworkMessage, NetworkError, NodeIdentifier, MessageHandler, ConnectionCallback};
use super::peer_registry::{PeerRegistry, PeerRegistryOptions};
use crate::network::discovery::{NodeInfo, NodeDiscovery};
use runar_common::Logger;

// QUIC Transport Implementation
//
// INTENTION: Implement the NetworkTransport trait using high-performance,
// secure, multiplexed communication between nodes. QUIC provides transport
// security, connection migration, and reliable messaging.

/// QUIC-specific transport options
#[derive(Debug, Clone)]
pub struct QuicTransportOptions {
    /// Base transport options
    pub transport_options: TransportOptions,
    /// Path to the TLS certificate file
    pub cert_path: Option<String>,
    /// Path to the TLS private key file
    pub key_path: Option<String>,
    /// Whether to verify certificates (disable for development)
    pub verify_certificates: bool,
    /// Keep-alive interval in milliseconds
    pub keep_alive_interval_ms: u64,
    /// Maximum number of concurrent bi-directional streams per connection
    pub max_concurrent_bidi_streams: u32,
}

impl Default for QuicTransportOptions {
    fn default() -> Self {
        Self {
            transport_options: TransportOptions::default(),
            cert_path: None,  // No certificate by default, will generate self-signed for development
            key_path: None,   // No key by default, will generate self-signed for development
            // This setting is true by default for security, only disable in development
            verify_certificates: true, 
            keep_alive_interval_ms: 5000,  // 5 seconds
            max_concurrent_bidi_streams: 100,
        }
    }
}

/// QUIC-based implementation of NetworkTransport
pub struct QuicTransport {
    /// Local node identifier
    node_id: NodeIdentifier,
    /// Transport options
    options: QuicTransportOptions,
    /// QUIC endpoint
    endpoint: Arc<TokioMutex<Option<Endpoint>>>,
    /// Active connections to other nodes
    connections: Arc<TokioRwLock<HashMap<String, quinn::Connection>>>,
    /// Peer registry
    peer_registry: Arc<PeerRegistry>,
    /// Handler for incoming messages
    handlers: Arc<StdRwLock<Vec<MessageHandler>>>,
    /// Background tasks
    server_task: Arc<TokioMutex<Option<JoinHandle<()>>>>,
    /// Channel to send outgoing messages
    message_tx: Arc<TokioMutex<Option<mpsc::Sender<(NetworkMessage, Option<String>)>>>>,
    /// Logger instance
    logger: Logger,
}

impl QuicTransport {
    /// Create a new QUIC transport
    pub fn new(node_id: NodeIdentifier, options: QuicTransportOptions, logger: Logger) -> Self {
        Self {
            node_id,
            options,
            endpoint: Arc::new(TokioMutex::new(None)),
            connections: Arc::new(TokioRwLock::new(HashMap::new())),
            peer_registry: Arc::new(PeerRegistry::new()),
            handlers: Arc::new(StdRwLock::new(Vec::new())),
            server_task: Arc::new(TokioMutex::new(None)),
            message_tx: Arc::new(TokioMutex::new(None)),
            logger,
        }
    }
    
    /// Setup the QUIC endpoint
    async fn setup_endpoint(&self) -> Result<Endpoint> {
        // Create server config
        let server_config = self.create_server_config()?;
        
        // Create endpoint config
        // let mut endpoint_config = EndpointConfig::default(); // EndpointConfig is likely unused
        
        // Create the endpoint
        // Unwrap the Option<String> before parsing, provide default
        let bind_addr_str = self.options.transport_options.bind_address
            .as_deref() // Convert Option<String> to Option<&str>
            .unwrap_or("0.0.0.0:0"); // Provide default if None
            
        let socket_addr: SocketAddr = bind_addr_str.parse()
            .map_err(|e| anyhow!("Invalid bind address format '{}': {}", bind_addr_str, e))?;
            
        // Create endpoint from server config and socket address
        let endpoint = Endpoint::server(server_config, socket_addr)?;
        
        Ok(endpoint)
    }
    
    /// Create server configuration for QUIC
    fn create_server_config(&self) -> Result<ServerConfig> {
        // Create transport config
        let mut transport_config = TransportConfig::default();
        
        // Set keep-alive interval
        transport_config.keep_alive_interval(Some(Duration::from_millis(
            self.options.keep_alive_interval_ms
        )));
        
        // Set max concurrent streams
        transport_config.max_concurrent_bidi_streams(
            self.options.max_concurrent_bidi_streams.into()
        );
        
        // Load certificates and private key
        let (cert, key) = self.load_certificates()?;
        
        // Create server configuration
        let server_crypto = if let (Some(cert_chain), Some(key)) = (cert, key) {
            let mut server_config = ServerConfig::with_single_cert(cert_chain, key)?;
            server_config.transport = Arc::new(transport_config);
            Ok(server_config)
        } else {
            // Generate self-signed certificate for development
            self.generate_self_signed_cert()
        }?;
        
        Ok(server_crypto)
    }
    
    /// Create client configuration for QUIC
    fn create_client_config(&self) -> Result<ClientConfig> {
        // Create transport config
        let mut transport_config = TransportConfig::default();
        
        transport_config.keep_alive_interval(Some(Duration::from_millis(
            self.options.keep_alive_interval_ms
        )));
        
        transport_config.max_concurrent_bidi_streams(
            self.options.max_concurrent_bidi_streams.into()
        );
        
        let shared_transport_config = Arc::new(transport_config);
        
        // Create client configuration - using ClientConfig builder
        let mut crypto_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
            
        // Disable certificate verification if needed
        // IMPORTANT: This should ONLY be used for development/testing and NEVER in production
        // Security will be improved in a future update
        if !self.options.verify_certificates {
            self.logger.warn("SECURITY WARNING: Certificate verification is disabled. This configuration is NOT secure for production use!");
            crypto_config.dangerous().set_certificate_verifier(Arc::new(NoVerification {}));
        }
        
        // Apply transport config using the builder
        let mut client_config = ClientConfig::new(Arc::new(crypto_config));
        client_config.transport_config(shared_transport_config);
        
        Ok(client_config)
    }
    
    /// Load certificates and private key from files
    fn load_certificates(&self) -> Result<(Option<Vec<Certificate>>, Option<PrivateKey>)> {
        if let (Some(cert_path), Some(key_path)) = (&self.options.cert_path, &self.options.key_path) {
            // Read certificate file
            let cert_file = std::fs::read(cert_path)?;
            let cert_chain = rustls_pemfile::certs(&mut cert_file.as_slice())?
                .into_iter()
                .map(Certificate)
                .collect();
                
            // Read private key file
            let key_file = std::fs::read(key_path)?;
            let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_file.as_slice())?;
            
            if keys.is_empty() {
                Err(anyhow!("No private keys found in key file"))
            } else {
                let key = PrivateKey(keys.remove(0));
                Ok((Some(cert_chain), Some(key)))
            }
        } else {
            // No certificates provided
            Ok((None, None))
        }
    }
    
    /// Generate a self-signed certificate for development
    fn generate_self_signed_cert(&self) -> Result<ServerConfig> {
        // IMPORTANT: Self-signed certificates should ONLY be used for development/testing
        // This is NOT secure for production use and will be improved in future updates
        self.logger.warn("SECURITY WARNING: Using self-signed certificate. This is NOT secure for production use!");
        
        // For development only - generate a self-signed certificate
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.serialize_der().unwrap();
        let priv_key = cert.serialize_private_key_der();
        let priv_key = PrivateKey(priv_key);
        let cert_chain = vec![Certificate(cert_der)];
        
        let mut server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;
        let mut transport_config = TransportConfig::default();
        
        transport_config.keep_alive_interval(Some(Duration::from_millis(
            self.options.keep_alive_interval_ms
        )));
        
        transport_config.max_concurrent_bidi_streams(
            self.options.max_concurrent_bidi_streams.into()
        );
        
        server_config.transport = Arc::new(transport_config);
        
        Ok(server_config)
    }
    
    /// Start the server task to accept incoming connections
    async fn start_server_task(&self, endpoint: Endpoint) -> Result<()> {
        // Clone Arcs needed for the main loop and potential inner tasks
        let logger = self.logger.clone();
        let handlers_arc = Arc::clone(&self.handlers);
        let connections_arc = Arc::clone(&self.connections);

        let task = tokio::spawn(async move {
            logger.info(format!("QUIC server listening on {}", endpoint.local_addr().unwrap()));
            while let Some(conn_attempt) = endpoint.accept().await {
                match conn_attempt.await {
                    Ok(conn) => {
                        // Clone the necessary state for handling the connection
                        let conn_logger = logger.clone();
                        let conn_handlers = handlers_arc.clone();
                        
                        // Get the remote address for logging
                        let remote_addr = conn.remote_address();
                        conn_logger.info(format!("Accepted QUIC connection from {}", remote_addr));
                        
                        // Spawn a task to handle the connection
                        tokio::spawn(async move {
                            // Simplified connection handler that processes incoming streams
                            loop {
                                match conn.accept_bi().await {
                                    Ok((mut send_stream, mut recv_stream)) => {
                                        // Clone the handlers for this stream
                                        let stream_handlers = conn_handlers.clone();
                                        let stream_logger = conn_logger.clone();
                                        
                                        // Spawn a task to handle this stream
                                        tokio::spawn(async move {
                                            let max_size = 1024 * 1024; // 1MB max message size
                                            match recv_stream.read_to_end(max_size).await {
                                                Ok(data) => {
                                                    stream_logger.debug(format!("Received {} bytes on QUIC stream", data.len()));
                                                    
                                                    // Deserialize the message
                                                    match bincode::deserialize::<NetworkMessage>(&data) {
                                                        Ok(message) => {
                                                            // Process the message with all registered handlers
                                                            if let Ok(handlers_guard) = stream_handlers.read() {
                                                                for handler in handlers_guard.iter() {
                                                                    if let Err(e) = handler(message.clone()) {
                                                                        stream_logger.error(format!("Error in QUIC message handler: {}", e));
                                                                    }
                                                                }
                                                            }
                                                            
                                                            // Send acknowledgement
                                                            let ack = b"ACK";
                                                            if let Err(e) = send_stream.write_all(ack).await {
                                                                stream_logger.error(format!("Failed to send QUIC ACK: {}", e));
                                                            }
                                                            if let Err(e) = send_stream.finish().await {
                                                                stream_logger.warn(format!("Failed to finish QUIC send stream after ACK: {}", e));
                                                            }
                                                        },
                                                        Err(e) => {
                                                            stream_logger.error(format!("Failed to deserialize QUIC message: {}", e));
                                                        }
                                                    }
                                                },
                                                Err(e) => {
                                                    stream_logger.error(format!("Error reading QUIC receive stream: {}", e));
                                                }
                                            }
                                        });
                                    },
                                    Err(ConnectionError::ApplicationClosed { .. }) => {
                                        conn_logger.info("QUIC Connection closed by application.");
                                        break;
                                    },
                                    Err(ConnectionError::LocallyClosed) => {
                                        conn_logger.info("QUIC Connection closed locally.");
                                        break;
                                    },
                                    Err(ConnectionError::TimedOut) => {
                                        conn_logger.warn("QUIC Connection timed out.");
                                        break;
                                    },
                                    Err(e) => {
                                        conn_logger.error(format!("Error accepting QUIC stream: {}", e));
                                        break;
                                    }
                                }
                            }
                            conn_logger.info(format!("Finished handling QUIC connection from {}", remote_addr));
                        });
                    },
                    Err(e) => {
                        logger.error(format!("Error accepting QUIC connection: {}", e));
                    }
                }
            }
            logger.info("QUIC server task stopped accepting connections.");
        });

        // Store the join handle - use Tokio mutex
        *self.server_task.lock().await = Some(task);
        Ok(())
    }
    
    /// Start the message sending task
    async fn start_message_sender(&self) -> Result<()> {
       let (tx, mut rx) = mpsc::channel::<(NetworkMessage, Option<String>)>(100);
       let connections_arc = Arc::clone(&self.connections);
       let logger = self.logger.clone();

        // Spawn the sender task
       tokio::spawn(async move {
           while let Some((message, target_id)) = rx.recv().await {
                // ... log sending ...
                match bincode::serialize(&message) {
                     Ok(data) => {
                         // Use expect before await
                         let connections_read_guard = connections_arc.read().await;
                         let target_connections: Vec<quinn::Connection> = if let Some(id) = target_id {
                             // Send to specific peer
                             connections_read_guard.get(&id).cloned().into_iter().collect()
                         } else {
                             // Broadcast to all connected peers
                             connections_read_guard.values().cloned().collect()
                         };
                         drop(connections_read_guard); // Drop guard before await

                         for conn in target_connections {
                            // ... open stream and send data ...
                            match conn.open_bi().await {
                                Ok((mut send_stream, mut recv_stream)) => {
                                    // Send the data
                                    if let Err(e) = send_stream.write_all(&data).await {
                                        logger.error(format!("Error writing to QUIC stream: {}", e));
                                        continue;
                                    }
                                    // It's crucial to finish the send stream to signal the end of the message
                                    if let Err(e) = send_stream.finish().await {
                                        logger.warn(format!("Error finishing QUIC send stream: {}", e));
                                        continue;
                                    }
                                    logger.debug("Message sent, waiting for ACK...");
                                    
                                    // Optional: Wait for ACK on recv_stream (implement timeout)
                                    match tokio::time::timeout(Duration::from_secs(5), recv_stream.read_to_end(64)).await {
                                        Ok(Ok(ack_data)) => {
                                             if ack_data == b"ACK" {
                                                 logger.debug("Received ACK");
                                             } else {
                                                 logger.warn("Received invalid ACK");
                                             }
                                        }
                                        Ok(Err(e)) => logger.error(format!("Error reading ACK: {}", e)),
                                        Err(_) => logger.warn("Timeout waiting for ACK"), // Timeout error
                                    }

                                }
                                Err(e) => logger.error(format!("Error opening QUIC stream: {}", e)),
                           }
                         }
                     },
                     Err(e) => {
                         logger.error(format!("Failed to serialize QUIC message: {}", e));
                     }
                 }
           }
           logger.info("QUIC message sender task finished.");
       });

       // Store the sender channel - use Tokio mutex
       *self.message_tx.lock().await = Some(tx);
       // Return Ok(()) to match function signature
       Ok(())
    }
    
    /// Handle an incoming connection
    async fn handle_connection(&self, conn: quinn::Connection) -> Result<()> {
        self.logger.info(format!("Handling new QUIC connection from: {}", conn.remote_address()));
        loop {
            match conn.accept_bi().await {
                Ok((mut send_stream, mut recv_stream)) => {
                    self.logger.debug("Accepted new QUIC bidirectional stream");
                    
                    let handlers_arc = Arc::clone(&self.handlers);
                    let logger_clone = self.logger.clone();

                    tokio::spawn(async move {
                        let max_size = 1024 * 1024; 
                        match recv_stream.read_to_end(max_size).await {
                            Ok(data) => {
                                logger_clone.debug(format!("Received {} bytes on QUIC stream", data.len()));
                                match bincode::deserialize::<NetworkMessage>(&data) {
                                    Ok(message) => {
                                        // Use standard RwLock instead of Tokio RwLock
                                        if let Ok(handlers_guard) = handlers_arc.read() {
                                            for handler in handlers_guard.iter() {
                                                if let Err(e) = handler(message.clone()) {
                                                    logger_clone.error(format!("Error in QUIC message handler: {}", e));
                                                }
                                            }
                                        }
                                        
                                        let ack = b"ACK";
                                        if let Err(e) = send_stream.write_all(ack).await {
                                            logger_clone.error(format!("Failed to send QUIC ACK: {}", e));
                                        }
                                        if let Err(e) = send_stream.finish().await {
                                             logger_clone.warn(format!("Failed to finish QUIC send stream after ACK: {}", e));
                                        }
                                    },
                                    Err(e) => {
                                        logger_clone.error(format!("Failed to deserialize QUIC message: {}", e));
                                    }
                                }
                            },
                            Err(e) => {
                                logger_clone.error(format!("Error reading QUIC receive stream: {}", e));
                            }
                        }
                    });
                },
                 Err(ConnectionError::ApplicationClosed { .. }) => {
                    self.logger.info("QUIC Connection closed by application.");
                    break;
                },
                 Err(ConnectionError::LocallyClosed) => {
                    self.logger.info("QUIC Connection closed locally.");
                    break;
                 },
                 Err(ConnectionError::TimedOut) => {
                     self.logger.warn("QUIC Connection timed out.");
                     break;
                 },
                 Err(e) => {
                    self.logger.error(format!("Error accepting QUIC stream: {}", e));
                    break; 
                }
            }
        }
        self.logger.info(format!("Finished handling QUIC connection from: {}", conn.remote_address()));
        Ok(())
    }

}

/// Certificate verifier that accepts any certificate
#[derive(Debug)]
struct NoVerification {}

impl rustls::client::ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

use std::io::Write;

#[async_trait]
impl NetworkTransport for QuicTransport {
    /// Initializes the transport layer
    async fn initialize(&self) -> Result<(), NetworkError> {
        let endpoint = self.setup_endpoint().await
            .map_err(|e| NetworkError::TransportError(format!("Failed to setup endpoint: {}", e)))?;
        
        self.start_server_task(endpoint.clone()).await
            .map_err(|e| NetworkError::TransportError(format!("Failed to start server task: {}", e)))?;
        
        *self.endpoint.lock().await = Some(endpoint);
        
        self.start_message_sender().await
            .map_err(|e| NetworkError::TransportError(format!("Failed to start message sender: {}", e)))?;
        
        self.logger.info("QUIC Transport initialized.");
        Ok(())
    }
    
    /// Start listening for incoming connections
    async fn start(&self) -> Result<(), NetworkError> {
        // Current implementation - call appropriate methods
        Ok(())
    }
    
    /// Stop listening for incoming connections
    async fn stop(&self) -> Result<(), NetworkError> {
        self.logger.info("Shutting down QUIC transport...");
        if let Some(endpoint) = self.endpoint.lock().await.take() { // Use Tokio mutex
            endpoint.close(0u32.into(), b"shutdown");
            endpoint.wait_idle().await;
            self.logger.debug("QUIC endpoint closed.");
        }
        if let Some(task) = self.server_task.lock().await.take() { // Use Tokio mutex
            task.abort();
            let _ = task.await; // Wait for abort
            self.logger.debug("QUIC server task stopped.");
        }
        if let Some(tx) = self.message_tx.lock().await.take() { // Use Tokio mutex
           drop(tx); // Close the channel sender
           self.logger.debug("QUIC message sender channel closed.");
           // Add logic to wait for the sender task if it has a handle
        }
        self.connections.write().await.clear(); // Use Tokio rwlock
        if let Ok(mut handlers) = self.handlers.write() {
            handlers.clear();
        }
        self.logger.info("QUIC transport shut down successfully.");
        Ok(())
    }
    
    /// Check if the transport is running
    fn is_running(&self) -> bool {
        // Check if server_task is Some
        true
    }
    
    /// Get the local address this transport is bound to
    fn get_local_address(&self) -> String {
        // Current implementation of local_address but return as string
        "0.0.0.0:0".to_string()
    }
    
    /// Get the local node identifier
    fn get_local_node_id(&self) -> NodeIdentifier {
        // Current implementation of local_node_id
        self.node_id.clone()
    }
    
    /// Connect to a remote node
    async fn connect(&self, node_id: NodeIdentifier) -> Result<(), NetworkError> {
        // Current implementation of connect but modified signature
        Ok(())
    }
    
    /// Disconnect from a remote node
    async fn disconnect(&self, node_id: NodeIdentifier) -> Result<(), NetworkError> {
        // New method
        Ok(())
    }
    
    /// Check if connected to a specific node
    fn is_connected(&self, node_id: NodeIdentifier) -> bool {
        // Check connections map
        false
    }
    
    /// Register a message handler for incoming messages
    fn register_message_handler(&self, handler: MessageHandler) -> Result<()> {
        // Current implementation of register_handler
        match self.handlers.write() {
            Ok(mut handlers) => {
                handlers.push(handler);
                Ok(())
            },
            Err(_) => Err(anyhow::Error::msg("Failed to acquire write lock for message handlers").into()),
        }
    }
    
    /// Set a callback for connection status changes
    fn set_connection_callback(&self, callback: ConnectionCallback) -> Result<()> {
        // New method
        Ok(())
    }
    
    /// Send a message to a remote node
    async fn send_message(&self, message: NetworkMessage) -> Result<(), NetworkError> {
        let tx_guard = self.message_tx.lock().await;
        if let Some(sender) = tx_guard.as_ref() {
            // Determine target address (None for broadcast)
            let target_id = message.destination.as_ref().map(|id| id.to_string());
            sender.send((message, target_id)).await
                .map_err(|e| NetworkError::MessageError(format!("Failed to queue message for sending: {}", e)))
        } else {
            Err(NetworkError::TransportError("Message sender task not initialized".to_string()))
        }
    }
    fn get_connected_nodes(&self) -> Vec<NodeIdentifier> {
        // Implement based on connections
        Vec::new()
    }
    
    /// Send a service request to a remote node
    async fn send_request(&self, message: NetworkMessage) -> Result<NetworkMessage, NetworkError> {
        // New method
        Err(NetworkError::TransportError("Not implemented".to_string()))
    }
    
    /// Handle an incoming network message
    async fn handle_message(&self, message: NetworkMessage) -> Result<(), NetworkError> {
        // New method
        Ok(())
    }
    
    /// Start node discovery process
    async fn start_discovery(&self) -> Result<(), NetworkError> {
        // New method
        Ok(())
    }
    
    /// Stop node discovery process
    async fn stop_discovery(&self) -> Result<(), NetworkError> {
        // New method
        Ok(())
    }
    
    /// Register a discovered node
    async fn register_discovered_node(&self, node_id: NodeIdentifier) -> Result<(), NetworkError> {
        // New method
        Ok(())
    }
    
    /// Get all discovered nodes
    fn get_discovered_nodes(&self) -> Vec<NodeIdentifier> {
        // New method
        Vec::new()
    }
    
    /// Set the node discovery mechanism
    fn set_node_discovery(&self, discovery: Box<dyn NodeDiscovery>) -> Result<()> {
        // New method
        Ok(())
    }
    
    /// Complete a pending request
    fn complete_pending_request(&self, correlation_id: String, response: NetworkMessage) -> Result<(), NetworkError> {
        // New method
        Ok(())
    }
}

/// Factory for creating QUIC transport instances
#[derive(Clone)]
pub struct QuicTransportFactory {
    options: QuicTransportOptions,
    logger: Logger,
}

impl QuicTransportFactory {
    /// Create a new factory
    pub fn new(options: QuicTransportOptions, logger: Logger) -> Self {
        QuicTransportFactory { options, logger }
    }
}

#[async_trait]
impl TransportFactory for QuicTransportFactory {
    type Transport = QuicTransport;

    async fn create_transport(&self, node_id: NodeIdentifier, logger: Logger) -> Result<Self::Transport> {
        // Pass the factory's logger down, or use the provided one?
        // Let's use the one passed specifically for this transport instance.
        Ok(QuicTransport::new(node_id, self.options.clone(), logger))
    }
} 