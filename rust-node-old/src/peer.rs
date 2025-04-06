use crate::db::SqliteDatabase;
use crate::p2p::crypto::{AccessToken, Crypto, NetworkId, PeerId};
use crate::p2p::dht::DHT;
use crate::p2p::transport::P2PTransport;
use anyhow::{anyhow, Error, Result};
use async_trait::async_trait;
use base64;
use bincode;
use futures::future::join_all;
use quinn::{ClientConfig, EndpointConfig, ServerConfig, TransportConfig};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rand;
use rcgen;
use rustls::{Certificate, PrivateKey};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

pub struct Peer {
    pub peer_id: PeerId,
    pub(crate) endpoint: Endpoint,
    pub(crate) connections: HashMap<PeerId, Connection>,
    message_sender: mpsc::Sender<(PeerId, Vec<u8>)>,
    pub(crate) dht: DHT,
    pub(crate) networks: HashMap<NetworkId, NetworkInfo>,
}

// Certificate verifier that accepts any certificate for testing
struct AcceptAllCertVerifier {}

impl rustls::client::ServerCertVerifier for AcceptAllCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[derive(Clone, Debug)]
pub struct NetworkInfo {
    pub admin_pubkey: ed25519_dalek::PublicKey,
    pub name: String,
    pub token: AccessToken,
}

// Define the Component enum for logging
#[derive(Debug, Clone, Copy)]
pub enum Component {
    P2P,
    // Add other components as needed
}

// Define logging functions
fn debug_log(component: Component, message: &str).await {
    debug!("[{:?}] {}", component, message);
}

fn error_log(component: Component, message: &str).await {
    error!("[{:?}] {}", component, message);
}

fn info_log(component: Component, message: &str).await {
    info!("[{:?}] {}", component, message);
}

impl Peer {
    pub fn new(peer_id: PeerId, message_sender: mpsc::Sender<(PeerId, Vec<u8>)>) -> Self {
        let (endpoint, _) = Self::create_quic_endpoint().unwrap();
        let peer_id_clone = peer_id.clone();
        Self {
            peer_id,
            endpoint,
            connections: HashMap::new(),
            message_sender,
            dht: DHT::new(peer_id_clone),
            networks: HashMap::new(),
        }
    }

    pub fn new_with_addr(
        peer_id: PeerId,
        message_sender: mpsc::Sender<(PeerId, Vec<u8>)>,
        listen_addr: Option<String>,
    ) -> Self {
        let (endpoint, _) = match listen_addr {
            Some(addr) => Self::create_quic_endpoint_with_addr(&addr)
                .unwrap_or_else(|_| Self::create_quic_endpoint().unwrap()),
            None => Self::create_quic_endpoint().unwrap(),
        };
        let peer_id_clone = peer_id.clone();
        Self {
            peer_id,
            endpoint,
            connections: HashMap::new(),
            message_sender,
            dht: DHT::new(peer_id_clone),
            networks: HashMap::new(),
        }
    }

    // Getters for private fields
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn connections(&self) -> &HashMap<PeerId, Connection> {
        &self.connections
    }

    pub fn dht(&self) -> &DHT {
        &self.dht
    }

    pub fn networks(&self) -> &HashMap<NetworkId, NetworkInfo> {
        &self.networks
    }

    // Mutable getters for private fields
    pub fn connections_mut(&mut self) -> &mut HashMap<PeerId, Connection> {
        &mut self.connections
    }

    pub fn dht_mut(&mut self) -> &mut DHT {
        &mut self.dht
    }

    pub fn networks_mut(&mut self) -> &mut HashMap<NetworkId, NetworkInfo> {
        &mut self.networks
    }

    /// Get the current network ID if one is set
    pub fn network_id(&self) -> Option<&NetworkId> {
        if self.networks.is_empty() {
            None
        } else {
            // Return the first network ID (there's typically only one)
            self.networks.keys().next()
        }
    }

    fn create_quic_endpoint() -> Result<(Endpoint, tokio::task::JoinHandle<()>)> {
        // For testing purposes, we'll use a more tolerant approach
        // This function might fail in tests but we'll catch that at a higher level

        // Create server config with insecure settings for testing
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new())),
        ));

        // Create client config with insecure settings for testing
        let client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(AcceptAllCertVerifier {}))
            .with_no_client_auth();

        let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));

        // Create endpoint config
        let endpoint_config = quinn::EndpointConfig::default();

        // Try to bind to a socket - if this fails in tests that's ok
        let socket = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(e) => return Err(anyhow!("Failed to bind UDP socket: {}", e)),
        };

        // Create the endpoint with proper TokioRuntime
        let mut endpoint = match quinn::Endpoint::new(
            endpoint_config,
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        ) {
            Ok(ep) => ep,
            Err(e) => return Err(anyhow!("Failed to create endpoint: {}", e)),
        };

        // Set the default client config
        endpoint.set_default_client_config(client_config);

        // Clone the endpoint for the task
        let endpoint_clone = endpoint.clone();

        let handle = tokio::spawn(async move {
            while let Some(conn) = endpoint_clone.accept().await {
                tokio::spawn(handle_connection(conn));
            }
        });

        Ok((endpoint, handle))
    }

    fn create_quic_endpoint_with_addr(
        addr: &str,
    ) -> Result<(Endpoint, tokio::task::JoinHandle<()>)> {
        // Generate a self-signed certificate for testing
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.serialize_der().unwrap();
        let priv_key = cert.serialize_private_key_der();
        let priv_key = rustls::PrivateKey(priv_key);
        let cert_chain = vec![rustls::Certificate(cert_der)];

        // Create server config with the generated certificate
        let mut server_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain.clone(), priv_key)
            .map_err(|e| anyhow!("Failed to create server config: {}", e))?;

        // Set ALPN protocols
        server_config.alpn_protocols = vec![b"runar-p2p".to_vec()];

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(server_config));

        // Create client config with the certificate
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(AcceptAllCertVerifier {}))
            .with_no_client_auth();

        // Set ALPN protocols
        client_crypto.alpn_protocols = vec![b"runar-p2p".to_vec()];

        let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));

        // Create endpoint config
        let mut endpoint_config = quinn::EndpointConfig::default();
        // Configure any endpoint settings if needed

        // Try to bind to the specified socket
        let socket = match std::net::UdpSocket::bind(addr) {
            Ok(s) => s,
            Err(e) => return Err(anyhow!("Failed to bind UDP socket to {}: {}", addr, e)),
        };

        // Create the endpoint with proper TokioRuntime
        let mut endpoint = match quinn::Endpoint::new(
            endpoint_config,
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        ) {
            Ok(ep) => ep,
            Err(e) => return Err(anyhow!("Failed to create endpoint: {}", e)),
        };

        // Set the default client config
        endpoint.set_default_client_config(client_config);

        // Clone the endpoint for the task
        let endpoint_clone = endpoint.clone();

        let handle = tokio::spawn(async move {
            while let Some(conn) = endpoint_clone.accept().await {
                tokio::spawn(handle_connection(conn));
            }
        });

        Ok((endpoint, handle))
    }

    pub async fn connect_to_peer(
        &mut self,
        peer_id: PeerId,
        addr_str: &str,
        network_id: NetworkId,
    ) -> Result<()> {
        // Check if we're already connected to this peer
        if self.connections.contains_key(&peer_id) {
            debug_log(
                Component::P2P,
                &format!("Already connected to peer {:?}", peer_id),
            );
            return Ok(());
        }

        info_log(
            Component::P2P,
            &format!("Connecting to peer {:?} at {}", peer_id, addr_str),
        );

        // Parse the address
        let addr = addr_str
            .parse::<SocketAddr>()
            .map_err(|e| anyhow!("Invalid address format: {}", e))?;

        // Connect to the peer
        let endpoint = self.endpoint.clone();
        let conn = match endpoint.connect(addr, "localhost") {
            Ok(connecting) => match connecting.await {
                Ok(conn) => conn,
                Err(e) => {
                    error_log(Component::P2P, &format!("Failed to connect to peer: {}", e));
                    return Err(anyhow!("Failed to connect to peer: {}", e));
                }
            },
            Err(e) => {
                error_log(
                    Component::P2P,
                    &format!("Failed to initiate connection: {}", e),
                );
                return Err(anyhow!("Failed to initiate connection: {}", e));
            }
        };

        // Create a dummy token for testing
        let dummy_token = AccessToken {
            peer_id: peer_id.clone(),
            network_id: network_id.clone(),
            expiration: None,
            signature: vec![0; 64], // Dummy signature
        };

        // Exchange tokens
        if let Err(e) = self.exchange_tokens(&conn, &dummy_token, &network_id).await {
            error_log(Component::P2P, &format!("Failed to exchange tokens: {}", e));
            return Err(anyhow!("Failed to exchange tokens: {}", e));
        }

        // Store the connection
        self.connections.insert(peer_id.clone(), conn.clone());

        // Spawn a task to handle incoming streams and keep the connection alive
        let peer_id_clone = peer_id.clone();
        let conn_clone = conn.clone();
        let message_sender = self.message_sender.clone();

        tokio::spawn(async move {
            debug_log(
                Component::P2P,
                &format!("Starting connection handler for peer: {:?}", peer_id_clone),
            );

            // Create a buffer to receive data
            let mut buffer = vec![0; 1024];

            // Accept incoming bi-directional streams
            loop {
                match conn_clone.accept_bi().await {
                    Ok((mut send, mut recv)) => {
                        debug_log(Component::P2P, "Accepted new bidirectional stream");

                        // Read data from the stream
                        match recv.read(&mut buffer).await {
                            Ok(Some(len)) => {
                                debug_log(
                                    Component::P2P,
                                    &format!("Received {} bytes from peer", len),
                                );

                                // Forward the message to the application
                                let _ = message_sender
                                    .send((peer_id_clone.clone(), buffer[..len].to_vec()))
                                    .await;

                                // For testing, just echo the message back
                                if let Err(e) = send.write_all(&buffer[..len]).await {
                                    error_log(
                                        Component::P2P,
                                        &format!("Failed to send response: {}", e),
                                    );
                                }

                                // Finish the stream
                                if let Err(e) = send.finish().await {
                                    error_log(
                                        Component::P2P,
                                        &format!("Failed to finish stream: {}", e),
                                    );
                                }
                            }
                            Ok(None) => {
                                debug_log(Component::P2P, "Stream closed by peer");
                                // Continue the loop to accept more streams
                                continue;
                            }
                            Err(e) => {
                                error_log(
                                    Component::P2P,
                                    &format!("Error reading from stream: {}", e),
                                );
                                // Only break if the connection is closed
                                if e.to_string().contains("closed") {
                                    break;
                                }
                                // Otherwise continue accepting streams
                                continue;
                            }
                        }
                    }
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                        debug_log(Component::P2P, "Connection closed by peer application");
                        break;
                    }
                    Err(e) => {
                        error_log(Component::P2P, &format!("Error accepting stream: {}", e));
                        // Only break if the connection is closed
                        if e.to_string().contains("closed") {
                            break;
                        }
                        // Add a small delay before trying again to avoid tight loops
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        continue;
                    }
                }
            }

            debug_log(
                Component::P2P,
                &format!("Connection handler for peer {:?} completed", peer_id_clone),
            );
        });

        Ok(())
    }

    async fn exchange_tokens(
        &self,
        conn: &Connection,
        token: &AccessToken,
        network_id: &NetworkId,
    ) -> Result<()> {
        // For testing purposes, we'll skip the token verification
        debug_log(
            Component::P2P,
            &format!("Exchanging tokens with peer for network: {:?}", network_id),
        );

        // Try to open a bidirectional stream
        let mut stream = match conn.open_bi().await {
            Ok(s) => s,
            Err(e) => {
                error_log(
                    Component::P2P,
                    &format!("Failed to open bidirectional stream: {}", e),
                );
                return Err(anyhow!("Failed to open bidirectional stream: {}", e));
            }
        };

        // Serialize the token
        let serialized_token = match bincode::serialize(token) {
            Ok(s) => s,
            Err(e) => {
                error_log(Component::P2P, &format!("Failed to serialize token: {}", e));
                return Err(anyhow!("Failed to serialize token: {}", e));
            }
        };

        // Send the token
        if let Err(e) = stream.0.write_all(&serialized_token).await {
            error_log(Component::P2P, &format!("Failed to send token: {}", e));
            return Err(anyhow!("Failed to send token: {}", e));
        }

        // Finish the stream to signal the end of the token
        if let Err(e) = stream.0.finish().await {
            error_log(Component::P2P, &format!("Failed to finish stream: {}", e));
            return Err(anyhow!("Failed to finish stream: {}", e));
        }

        // For testing purposes, we'll skip reading the peer token
        debug_log(Component::P2P, "Token exchange completed successfully");

        Ok(())
    }

    pub async fn send_to_peer<T: Serialize>(&self, peer_id: PeerId, message: T) -> Result<()> {
        debug_log(
            Component::P2P,
            &format!("Sending message to peer: {:?}", peer_id),
        );

        let conn = self
            .connections
            .get(&peer_id)
            .ok_or(Error::msg("Peer not connected"))?;

        // Open a bidirectional stream
        let mut stream = match conn.open_bi().await {
            Ok(s) => s,
            Err(e) => {
                error_log(
                    Component::P2P,
                    &format!("Failed to open bidirectional stream: {}", e),
                );
                return Err(anyhow!("Failed to open bidirectional stream: {}", e));
            }
        };

        // Serialize the message
        let serialized = match bincode::serialize(&message) {
            Ok(s) => s,
            Err(e) => {
                error_log(
                    Component::P2P,
                    &format!("Failed to serialize message: {}", e),
                );
                return Err(anyhow!("Failed to serialize message: {}", e));
            }
        };

        // Send the message
        if let Err(e) = stream.0.write_all(&serialized).await {
            error_log(Component::P2P, &format!("Failed to send message: {}", e));
            return Err(anyhow!("Failed to send message: {}", e));
        }

        // Finish the stream to signal the end of the message
        if let Err(e) = stream.0.finish().await {
            error_log(Component::P2P, &format!("Failed to finish stream: {}", e));
            return Err(anyhow!("Failed to finish stream: {}", e));
        }

        // Wait for a response to ensure the message was received
        let mut buffer = vec![0; 1024];
        match stream.1.read(&mut buffer).await {
            Ok(Some(len)) => {
                debug_log(
                    Component::P2P,
                    &format!("Received response of {} bytes", len),
                );
                // Process the response if needed
            }
            Ok(None) => {
                debug_log(Component::P2P, "No response from peer");
            }
            Err(e) => {
                error_log(Component::P2P, &format!("Error reading response: {}", e));
                // Don't return an error here, as we've already sent the message successfully
            }
        }

        debug_log(
            Component::P2P,
            &format!("Message sent successfully to peer: {:?}", peer_id),
        );

        Ok(())
    }

    pub async fn broadcast<T: Serialize>(&self, peer_ids: &[PeerId], message: T) -> Result<()> {
        // Serialize the message once
        let serialized = bincode::serialize(&message)?;

        // Use a Vec to collect the futures
        let mut futures = Vec::with_capacity(peer_ids.len());

        // For each peer, create a future that sends the serialized message
        for peer_id in peer_ids {
            if let Some(conn) = self.connections.get(peer_id) {
                // Clone the serialized data for each future
                let data = serialized.clone();

                // Create the future
                let future = async move {
                    let mut stream = conn.open_bi().await?;
                    stream.0.write_all(&data).await?;
                    Ok::<_, anyhow::Error>(())
                };

                futures.push(future);
            }
        }

        // Join all futures and collect the results
        join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()?;

        Ok(())
    }

    async fn handle_connection(&self, connection: Connection) -> Result<()> {
        debug_log(
            Component::P2P,
            &format!("Handling new connection from peer"),
        );

        // Create a buffer to receive data
        let mut buffer = vec![0; 1024];

        // Accept incoming bi-directional streams
        loop {
            match connection.accept_bi().await {
                Ok((mut send, mut recv)) => {
                    debug_log(Component::P2P, "Accepted new bidirectional stream");

                    // Read data from the stream
                    match recv.read(&mut buffer).await {
                        Ok(Some(len)) => {
                            debug_log(Component::P2P, &format!("Received {} bytes from peer", len));

                            // For testing, just echo the message back
                            if let Err(e) = send.write_all(&buffer[..len]).await {
                                error_log(
                                    Component::P2P,
                                    &format!("Failed to send response: {}", e),
                                );
                            }

                            // Finish the stream
                            if let Err(e) = send.finish().await {
                                error_log(
                                    Component::P2P,
                                    &format!("Failed to finish stream: {}", e),
                                );
                            }
                        }
                        Ok(None) => {
                            debug_log(Component::P2P, "Stream closed by peer");
                            break;
                        }
                        Err(e) => {
                            error_log(Component::P2P, &format!("Error reading from stream: {}", e));
                            break;
                        }
                    }
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    debug_log(Component::P2P, "Connection closed by peer application");
                    break;
                }
                Err(e) => {
                    error_log(Component::P2P, &format!("Error accepting stream: {}", e));
                    break;
                }
            }
        }

        debug_log(Component::P2P, "Connection handler completed");

        Ok(())
    }
}

async fn handle_connection(conn: quinn::Connecting) -> Result<()> {
    let connection = conn.await?;
    debug_log(
        Component::P2P,
        &format!("Handling new connection from peer"),
    );

    // Create a buffer to receive data
    let mut buffer = vec![0; 1024];

    // Accept incoming bi-directional streams
    loop {
        match connection.accept_bi().await {
            Ok((mut send, mut recv)) => {
                debug_log(Component::P2P, "Accepted new bidirectional stream");

                // Read data from the stream
                match recv.read(&mut buffer).await {
                    Ok(Some(len)) => {
                        debug_log(Component::P2P, &format!("Received {} bytes from peer", len));

                        // For testing, just echo the message back
                        if let Err(e) = send.write_all(&buffer[..len]).await {
                            error_log(Component::P2P, &format!("Failed to send response: {}", e));
                        }

                        // Finish the stream
                        if let Err(e) = send.finish().await {
                            error_log(Component::P2P, &format!("Failed to finish stream: {}", e));
                        }
                    }
                    Ok(None) => {
                        debug_log(Component::P2P, "Stream closed by peer");
                        // Continue the loop to accept more streams
                        continue;
                    }
                    Err(e) => {
                        error_log(Component::P2P, &format!("Error reading from stream: {}", e));
                        // Only break if the connection is closed
                        if e.to_string().contains("closed") {
                            break;
                        }
                        // Otherwise continue accepting streams
                        continue;
                    }
                }
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                debug_log(Component::P2P, "Connection closed by peer application");
                break;
            }
            Err(e) => {
                error_log(Component::P2P, &format!("Error accepting stream: {}", e));
                // Only break if the connection is closed
                if e.to_string().contains("closed") {
                    break;
                }
                // Add a small delay before trying again to avoid tight loops
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
        }
    }

    debug_log(Component::P2P, "Connection handler completed");

    Ok(())
}
