use runar_schemas::NodeInfo;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::watch;

use async_trait::async_trait;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use runar_common::compact_ids::compact_id;
use runar_common::logging::Logger;
use runar_macros_common::{log_debug, log_error, log_info, log_warn};
use serde::{Deserialize, Serialize};

use dashmap::DashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::RwLock;
// Removed custom certificate parsing; rely on rustls standard verification.

use crate::discovery::multicast_discovery::PeerInfo;

use crate::transport::{GetLocalNodeInfoCallback, NetworkError, NetworkMessage, NetworkTransport};
use runar_keys::NodeKeyManager;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

// No direct use of ServerName; rely on rustls SNI handling.

pub struct QuicTransportOptions {
    // Original QUIC/TLS options
    certificates: Option<Vec<CertificateDer<'static>>>,
    private_key: Option<PrivateKeyDer<'static>>,
    root_certificates: Option<Vec<CertificateDer<'static>>>,
    connection_idle_timeout: Duration,
    keep_alive_interval: Duration,

    // New parameters moved from constructor
    local_node_public_key: Option<Vec<u8>>,
    bind_addr: Option<SocketAddr>,
    // message_handler: Option<super::MessageHandler>,
    // one_way_message_handler: Option<super::OneWayMessageHandler>,
    peer_connected_callback: Option<super::PeerConnectedCallback>,
    peer_disconnected_callback: Option<super::PeerDisconnectedCallback>,
    request_callback: Option<super::RequestCallback>,
    event_callback: Option<super::EventCallback>,
    get_local_node_info: Option<GetLocalNodeInfoCallback>,
    //connection_callback: Option<super::ConnectionCallback>,
    logger: Option<Arc<Logger>>,
    keystore: Option<Arc<dyn runar_serializer::traits::EnvelopeCrypto>>,
    label_resolver_config: Option<Arc<runar_serializer::traits::LabelResolverConfig>>,
    // Cache TTL for idempotent response replay
    response_cache_ttl: Duration,
    // Maximum number of retries for failed requests
    max_request_retries: Option<u32>,
    // Timeout for waiting a handshake response from peer
    handshake_response_timeout: Duration,
    // Timeout for opening streams
    open_stream_timeout: Duration,
    // Effective maximum message size (bytes) enforced by framing
    max_message_size: Option<usize>,
    // Optional: use key manager directly for certs/keys/roots
    key_manager: Option<Arc<NodeKeyManager>>,
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
            .field("local_node_public_key", &self.local_node_public_key)
            .field("bind_addr", &self.bind_addr)
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
                "label_resolver_config",
                &if self.label_resolver_config.is_some() {
                    "Some(LabelResolverConfig)"
                } else {
                    "None"
                },
            )
            .field(
                "request_callback",
                &if self.request_callback.is_some() {
                    "Some(RequestCallback)"
                } else {
                    "None"
                },
            )
            .field(
                "event_callback",
                &if self.event_callback.is_some() {
                    "Some(EventCallback)"
                } else {
                    "None"
                },
            )
            .finish()
    }
}

impl Default for QuicTransportOptions {
    fn default() -> Self {
        Self {
            certificates: None,
            private_key: None,
            root_certificates: None,
            // Provide sane non-zero defaults to avoid immediate handshake/idle timeouts
            connection_idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(5),

            local_node_public_key: None,
            bind_addr: None,
            peer_connected_callback: None,
            peer_disconnected_callback: None,
            request_callback: None,
            event_callback: None,
            get_local_node_info: None,
            logger: None,
            keystore: None,
            label_resolver_config: None,
            response_cache_ttl: Duration::from_secs(5),
            max_request_retries: None,
            handshake_response_timeout: Duration::from_secs(2),
            open_stream_timeout: Duration::from_secs(1),
            max_message_size: Some(1024 * 1024),
            key_manager: None,
        }
    }
}

impl QuicTransportOptions {
    pub fn new() -> Self {
        Self::default()
    }

    // Original builder methods - DEPRECATED: Use with_key_manager instead
    /// DEPRECATED: Use `with_key_manager()` instead for production code.
    /// This method is kept for testing purposes only.
    pub fn with_certificates(mut self, certs: Vec<CertificateDer<'static>>) -> Self {
        self.certificates = Some(certs);
        self
    }

    /// DEPRECATED: Use `with_key_manager()` instead for production code.
    /// This method is kept for testing purposes only.
    pub fn with_private_key(mut self, key: PrivateKeyDer<'static>) -> Self {
        self.private_key = Some(key);
        self
    }

    /// DEPRECATED: Use `with_key_manager()` instead for production code.
    /// This method is kept for testing purposes only.
    pub fn with_root_certificates(mut self, certs: Vec<CertificateDer<'static>>) -> Self {
        self.root_certificates = Some(certs);
        self
    }

    // New builder methods for moved parameters
    pub fn with_local_node_public_key(mut self, public_key: Vec<u8>) -> Self {
        self.local_node_public_key = Some(public_key);
        self
    }

    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    // pub fn with_message_handler(mut self, handler: super::MessageHandler) -> Self {
    //     self.message_handler = Some(handler);
    //     self
    // }

    // pub fn with_one_way_message_handler(mut self, handler: super::OneWayMessageHandler) -> Self {
    //     self.one_way_message_handler = Some(handler);
    //     self
    // }

    pub fn with_peer_connected_callback(mut self, callback: super::PeerConnectedCallback) -> Self {
        self.peer_connected_callback = Some(callback);
        self
    }

    pub fn with_peer_disconnected_callback(
        mut self,
        callback: super::PeerDisconnectedCallback,
    ) -> Self {
        self.peer_disconnected_callback = Some(callback);
        self
    }

    pub fn with_request_callback(mut self, callback: super::RequestCallback) -> Self {
        self.request_callback = Some(callback);
        self
    }

    pub fn with_event_callback(mut self, callback: super::EventCallback) -> Self {
        self.event_callback = Some(callback);
        self
    }

    pub fn with_get_local_node_info(
        mut self,
        get_local_node_info: GetLocalNodeInfoCallback,
    ) -> Self {
        self.get_local_node_info = Some(get_local_node_info);
        self
    }

    pub fn with_logger(mut self, logger: Arc<Logger>) -> Self {
        self.logger = Some(logger);
        self
    }

    pub fn with_logger_from_node_id(mut self, node_id: String) -> Self {
        let logger = Arc::new(Logger::new_root(runar_common::Component::Transporter));
        logger.set_node_id(node_id);
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

    pub fn with_label_resolver_config(
        mut self,
        config: Arc<runar_serializer::traits::LabelResolverConfig>,
    ) -> Self {
        self.label_resolver_config = Some(config);
        self
    }

    pub fn with_response_cache_ttl(mut self, ttl: Duration) -> Self {
        self.response_cache_ttl = ttl;
        self
    }

    pub fn with_max_request_retries(mut self, max_retries: u32) -> Self {
        self.max_request_retries = Some(max_retries);
        self
    }

    pub fn with_handshake_response_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_response_timeout = timeout;
        self
    }

    pub fn with_open_stream_timeout(mut self, timeout: Duration) -> Self {
        self.open_stream_timeout = timeout;
        self
    }

    pub fn with_max_message_size(mut self, max: usize) -> Self {
        self.max_message_size = Some(max);
        self
    }

    pub fn with_key_manager(mut self, key_manager: Arc<NodeKeyManager>) -> Self {
        self.key_manager = Some(key_manager);
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
    pub fn local_node_public_key(&self) -> Option<&Vec<u8>> {
        self.local_node_public_key.as_ref()
    }

    pub fn bind_addr(&self) -> Option<SocketAddr> {
        self.bind_addr
    }

    pub fn logger(&self) -> Option<&Arc<Logger>> {
        self.logger.as_ref()
    }

    pub fn keystore(&self) -> Option<&Arc<dyn runar_serializer::traits::EnvelopeCrypto>> {
        self.keystore.as_ref()
    }

    pub fn label_resolver_config(
        &self,
    ) -> Option<&Arc<runar_serializer::traits::LabelResolverConfig>> {
        self.label_resolver_config.as_ref()
    }

    pub fn response_cache_ttl(&self) -> Duration {
        self.response_cache_ttl
    }

    pub fn max_message_size(&self) -> Option<usize> {
        self.max_message_size
    }

    pub fn key_manager(&self) -> Option<&Arc<NodeKeyManager>> {
        self.key_manager.as_ref()
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
            local_node_public_key: self.local_node_public_key.clone(),
            bind_addr: self.bind_addr,
            peer_connected_callback: self.peer_connected_callback.clone(),
            peer_disconnected_callback: self.peer_disconnected_callback.clone(),
            request_callback: self.request_callback.clone(),
            event_callback: self.event_callback.clone(),
            get_local_node_info: self.get_local_node_info.clone(),
            logger: self.logger.clone(),
            keystore: self.keystore.clone(),
            label_resolver_config: self.label_resolver_config.clone(),
            response_cache_ttl: self.response_cache_ttl,
            max_request_retries: self.max_request_retries,
            handshake_response_timeout: self.handshake_response_timeout,
            open_stream_timeout: self.open_stream_timeout,
            max_message_size: self.max_message_size,
            key_manager: self.key_manager.clone(),
        }
    }
}

/// Simple peer state used by the new transport.
#[derive(Debug, Clone)]
struct PeerState {
    connection: Arc<quinn::Connection>,
    connection_id: usize,
    node_info_version: i64,
    initiator_peer_id: String,
    initiator_nonce: u64,
    responder_peer_id: String,
    responder_nonce: u64,
    // Connection becomes active only after duplicate-resolution + handshake complete
    activation_tx: watch::Sender<bool>,
    activation_rx: watch::Receiver<bool>,
}

impl PeerState {
    fn new(
        connection: Arc<quinn::Connection>,
        node_info_version: i64,
        initiator_peer_id: String,
        initiator_nonce: u64,
        responder_peer_id: String,
        responder_nonce: u64,
    ) -> Self {
        let (activation_tx, activation_rx) = watch::channel(false);
        Self {
            connection: connection.clone(),
            connection_id: connection.stable_id(),
            node_info_version,
            initiator_peer_id,
            initiator_nonce,
            responder_peer_id,
            responder_nonce,
            activation_tx,
            activation_rx,
        }
    }
}

#[derive(Clone, Debug)]
struct SharedState {
    peers: Arc<DashMap<String, PeerState>>,
    connection_id_to_peer_id: Arc<DashMap<usize, String>>,
    dial_backoff: Arc<DashMap<String, (u32, Instant)>>,
    dial_cancel: Arc<DashMap<String, Arc<Notify>>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum ConnectionRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HandshakeData {
    node_info: NodeInfo,
    nonce: u64,
    role: ConnectionRole,
}

/// Encode a `NetworkMessage` with a 4-byte BE length prefix.
fn encode_message(msg: &NetworkMessage) -> Result<Vec<u8>, NetworkError> {
    let mut buf = serde_cbor::to_vec(msg)
        .map_err(|e| NetworkError::MessageError(format!("failed to encode cbor: {e}")))?;

    let mut framed = (buf.len() as u32).to_be_bytes().to_vec();
    framed.append(&mut buf);

    Ok(framed)
}

// Custom server name verification is removed from production; rely on rustls standard verification.

pub struct QuicTransport {
    // immutable configuration
    bind_addr: SocketAddr,
    options: QuicTransportOptions,

    local_node_id: String,

    // runtime state
    endpoint: Arc<RwLock<Option<Endpoint>>>,
    logger: Arc<Logger>,

    max_request_retries: u32,

    // callback into Node layer
    peer_connected_callback: Option<super::PeerConnectedCallback>,
    peer_disconnected_callback: Option<super::PeerDisconnectedCallback>,
    request_callback: super::RequestCallback,
    event_callback: super::EventCallback,
    get_local_node_info: GetLocalNodeInfoCallback,

    // Per-peer connect guards to avoid concurrent connects
    peer_connect_mutexes: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,

    // crypto helpers
    keystore: Arc<dyn runar_serializer::traits::EnvelopeCrypto>,
    label_resolver_config: Arc<runar_serializer::traits::LabelResolverConfig>,

    // shared runtime state (peers + broadcast)
    state: SharedState,

    // short-lived cache to deduplicate REQUEST handling by correlation_id
    response_cache: dashmap::DashMap<String, (Instant, Arc<NetworkMessage>)>,
    response_cache_ttl: Duration,

    // background tasks
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,

    running: AtomicBool,
}

impl QuicTransport {
    fn generate_nonce() -> u64 {
        rand::random::<u64>()
    }

    async fn get_or_create_connect_mutex(&self, peer_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.peer_connect_mutexes
            .entry(peer_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    // Deprecated: nonce-based winner decision. Left for reference.
    fn _decide_connection_winner_legacy(
        &self,
        existing: (&str, u64, &str, u64),
        candidate: (&str, u64, &str, u64),
    ) -> bool {
        fn canonical_key<'a>(
            a_id: &'a str,
            a_nonce: u64,
            b_id: &'a str,
            b_nonce: u64,
        ) -> (std::cmp::Ordering, &'a str, u64, &'a str, u64) {
            if a_id <= b_id {
                (std::cmp::Ordering::Less, a_id, a_nonce, b_id, b_nonce)
            } else {
                (std::cmp::Ordering::Greater, b_id, b_nonce, a_id, a_nonce)
            }
        }
        let (_e_ord, e_low_id, e_low_nonce, e_high_id, e_high_nonce) =
            canonical_key(existing.0, existing.1, existing.2, existing.3);
        let (_c_ord, c_low_id, c_low_nonce, c_high_id, c_high_nonce) =
            canonical_key(candidate.0, candidate.1, candidate.2, candidate.3);
        (c_low_id, c_low_nonce, c_high_id, c_high_nonce)
            < (e_low_id, e_low_nonce, e_high_id, e_high_nonce)
    }

    async fn replace_or_keep_connection(
        &self,
        peer_node_id: &str,
        new_conn: Arc<quinn::Connection>,
        initiator_peer_id: String,
        initiator_nonce: u64,
        responder_peer_id: String,
        responder_nonce: u64,
    ) -> bool {
        let new_id = new_conn.stable_id();
        log_debug!(self.logger, "[dup] evaluate peer={peer_node_id} new_id={new_id} init=({initiator_peer_id},{initiator_nonce}) resp=({responder_peer_id},{responder_nonce})");
        // Cancel any pending outbound dial to this peer and reset backoff on successful inbound
        {
            if let Some((_, n)) = self.state.dial_cancel.remove(peer_node_id) {
                n.notify_waiters();
            }
        }
        {
            self.state.dial_backoff.remove(peer_node_id);
        }
        let existing_opt = self
            .state
            .peers
            .get(peer_node_id)
            .map(|entry| entry.value().clone());
        if let Some(existing) = existing_opt {
            log_debug!(
                self.logger,
                "[dup] existing for peer={peer_node_id} existing_id={} init=({},{}) resp=({},{})",
                existing.connection_id,
                existing.initiator_peer_id,
                existing.initiator_nonce,
                existing.responder_peer_id,
                existing.responder_nonce
            );
            // If existing entry is a placeholder (no dup-metadata), always replace with the real connection
            if existing.initiator_nonce == 0 && existing.responder_nonce == 0 {
                log_debug!(self.logger, "[dup] Replacing placeholder connection for peer {peer_node_id} with established connection");
                // If the placeholder refers to the same underlying connection, do NOT close it.
                let existing_id = existing.connection_id;
                let new_id = new_conn.stable_id();
                let new_state = PeerState::new(
                    new_conn,
                    existing.node_info_version,
                    initiator_peer_id,
                    initiator_nonce,
                    responder_peer_id,
                    responder_nonce,
                );
                self.state.peers.insert(peer_node_id.to_string(), new_state);
                // Update mapping for the connection id
                self.state
                    .connection_id_to_peer_id
                    .insert(new_id, peer_node_id.to_string());
                // Activate the winner
                if let Some(state) = self.state.peers.get(peer_node_id) {
                    let _ = state.value().activation_tx.send(true);
                }
                // If the new connection differs from the placeholder's, close the old one
                if new_id != existing_id {
                    existing
                        .connection
                        .close(0u32.into(), b"duplicate-replaced");
                }
                return true;
            }
            // Deterministic, nonce-free tie-breaker based on peer IDs and local direction.
            // Rule: Let L = local_node_id(), R = peer_node_id. If L < R, keep direction=Initiator (outbound) locally.
            // Otherwise, keep direction=Responder (inbound) locally. This yields a single winner across both peers.
            let local_node_id = self.local_node_id.clone();
            let desired_local_role = if local_node_id.as_str() < peer_node_id {
                ConnectionRole::Initiator
            } else {
                ConnectionRole::Responder
            };

            let existing_local_role = if existing.initiator_peer_id == local_node_id {
                ConnectionRole::Initiator
            } else {
                ConnectionRole::Responder
            };
            let candidate_local_role = if initiator_peer_id == local_node_id {
                ConnectionRole::Initiator
            } else {
                ConnectionRole::Responder
            };

            let candidate_matches = candidate_local_role == desired_local_role;
            let existing_matches = existing_local_role == desired_local_role;

            let pick_candidate = match (existing_matches, candidate_matches) {
                (false, true) => true,
                (true, false) => false,
                (true, true) => {
                    // Same desired direction; prefer lower stable_id to avoid flapping locally
                    new_conn.stable_id() < existing.connection_id
                }
                (false, false) => {
                    // Neither matches (shouldn't happen); prefer existing for stability
                    false
                }
            };

            if pick_candidate {
                log_debug!(self.logger, "[dup] Candidate wins (desired={desired_local_role:?}, existing={existing_local_role:?}, candidate={candidate_local_role:?}) for peer {peer_node_id}");
                let new_state = PeerState::new(
                    new_conn,
                    existing.node_info_version,
                    initiator_peer_id,
                    initiator_nonce,
                    responder_peer_id,
                    responder_nonce,
                );
                let conn_id = new_state.connection_id;
                self.state.peers.insert(peer_node_id.to_string(), new_state);
                self.state
                    .connection_id_to_peer_id
                    .insert(conn_id, peer_node_id.to_string());
                if existing.connection_id != conn_id {
                    existing
                        .connection
                        .close(0u32.into(), b"duplicate-replaced");
                }
                if let Some(state) = self.state.peers.get(peer_node_id) {
                    let _ = state.value().activation_tx.send(true);
                }
                true
            } else {
                log_debug!(self.logger, "[dup] Existing kept (desired={desired_local_role:?}, existing={existing_local_role:?}, candidate={candidate_local_role:?}) for peer {peer_node_id}; evaluating close on new");
                // If the \"new\" connection refers to the same underlying connection as the existing one,
                // do NOT close it. This situation happens for update handshakes sent over an already-active conn.
                let existing_id = existing.connection_id;
                let new_id = new_conn.stable_id();
                if new_id != existing_id {
                    new_conn.close(0u32.into(), b"duplicate-loser");
                } else {
                    log_debug!(self.logger, "[dup] Skipping close for duplicate-loser: same connection id={new_id} for peer {peer_node_id}");
                }
                false
            }
        } else {
            let new_state = PeerState::new(
                new_conn,
                0,
                initiator_peer_id,
                initiator_nonce,
                responder_peer_id,
                responder_nonce,
            );
            let conn_id = new_state.connection_id;
            self.state.peers.insert(peer_node_id.to_string(), new_state);
            self.state
                .connection_id_to_peer_id
                .insert(conn_id, peer_node_id.to_string());
            if let Some(state) = self.state.peers.get(peer_node_id) {
                let _ = state.value().activation_tx.send(true);
            }
            true
        }
    }
    pub fn new(
        mut options: QuicTransportOptions,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Extract required parameters from options
        let local_node_public_key = options.local_node_public_key.take().ok_or_else(|| {
            NetworkError::ConfigurationError("local_node_public_key is required".into())
        })?;
        let local_node_id = compact_id(&local_node_public_key);
        let bind_addr = options
            .bind_addr
            .take()
            .ok_or_else(|| NetworkError::ConfigurationError("bind_addr is required".into()))?;
        let logger = (options
            .logger
            .take()
            .ok_or_else(|| NetworkError::ConfigurationError("logger is required".into()))?)
        .with_component(runar_common::Component::Transporter);
        // Prefer EnvelopeCrypto provided by the key manager. Fall back to explicit keystore only for
        // legacy/tests that don't use a key manager.
        let keystore: Arc<dyn runar_serializer::traits::EnvelopeCrypto> =
            if let Some(km) = options.key_manager().cloned() {
                // NodeKeyManager implements EnvelopeCrypto
                km as Arc<dyn runar_serializer::traits::EnvelopeCrypto>
            } else {
                options.keystore.take().ok_or_else(|| {
                    NetworkError::ConfigurationError("keystore or key_manager is required".into())
                })?
            };
        let label_resolver_config = options.label_resolver_config.take().ok_or_else(|| {
            NetworkError::ConfigurationError("label_resolver_config is required".into())
        })?;

        if rustls::crypto::CryptoProvider::get_default().is_none() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("Failed to install default crypto provider");
        }

        // Basic configuration validation
        if options.max_message_size.unwrap_or(0) == 0 {
            return Err(
                NetworkError::ConfigurationError("max_message_size must be > 0".into()).into(),
            );
        }
        if options.handshake_response_timeout == Duration::from_millis(0) {
            return Err(NetworkError::ConfigurationError(
                "handshake_response_timeout must be > 0".into(),
            )
            .into());
        }
        if options.open_stream_timeout == Duration::from_millis(0) {
            return Err(
                NetworkError::ConfigurationError("open_stream_timeout must be > 0".into()).into(),
            );
        }
        if options.key_manager.is_none()
            && (options.certificates.is_none() || options.private_key.is_none())
        {
            return Err(NetworkError::ConfigurationError(
                "either key_manager or (certificates and private_key) must be provided".into(),
            )
            .into());
        }

        let peer_connected_callback = options.peer_connected_callback.take();
        let peer_disconnected_callback = options.peer_disconnected_callback.take();
        let request_callback = options.request_callback.take().ok_or_else(|| {
            NetworkError::ConfigurationError("request_callback is required".into())
        })?;
        let event_callback = options
            .event_callback
            .take()
            .ok_or_else(|| NetworkError::ConfigurationError("event_callback is required".into()))?;

        let get_local_node_info = options.get_local_node_info.take().ok_or_else(|| {
            NetworkError::ConfigurationError("get_local_node_info is required".into())
        })?;

        let cache_ttl = options.response_cache_ttl();

        let max_request_retries = options.max_request_retries.unwrap_or(5);
        Ok(Self {
            bind_addr,
            options,
            endpoint: Arc::new(RwLock::new(None)),
            logger: Arc::new(logger),
            peer_connected_callback,
            peer_disconnected_callback,
            request_callback,
            event_callback,
            peer_connect_mutexes: Arc::new(DashMap::new()),
            get_local_node_info,
            local_node_id,
            keystore,
            label_resolver_config,
            state: Self::shared_state(),
            tasks: Mutex::new(Vec::new()),
            running: AtomicBool::new(false),
            response_cache: dashmap::DashMap::new(),
            response_cache_ttl: cache_ttl,
            max_request_retries,
        })
    }

    fn build_quinn_configs(&self) -> Result<(ServerConfig, ClientConfig), NetworkError> {
        // Resolve certificates and private key either from key manager or explicit options
        let (certs, key): (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) =
            if let Some(km) = self.options.key_manager() {
                let cfg = km.get_quic_certificate_config().map_err(|e| {
                    NetworkError::ConfigurationError(format!(
                        "Failed to get QUIC certificate config from key manager: {e}"
                    ))
                })?;
                (cfg.certificate_chain, cfg.private_key)
            } else {
                let certs = self
                    .options
                    .certificates()
                    .ok_or(NetworkError::ConfigurationError("no certs".into()))?
                    .clone();
                let key = self
                    .options
                    .private_key()
                    .ok_or(NetworkError::ConfigurationError("no key".into()))?
                    .clone_key();
                (certs, key)
            };

        let mut transport_config = quinn::TransportConfig::default();

        // Apply our connection idle timeout (convert Duration to milliseconds for VarInt)
        let idle_timeout_ms = self.options.connection_idle_timeout.as_millis() as u64;
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(
            quinn::VarInt::from_u64(idle_timeout_ms).unwrap(),
        )));

        // Apply our keep-alive interval
        transport_config.keep_alive_interval(Some(self.options.keep_alive_interval));

        log_info!(
            self.logger,
            "Configured transport timeouts - Idle: {}ms, Keep-alive: {}ms",
            idle_timeout_ms,
            self.options.keep_alive_interval.as_millis()
        );

        let transport_config = Arc::new(transport_config);

        // Create server configuration using Quinn 0.11.x API with custom transport config
        let mut server_config = ServerConfig::with_single_cert(certs.clone(), key.clone_key())
            .map_err(|e| {
                NetworkError::ConfigurationError(format!("Failed to create server config: {e}"))
            })?;
        server_config.transport_config(transport_config.clone());

        // Build a strict rustls client config with provided root certificates (or CA from key manager).
        // Server name verification is handled by rustls using SNI; certificates must match peer_id DNS name.
        let mut root_store = rustls::RootCertStore::empty();
        if let Some(roots) = self.options.root_certificates() {
            for der in roots.iter() {
                root_store.add(der.clone()).map_err(|e| {
                    NetworkError::ConfigurationError(format!("Failed to add root certificate: {e}"))
                })?;
            }
        } else if let Some(km) = self.options.key_manager() {
            // Use CA from key manager certificate chain (append all for simplicity)
            let cfg = km.get_quic_certificate_config().map_err(|e| {
                NetworkError::ConfigurationError(format!("Failed to get certs for roots: {e}"))
            })?;
            for der in cfg.certificate_chain.iter() {
                root_store.add(der.clone()).map_err(|e| {
                    NetworkError::ConfigurationError(format!("Failed to add key-manager root: {e}"))
                })?;
            }
        } else {
            return Err(NetworkError::ConfigurationError(
                "no root certificates configured".into(),
            ));
        }
        let rustls_client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
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

        log_info!(
            self.logger,
            "Successfully created Quinn server and client configurations with custom timeouts"
        );

        Ok((server_config, client_config))
    }

    fn spawn_accept_loop(self: Arc<Self>, _endpoint: Endpoint) -> tokio::task::JoinHandle<()> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            loop {
                // If transport is no longer running, break the loop
                if !self_clone.running.load(Ordering::SeqCst) {
                    break;
                }
                // Snapshot endpoint without holding the lock across await points
                let endpoint_opt = { self_clone.endpoint.read().await.clone() };
                let Some(endpoint) = endpoint_opt else {
                    break;
                };
                // Await on accept without holding the RwLock guard
                if let Some(connecting) = endpoint.accept().await {
                    match connecting.await {
                        Ok(conn) => {
                            let task = self_clone
                                .clone()
                                .spawn_connection_tasks("inbound".to_string(), Arc::new(conn));
                            self_clone.tasks.lock().await.push(task);
                        }
                        Err(e) => log_error!(self_clone.logger, "accept failed: {e}"),
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
                res = self_clone.uni_accept_loop(conn.clone(), needs_to_correlate_peer_id) => if let Err(e) = res { log_error!(self_clone.logger, "uni loop failed: {e}") },
                res = self_clone.bi_accept_loop(conn.clone(), needs_to_correlate_peer_id) => if let Err(e) = res { log_error!(self_clone.logger, "bi loop failed: {e}") },
            }
            let resolved_peer_id = if needs_to_correlate_peer_id {
                let connection_id = conn.stable_id();
                match self_clone
                    .state
                    .connection_id_to_peer_id
                    .get(&connection_id)
                {
                    Some(entry) => entry.value().clone(),
                    None => {
                        log_error!(self_clone.logger, "Connection id {connection_id} not found in connection id to peer id map");
                        return;
                    }
                }
            } else {
                peer_id
            };
            // Remove from peers ONLY if this task belonged to the current active connection.
            let connection_id = conn.stable_id();
            let mut removed = false;
            // Gracefully handle brief handover races by re-checking after a short delay
            let should_remove = {
                matches!(self_clone.state.peers.get(&resolved_peer_id), Some(entry) if entry.value().connection_id == connection_id)
            };
            if should_remove {
                tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                if let Some((_, current)) = self_clone.state.peers.remove(&resolved_peer_id) {
                    let current_conn_id = current.connection_id;
                    if current_conn_id == connection_id {
                        removed = true;
                    } else {
                        // Re-insert if it wasn't the current connection
                        self_clone
                            .state
                            .peers
                            .insert(resolved_peer_id.clone(), current);
                        log_debug!(self_clone.logger, "(post-grace) connection tasks for old conn_id={connection_id} exited; current conn_id={current_conn_id} remains for peer {resolved_peer_id}");
                    }
                }
            } else {
                log_debug!(self_clone.logger, "connection tasks for old conn_id={connection_id} exited; current active differs for peer {resolved_peer_id}");
            }
            if removed {
                // Reset backoff so that future dials are allowed promptly after a clean disconnect
                self_clone.state.dial_backoff.remove(&resolved_peer_id);
                // Cancel any pending dial waits
                if let Some((_, n)) = self_clone.state.dial_cancel.remove(&resolved_peer_id) {
                    n.notify_waiters();
                }
                log_debug!(
                    self_clone.logger,
                    "connection tasks exited for peer_node_id: {resolved_peer_id}"
                );

                // Grace period: avoid flapping during duplicate-connection resolution.
                // Only emit on_down if the peer remains absent after a short delay.
                if let Some(disconnected_callback) = &self_clone.peer_disconnected_callback {
                    let disconnected_callback = disconnected_callback.clone();
                    let self_check = self_clone.clone();
                    let peer_for_check = resolved_peer_id.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                        let still_disconnected =
                            !self_check.state.peers.contains_key(&peer_for_check);
                        if still_disconnected {
                            (disconnected_callback)(peer_for_check.clone()).await;
                        } else {
                            log_debug!(self_check.logger, "disconnect suppressed for {peer_for_check} due to new active connection");
                        }
                    });
                }
            }
        })
    }

    async fn uni_accept_loop(
        &self,
        conn: Arc<quinn::Connection>,
        needs_to_correlate_peer_id: bool,
    ) -> Result<(), NetworkError> {
        loop {
            let mut recv = conn
                .accept_uni()
                .await
                .map_err(|e| NetworkError::TransportError(e.to_string()))?;
            let msg = self.read_message(&mut recv).await?;

            if msg.message_type == super::MESSAGE_TYPE_HANDSHAKE {
                self.handle_handshake(conn.clone(), None, msg, needs_to_correlate_peer_id)
                    .await?;
                continue;
            }

            if msg.message_type == super::MESSAGE_TYPE_EVENT {
                self.handle_event(msg).await?;
                continue;
            }

            log_error!(self.logger, "[uni_accept_loop] Received message of unknown type: {type} correlation_id: {correlation_id}", type=msg.message_type, correlation_id=msg.payload.correlation_id);
        }
    }

    async fn write_message<S: tokio::io::AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        msg: &NetworkMessage,
    ) -> Result<(), NetworkError> {
        use tokio::io::AsyncWriteExt;

        log_debug!(
            self.logger,
            "[write_message] Encoding message: type={}, source={}, dest={}",
            msg.message_type,
            msg.source_node_id,
            msg.destination_node_id
        );

        let framed = encode_message(msg)?;
        log_debug!(
            self.logger,
            "[write_message] Encoded message size: {} bytes",
            framed.len()
        );

        match stream.write_all(&framed).await {
            Ok(_) => {
                log_debug!(
                    self.logger,
                    "[write_message] Successfully wrote message to stream"
                );
                Ok(())
            }
            Err(e) => {
                log_error!(self.logger, "[write_message] Failed to write message: {e}");
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
        // log_debug!(self.logger, "[read_message] Reading message from stream");

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
        let max = self.options.max_message_size().unwrap_or(1024 * 1024);
        if len > max {
            return Err(NetworkError::MessageError(format!(
                "message too large: {len} > {max}"
            )));
        }

        let mut msg_buf = vec![0u8; len];

        // log_debug!(
        //     self.logger,
        //     "[read_message] Reading message payload of length {len}"
        // );

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
                log_debug!(self.logger, "[read_message] Decoded message: type={type}, source={source}, dest={dest}", 
                     type=msg.message_type, source=msg.source_node_id, dest=msg.destination_node_id);
                Ok(msg)
            }
            Err(e) => Err(NetworkError::MessageError(format!(
                "failed to decode cbor: {e}"
            ))),
        }
    }

    async fn handle_event(&self, msg: NetworkMessage) -> Result<(), NetworkError> {
        log_debug!(
            self.logger,
            "[handle_event] Processing event message correlation id: {correlation_id}",
            correlation_id = msg.payload.correlation_id
        );

        let correlation_id = msg.payload.correlation_id.clone();
        (self.event_callback)(msg).await.map_err(|e| {
            log_error!(
                self.logger,
                "failed to handle event correlation id: {correlation_id } error: {e}"
            );
            NetworkError::TransportError(format!("failed to handle event: {e}"))
        })?;

        Ok(())
    }

    async fn handle_request(&self, msg: NetworkMessage) -> Result<NetworkMessage, NetworkError> {
        log_debug!(
            self.logger,
            "[handle_request] Processing request message correlation id: {correlation_id}",
            correlation_id = msg.payload.correlation_id
        );
        let correlation_id = msg.payload.correlation_id.clone();
        let response = (self.request_callback)(msg).await.map_err(|e| {
            log_error!(
                self.logger,
                "failed to handle request correlation id: {correlation_id } error: {e}"
            );
            NetworkError::TransportError(format!("failed to handle request: {e}"))
        })?;

        Ok(response)
    }

    async fn handle_handshake(
        &self,
        conn: Arc<quinn::Connection>,
        send: Option<&mut quinn::SendStream>,
        msg: NetworkMessage,
        needs_to_correlate_peer_id: bool,
    ) -> Result<(), NetworkError> {
        self.logger
            .debug("[handle_handshake] Processing handshake message");

        let should_send_response = send.is_some();
        let local_node_id = self.local_node_id.clone();
        let payload = &msg.payload;
        let hs: HandshakeData = serde_cbor::from_slice(&payload.payload_bytes)
            .map_err(|e| NetworkError::MessageError(format!("failed to decode cbor: {e}")))?;

        let peer_node_id = msg.source_node_id.clone();
        let node_info = hs.node_info;
        let node_info_version = node_info.version;
        let remote_nonce = hs.nonce;
        let remote_role = hs.role;
        let local_role = ConnectionRole::Responder;
        let local_nonce = Self::generate_nonce();
        let response_nonce = local_nonce;

        // Update (nonce==0) handshakes sent over a unidirectional stream should NOT trigger
        // duplicate-resolution. They are metadata updates on an already-established connection.
        if remote_nonce == 0 && send.is_none() {
            log_debug!(
                self.logger,
                "[handle_handshake] Received update handshake (nonce=0) over uni; skipping duplicate-resolution for peer {peer_node_id}"
            );
            if let Some(connected_callback) = &self.peer_connected_callback {
                (connected_callback)(peer_node_id.clone(), node_info.clone()).await;
            }
            if needs_to_correlate_peer_id {
                self.state
                    .connection_id_to_peer_id
                    .insert(conn.stable_id(), peer_node_id);
            }
            return Ok(());
        }

        log_debug!(self.logger, "[handle_handshake] from {peer_node_id} ver={node_info_version} role={remote_role:?} nonce={remote_nonce}");
        let candidate_initiator = match (remote_role, local_role) {
            (ConnectionRole::Initiator, ConnectionRole::Responder) => (
                peer_node_id.clone(),
                remote_nonce,
                local_node_id,
                local_nonce,
            ),
            (ConnectionRole::Responder, ConnectionRole::Responder) => (
                peer_node_id.clone(),
                remote_nonce,
                local_node_id,
                local_nonce,
            ),
            (ConnectionRole::Initiator, ConnectionRole::Initiator) => (
                peer_node_id.clone(),
                remote_nonce,
                local_node_id,
                local_nonce,
            ),
            (ConnectionRole::Responder, ConnectionRole::Initiator) => (
                local_node_id,
                local_nonce,
                peer_node_id.clone(),
                remote_nonce,
            ),
        };
        log_debug!(
            self.logger,
            "[handle_handshake] candidate dup key init=({},{}) resp=({},{})",
            candidate_initiator.0,
            candidate_initiator.1,
            candidate_initiator.2,
            candidate_initiator.3
        );
        let kept = self
            .replace_or_keep_connection(
                &peer_node_id,
                conn.clone(),
                candidate_initiator.0,
                candidate_initiator.1,
                candidate_initiator.2,
                candidate_initiator.3,
            )
            .await;
        if !kept {
            // New inbound lost; skip further processing for this connection
            log_debug!(self.logger, "[handle_handshake] New inbound lost; skipping further processing for this connection");
            return Ok(());
        }
        // Mark active after surviving dup-resolution
        if let Some(state) = self.state.peers.get(&peer_node_id) {
            let _ = state.value().activation_tx.send(true);
        }

        if let Some(connected_callback) = &self.peer_connected_callback {
            (connected_callback)(peer_node_id.clone(), node_info).await;
        }
        if needs_to_correlate_peer_id {
            self.state
                .connection_id_to_peer_id
                .insert(conn.stable_id(), peer_node_id);
        }

        // Send handshake response only if this connection is the surviving winner
        if should_send_response {
            self.logger
                .debug("[handle_handshake] Sending handshake response");
            let local_node_info = (self.get_local_node_info)()
                .await
                .map_err(|e| NetworkError::TransportError(e.to_string()))?;
            let source_node_id = self.local_node_id.clone();
            let response_hs = HandshakeData {
                node_info: local_node_info,
                nonce: response_nonce, // include responder nonce (0 for legacy), so both sides can compute tie-break keys
                role: ConnectionRole::Responder,
            };
            let response_msg = NetworkMessage {
                source_node_id,
                destination_node_id: msg.source_node_id,
                message_type: super::MESSAGE_TYPE_HANDSHAKE,
                payload: super::NetworkMessagePayloadItem {
                    path: "handshake".to_string(),
                    payload_bytes: serde_cbor::to_vec(&response_hs).unwrap_or_default(),
                    correlation_id: msg.payload.correlation_id,
                    profile_public_keys: msg.payload.profile_public_keys.clone(),
                    network_public_key: None, // Handshake doesn't need network context
                },
            };

            let send = send.unwrap();

            // Let upper layer process our handshake response (capabilities) as well
            // so both sides can register remote services. First, send it to peer:
            self.write_message(send, &response_msg).await?;
            send.finish()
                .map_err(|e| NetworkError::TransportError(e.to_string()))?;
            self.logger
                .debug("[handle_handshake] Handshake response sent");
        }
        Ok(())
    }

    async fn bi_accept_loop(
        &self,
        conn: Arc<quinn::Connection>,
        needs_to_correlate_peer_id: bool,
    ) -> Result<(), NetworkError> {
        loop {
            // Accept bidirectional streams; do not fail the whole loop on timeouts
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(v) => v,
                Err(e) => {
                    return Err(NetworkError::TransportError(e.to_string()));
                }
            };
            let msg = self.read_message(&mut recv).await?;

            log_debug!(self.logger, "[bi_accept_loop] Received message: type={type}, source={source}, dest={dest}",
            type=msg.message_type,
            source=msg.source_node_id,
            dest=msg.destination_node_id
            );

            if msg.message_type == super::MESSAGE_TYPE_HANDSHAKE {
                self.handle_handshake(
                    conn.clone(),
                    Some(&mut send),
                    msg,
                    needs_to_correlate_peer_id,
                )
                .await?;
                continue;
            }

            // Extract fields needed for error handling before moving msg
            // let source_node_id = msg.source_node_id.clone();
            // let payload = msg.payload;

            // For REQUEST messages, attempt idempotent handling using correlation_id
            if msg.message_type == super::MESSAGE_TYPE_REQUEST {
                //first check if the request response is cached -  for idempotency when request is retried
                //let correlation_id = msg.payload.correlation_id;
                if let Some(entry) = self.response_cache.get(&msg.payload.correlation_id) {
                    let (ts, cached) = entry.value();
                    let now = Instant::now();
                    if now.saturating_duration_since(*ts) <= self.response_cache_ttl {
                        log_debug!(self.logger, "[bi_accept_loop] Found cached response for correlation id: {correlation_id}", correlation_id=&msg.payload.correlation_id);
                        self.write_message(&mut send, cached).await?;
                        send.finish()
                            .map_err(|e| {
                                log_error!(self.logger, "failed to write cached response message correlation id: {correlation_id} error: {e}", correlation_id=&msg.payload.correlation_id);
                                NetworkError::TransportError(e.to_string())
                            })?;
                        continue;
                    }
                }

                //if not cached, handle the request and send the response
                let correlation_id = msg.payload.correlation_id.clone();
                log_debug!(
                    self.logger,
                    "[bi_accept_loop] Handling request correlation_id: {correlation_id}",
                    correlation_id = correlation_id
                );
                let response = self.handle_request(msg.clone()).await?;
                // response is already NetworkMessage, just update destination
                let response_msg = NetworkMessage {
                    source_node_id: self.local_node_id.clone(),
                    destination_node_id: msg.source_node_id,
                    message_type: super::MESSAGE_TYPE_RESPONSE,
                    payload: response.payload, // response.payload is NetworkMessagePayloadItem
                };

                log_debug!(self.logger, "[bi_accept_loop] Built response message correlation_id: {correlation_id} response_payload_bytes: {response_len}",
                    correlation_id=correlation_id,
                    response_len=response_msg.payload.payload_bytes.len()
                );
                let now = Instant::now();
                let response_msg_arc = Arc::new(response_msg);
                self.response_cache
                    .insert(correlation_id.clone(), (now, response_msg_arc.clone()));

                log_debug!(self.logger, "[bi_accept_loop] Writing response message correlation_id: {correlation_id} response_payload_bytes: {response_len}",
                    correlation_id=correlation_id,
                    response_len=response_msg_arc.payload.payload_bytes.len()
                );
                self.write_message(&mut send, &response_msg_arc).await?;
                send.finish()
                    .map_err(|e| {
                        log_error!(self.logger, "[bi_accept_loop] failed to write response message correlation id: {correlation_id} error: {e}", correlation_id=response_msg_arc.payload.correlation_id);
                        NetworkError::TransportError(e.to_string())
                    })?;
                continue;
            }

            log_error!(self.logger, "[bi_accept_loop] Received message of unknown type: {type}", type=msg.message_type);
        }
    }

    async fn handshake_outbound(
        &self,
        peer_id: &str,
        conn: &quinn::Connection,
        local_nonce: u64,
    ) -> Result<u64, NetworkError> {
        log_debug!(
            self.logger,
            "[handshake_outbound] Starting handshake with peer: {peer_id}"
        );

        let local_node_info = (self.get_local_node_info)()
            .await
            .map_err(|e| NetworkError::TransportError(e.to_string()))?;
        let local_node_id = self.local_node_id.clone();
        let hs = HandshakeData {
            node_info: local_node_info,
            nonce: local_nonce,
            role: ConnectionRole::Initiator,
        };
        let payload_bytes = serde_cbor::to_vec(&hs).map_err(|e| {
            log_error!(
                self.logger,
                "[handshake_outbound] Failed to serialize HandshakeData: {e}"
            );
            NetworkError::MessageError(e.to_string())
        })?;

        let payload = super::NetworkMessagePayloadItem {
            path: "handshake".to_string(),
            payload_bytes,
            correlation_id: uuid::Uuid::new_v4().to_string(),
            profile_public_keys: vec![],
            network_public_key: None, // Handshake doesn't need network context
        };

        let msg = NetworkMessage {
            source_node_id: local_node_id,
            destination_node_id: peer_id.to_string(),
            message_type: super::MESSAGE_TYPE_HANDSHAKE,
            payload,
        };

        log_debug!(
            self.logger,
            "[handshake_outbound] Opening bi stream for handshake (v2)"
        );
        // Open a fresh bi-directional stream for handshake
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| {
            log_error!(
                self.logger,
                "[handshake_outbound] Failed to open bi stream: {e}"
            );
            NetworkError::TransportError(e.to_string())
        })?;

        log_debug!(
            self.logger,
            "[handshake_outbound] Writing handshake message"
        );
        self.write_message(&mut send, &msg).await?;
        send.finish().map_err(|e| {
            log_error!(
                self.logger,
                "[handshake_outbound] Failed to finish send: {e}"
            );
            NetworkError::TransportError(e.to_string())
        })?;

        log_debug!(
            self.logger,
            "[handshake_outbound] Waiting for handshake response with timeout"
        );
        let reply = tokio::time::timeout(
            self.options.handshake_response_timeout,
            self.read_message(&mut recv),
        )
        .await
        .map_err(|_| NetworkError::TransportError("handshake response timeout".into()))??;

        log_debug!(
            self.logger,
            "[handshake_outbound] Received handshake response, processing..."
        );

        // Parse responder handshake (prefer v2), fall back to v1 NodeInfo
        let hs =
            serde_cbor::from_slice::<HandshakeData>(&reply.payload.payload_bytes).map_err(|e| {
                log_error!(
                    self.logger,
                    "[handshake_outbound] Failed to parse HandshakeData: {e}"
                );
                NetworkError::MessageError(e.to_string())
            })?;
        let responder_nonce = hs.nonce;
        if let Some(connected_callback) = &self.peer_connected_callback {
            (connected_callback)(peer_id.to_string(), hs.node_info).await;
        }

        //send to node to handle handshake response and store peer node info
        // let _ = (self.message_handler)(reply).await;

        Ok(responder_nonce)
    }

    // Helper: wait for an active peer state with limited retries
    async fn wait_for_active_peer(
        &self,
        peer_node_id: &str,
        max_attempts: u8,
    ) -> Result<PeerState, NetworkError> {
        let mut attempt: u8 = 0;
        loop {
            let maybe_peer = self
                .state
                .peers
                .get(peer_node_id)
                .map(|entry| entry.value().clone());
            let peer = match maybe_peer {
                Some(p) => p,
                None => {
                    if attempt < max_attempts {
                        attempt = attempt.saturating_add(1);
                        tokio::time::sleep(Duration::from_millis(80)).await;
                        continue;
                    }
                    return Err(NetworkError::ConnectionError(format!(
                        "not connected to peer {peer_node_id}"
                    )));
                }
            };
            if !*peer.activation_rx.borrow() {
                let mut rx = peer.activation_rx.clone();
                let _ = rx.changed().await;
            }
            return Ok(peer);
        }
    }

    // Helper: open a bi-directional stream to an active peer with limited retries
    async fn open_bi_active(
        &self,
        peer_node_id: &str,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), NetworkError> {
        let mut attempt: u8 = 0;
        let max_attempts: u8 = 3;
        loop {
            let peer = self
                .wait_for_active_peer(peer_node_id, max_attempts)
                .await?;
            match peer.connection.open_bi().await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    if attempt < max_attempts {
                        attempt = attempt.saturating_add(1);
                        tokio::time::sleep(Duration::from_millis(70)).await;
                        continue;
                    }
                    return Err(NetworkError::TransportError(format!("open_bi failed: {e}")));
                }
            }
        }
    }

    // Helper: open a uni-directional stream to an active peer with limited retries
    async fn open_uni_active(&self, peer_node_id: &str) -> Result<quinn::SendStream, NetworkError> {
        let mut attempt: u8 = 0;
        let max_attempts: u8 = 3;
        loop {
            let peer = self
                .wait_for_active_peer(peer_node_id, max_attempts)
                .await?;
            match peer.connection.open_uni().await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    if attempt < max_attempts {
                        attempt = attempt.saturating_add(1);
                        tokio::time::sleep(Duration::from_millis(70)).await;
                        continue;
                    }
                    return Err(NetworkError::TransportError(format!(
                        "open_uni failed: {e}"
                    )));
                }
            }
        }
    }

    #[allow(dead_code)]
    async fn request_inner(
        &self,
        conn: &quinn::Connection,
        msg: &NetworkMessage,
    ) -> Result<NetworkMessage, NetworkError> {
        self.logger
            .debug("[request_inner] Opening bidirectional stream");

        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| {
            log_error!(
                self.logger,
                "[request_inner] Failed to open bidirectional stream: {e}"
            );
            NetworkError::TransportError(e.to_string())
        })?;

        log_debug!(
            self.logger,
            "[request_inner] Bidirectional stream opened successfully"
        );

        log_debug!(self.logger, "[request_inner] Writing message to stream");
        self.write_message(&mut send, msg).await?;

        log_debug!(self.logger, "[request_inner] Finishing send stream");
        send.finish().map_err(|e| {
            log_error!(
                self.logger,
                "[request_inner] Failed to finish send stream: {e}"
            );
            NetworkError::TransportError(e.to_string())
        })?;

        log_debug!(self.logger, "[request_inner] Reading response message");
        // Read the response message first
        let response_msg = self.read_message(&mut recv).await?;

        log_debug!(
            self.logger,
            "[request_inner] Response message read successfully, draining remaining data"
        );

        // Then spawn a task to drain any remaining data from the stream
        let drain_task =
            tokio::spawn(async move { while recv.read(&mut [0u8; 0]).await.is_ok() {} });

        // Abort the drain task since we've already read what we need
        drain_task.abort();
        let _ = drain_task.await;

        self.logger
            .debug("[request_inner] Request completed successfully");
        Ok(response_msg)
    }

    fn shared_state() -> SharedState {
        SharedState {
            peers: Arc::new(DashMap::new()),
            connection_id_to_peer_id: Arc::new(DashMap::new()),
            dial_backoff: Arc::new(DashMap::new()),
            dial_cancel: Arc::new(DashMap::new()),
        }
    }
}

#[async_trait]
impl NetworkTransport for QuicTransport {
    async fn start(self: Arc<Self>) -> Result<(), NetworkError> {
        log_info!(self.logger, "Starting QUIC transport");

        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        // Create Quinn server & client configs
        let (server_cfg, client_cfg) = self.build_quinn_configs()?;

        // Bind endpoint with retry to tolerate fast restarts (port linger)
        let mut attempt: u8 = 0;
        let endpoint: Endpoint = loop {
            match Endpoint::server(server_cfg.clone(), self.bind_addr) {
                Ok(mut ep) => {
                    ep.set_default_client_config(client_cfg.clone());
                    break ep;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    // Retry a few times on EADDRINUSE during fast restarts
                    if err_str.contains("Address already in use") && attempt < 40 {
                        log_warn!(
                            self.logger,
                            "[start] Bind failed with EADDRINUSE, retrying attempt {}...",
                            attempt + 1
                        );
                        attempt += 1;
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                    return Err(NetworkError::TransportError(format!(
                        "failed to create endpoint: {err_str}"
                    )));
                }
            }
        };

        // store endpoint
        {
            let mut guard = self.endpoint.write().await;
            *guard = Some(endpoint.clone());
        }

        // spawn accept loops
        let accept_task: tokio::task::JoinHandle<()> = self.clone().spawn_accept_loop(endpoint);
        self.tasks.lock().await.push(accept_task);

        // spawn periodic cache prune task
        let prune_self = self.clone();
        let ttl = self.response_cache_ttl;
        let prune_task = tokio::spawn(async move {
            let interval = Duration::from_secs(1);
            loop {
                if !prune_self.running.load(Ordering::SeqCst) {
                    break;
                }
                let now = Instant::now();
                prune_self
                    .response_cache
                    .retain(|_, (ts, _)| now.saturating_duration_since(*ts) <= ttl);
                tokio::time::sleep(interval).await;
            }
        });
        self.tasks.lock().await.push(prune_task);

        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn stop(&self) -> Result<(), NetworkError> {
        log_info!(self.logger, "Stopping QUIC transport",);

        {
            if !self.running.load(Ordering::SeqCst) {
                log_debug!(self.logger, "QUIC transport is not running - skipping stop");
                return Ok(());
            }
            self.running.store(false, Ordering::SeqCst);
        }

        log_debug!(self.logger, "Closing endpoint");
        if let Some(ep) = self.endpoint.write().await.take() {
            ep.close(0u32.into(), b"shutdown");
        }

        // Snapshot and clear peers under a write lock to avoid deadlocks
        log_debug!(self.logger, "Closing all connections");
        let connections_to_close: Vec<quinn::Connection> = {
            let conns = self
                .state
                .peers
                .iter()
                .map(|entry| entry.value().connection.as_ref().clone())
                .collect::<Vec<_>>();
            self.state.peers.clear();
            conns
        };
        for conn in connections_to_close {
            conn.close(0u32.into(), b"shutdown");
        }

        // Clear in-memory maps
        self.state.connection_id_to_peer_id.clear();
        self.state.dial_backoff.clear();
        self.state.dial_cancel.clear();

        // Abort background tasks without awaiting them to prevent potential deadlocks
        log_debug!(self.logger, "canceling all remaining tasks");
        let mut tasks = self.tasks.lock().await;
        while let Some(t) = tasks.pop() {
            t.abort();
        }
        Ok(())
    }

    async fn disconnect(&self, node_id: &str) -> Result<(), NetworkError> {
        // Remove peer from the peers map
        if let Some((_, peer_state)) = self.state.peers.remove(node_id) {
            // Close the connection gracefully
            peer_state.connection.close(0u32.into(), b"disconnect");
            log_info!(self.logger, "Disconnected from peer: {node_id}");
        } else {
            log_warn!(
                self.logger,
                "Attempted to disconnect from unknown peer: {node_id}"
            );
        }
        Ok(())
    }

    async fn is_connected(&self, peer_node_id: &str) -> bool {
        self.state.peers.contains_key(peer_node_id)
    }

    async fn request(
        &self,
        topic_path: &str,
        correlation_id: &str,
        payload: Vec<u8>,
        peer_node_id: &str,
        network_public_key: Option<Vec<u8>>,
        profile_public_keys: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>, NetworkError> {
        log_debug!(
            self.logger,
            "[request] to peer: {peer_node_id} topic: {topic_path} correlation_id: {correlation_id} payload_bytes: {payload_len}",
            payload_len = payload.len()
        );

        let local_node_id = self.local_node_id.clone();

        // build message
        let msg = NetworkMessage {
            source_node_id: local_node_id,
            destination_node_id: peer_node_id.to_string(),
            message_type: super::MESSAGE_TYPE_REQUEST,
            payload: super::NetworkMessagePayloadItem {
                path: topic_path.to_string(),
                payload_bytes: payload.clone(),
                correlation_id: correlation_id.to_string(),
                profile_public_keys: profile_public_keys.clone(),
                network_public_key: network_public_key.clone(),
            },
        };

        log_debug!(
            self.logger,
            "[request] Built NetworkMessage - source: {source} dest: {dest} type: {msg_type} path: {path} payload_bytes: {payload_len} correlation_id: {corr_id}",
            source = msg.source_node_id,
            dest = msg.destination_node_id,
            msg_type = msg.message_type,
            path = msg.payload.path,
            payload_len = msg.payload.payload_bytes.len(),
            corr_id = msg.payload.correlation_id
        );

        let mut retry_count = 0;
        let response_msg = loop {
            log_debug!(
                self.logger,
                "[request] Opening bidirectional stream correlation_id: {correlation_id}",
                correlation_id = &msg.payload.correlation_id
            );
            let (mut send, mut recv) = tokio::time::timeout(
                self.options.open_stream_timeout,
                self.open_bi_active(peer_node_id),
            )
            .await
            .map_err(|_| NetworkError::TransportError("open_bi timeout".into()))??;

            if let Err(e) = self.write_message(&mut send, &msg).await {
                log_error!(
                    self.logger,
                    "[request] Failed to write request correlation_id: {correlation_id} error: {e}",
                    correlation_id = &msg.payload.correlation_id
                );
                break Err(e);
            }

            log_debug!(
                self.logger,
                "[request] Finishing send stream correlation_id: {correlation_id}",
                correlation_id = &msg.payload.correlation_id
            );
            if let Err(e) = send.finish() {
                log_error!(
                    self.logger,
                    "[request] Failed to finish send stream correlation_id: {correlation_id} error: {e} - retry_count: {retry_count}",
                    correlation_id=&msg.payload.correlation_id
                );
                retry_count += 1;
                if retry_count > self.max_request_retries {
                    log_error!(self.logger, "[request] Failed to finish send stream correlation_id: {correlation_id} error: {e} - retry_count: {retry_count} - giving up", correlation_id=&msg.payload.correlation_id);
                    break Err(NetworkError::TransportError(format!("failed to finish send stream correlation_id: {correlation_id} error: {e} - retry_count: {retry_count} - giving up", correlation_id=&msg.payload.correlation_id)));
                }
                tokio::time::sleep(Duration::from_millis(70)).await;
                continue;
            }

            retry_count = 0;
            log_debug!(
                self.logger,
                "[request] Reading response message correlation_id: {correlation_id}",
                correlation_id = &msg.payload.correlation_id
            );
            match self.read_message(&mut recv).await {
                Ok(resp) => break Ok(resp),
                Err(e) => {
                    let s = e.to_string();
                    let should_retry = s.contains("connection lost")
                        || s.contains("duplicate")
                        || s.contains("aborted by peer")
                        || s.contains("closed");
                    if should_retry {
                        retry_count += 1;
                        if retry_count > self.max_request_retries {
                            log_error!(self.logger, "[request] Failed to read response message correlation_id: {correlation_id} error: {e} - retry_count: {retry_count} - giving up", correlation_id=&msg.payload.correlation_id);
                            break Err(NetworkError::TransportError(format!("failed to read response message correlation_id: {correlation_id} error: {e} - retry_count: {retry_count} - giving up", correlation_id=&msg.payload.correlation_id)));
                        }
                        tokio::time::sleep(Duration::from_millis(70)).await;
                        continue;
                    }
                    log_error!(self.logger, "[request] Failed to read response message correlation_id: {correlation_id} error: {e} - non retryable error", correlation_id=&msg.payload.correlation_id);
                    break Err(e);
                }
            }
        }?;
        log_debug!(
            self.logger,
            "[request] Received response message correlation_id: {correlation_id} type={message_type} payload_bytes={payload_bytes}",
            correlation_id=&msg.payload.correlation_id,
            message_type=response_msg.message_type,
            payload_bytes=response_msg.payload.payload_bytes.len()
        );

        Ok(response_msg.payload.payload_bytes)
    }

    async fn publish(
        &self,
        topic_path: &str,
        correlation_id: &str,
        payload: Vec<u8>,
        peer_node_id: &str,
        network_public_key: Option<Vec<u8>>,
    ) -> Result<(), NetworkError> {
        let local_node_id = self.local_node_id.clone();
        // Create the NetworkMessage internally
        let message = NetworkMessage {
            source_node_id: local_node_id,
            destination_node_id: peer_node_id.to_string(),
            message_type: super::MESSAGE_TYPE_EVENT,
            payload: super::NetworkMessagePayloadItem {
                path: topic_path.to_string(),
                payload_bytes: payload,
                correlation_id: correlation_id.to_string(),
                profile_public_keys: vec![],
                network_public_key,
            },
        };

        let mut send = tokio::time::timeout(
            self.options.open_stream_timeout,
            self.open_uni_active(peer_node_id),
        )
        .await
        .map_err(|_| NetworkError::TransportError("open_uni timeout".into()))??;
        self.write_message(&mut send, &message).await?;
        send.finish()
            .map_err(|e| NetworkError::TransportError(format!("finish uni failed: {e}")))?;
        Ok(())
    }

    async fn connect_peer(self: Arc<Self>, discovery_msg: PeerInfo) -> Result<(), NetworkError> {
        let peer_node_id = compact_id(&discovery_msg.public_key);

        // Guard concurrent connects to same peer
        let connect_mutex = self.get_or_create_connect_mutex(&peer_node_id).await;
        let _guard = connect_mutex.lock().await;

        // check we already know about this peer
        if self.state.peers.contains_key(&peer_node_id) {
            log_debug!(
                self.logger,
                "[connect_peer] Peer already connected: {peer_node_id}"
            );
            return Ok(());
        }

        log_debug!(
            self.logger,
            "[connect_peer] Starting connection to peer: {peer_node_id}"
        );
        let endpoint = {
            let guard = self.endpoint.read().await;
            match guard.as_ref().cloned() {
                Some(ep) => ep,
                None => {
                    log_debug!(self.logger, "[connect_peer] Endpoint not started (transport stopping or stopped); coalescing to no-op");
                    return Ok(());
                }
            }
        };

        if discovery_msg.addresses.is_empty() {
            log_error!(self.logger, "[connect_peer] No addresses in PeerInfo");
            return Err(NetworkError::ConfigurationError(
                "no addresses in PeerInfo".into(),
            ));
        }

        // Choose first valid address; try all if needed (for now pick first valid)
        // Iterate addresses with fallback and per-attempt backoff
        let mut last_err: Option<NetworkError> = None;
        let mut addr: Option<std::net::SocketAddr> = None;
        for (idx, addr_str) in discovery_msg.addresses.iter().enumerate() {
            match addr_str.parse::<std::net::SocketAddr>() {
                Ok(sa) => {
                    addr = Some(sa);
                    break;
                }
                Err(e) => {
                    log_warn!(
                        self.logger,
                        "[connect_peer] address[{idx}] parse error: {e}"
                    );
                    last_err = Some(NetworkError::ConfigurationError(format!(
                        "bad addr[{idx}]: {e}"
                    )));
                    continue;
                }
            }
        }
        let addr = match addr {
            Some(sa) => sa,
            None => {
                return Err(last_err.unwrap_or_else(|| {
                    NetworkError::ConfigurationError("no valid address in PeerInfo".into())
                }))
            }
        };

        // Deterministic dial-direction gate: Higher node-id yields to inbound
        let local_node_id = self.local_node_id.clone();
        let prefer_inbound = local_node_id.as_str() > peer_node_id.as_str();
        if prefer_inbound {
            // If we prefer inbound and no connection exists yet, wait briefly for inbound acceptance
            // This avoids simultaneous dials and reduces duplicate-resolution churn
            let mut attempts = 0u8;
            while attempts < 6 {
                if self.state.peers.contains_key(&peer_node_id) {
                    log_debug!(self.logger, "[connect_peer] Prefer inbound and detected mapping for {peer_node_id}; skipping outbound dial");
                    return Ok(());
                }
                // If a cancel notify is signaled (due to inbound), break early
                if let Some(n) = self
                    .state
                    .dial_cancel
                    .get(&peer_node_id)
                    .map(|e| e.value().clone())
                {
                    let notified =
                        tokio::time::timeout(Duration::from_millis(50), n.notified()).await;
                    if notified.is_ok() {
                        log_debug!(self.logger, "[connect_peer] Prefer inbound; cancel signal received for {peer_node_id}");
                        return Ok(());
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                attempts = attempts.saturating_add(1);
            }
            // Fall through to dial if inbound did not arrive in time
            log_debug!(
                self.logger,
                "[connect_peer] Prefer inbound but none arrived; proceeding to dial {peer_node_id}"
            );
        }
        log_debug!(
            self.logger,
            "[connect_peer] Connecting to {peer_node_id} at {addr}"
        );

        // Per-peer cancel Notify (created if absent)
        let cancel_notify = {
            self.state
                .dial_cancel
                .entry(peer_node_id.clone())
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone()
        };

        // Honor per-peer backoff
        let now = Instant::now();
        if let Some((attempts, until)) = self
            .state
            .dial_backoff
            .get(&peer_node_id)
            .map(|e| *e.value())
        {
            if now < until {
                let wait_ms = until.saturating_duration_since(now).as_millis();
                log_debug!(
                    self.logger,
                    "[backoff] peer={peer_node_id} attempts={attempts} remaining_ms={wait_ms}"
                );
                tokio::select! {
                    _ = tokio::time::sleep(until.saturating_duration_since(now)) => {},
                    _ = cancel_notify.notified() => {
                        log_debug!(self.logger, "[dial-cancel] peer={peer_node_id} reason=inbound-connected");
                        return Ok(());
                    }
                }
            }
        }

        let connecting = endpoint.connect(addr, &peer_node_id).map_err(|e| {
            log_error!(self.logger, "[connect_peer] Connect failed: {e}");
            NetworkError::ConnectionError(format!("connect: {e}"))
        })?;

        log_debug!(
            self.logger,
            "[connect_peer] Connection initiated, waiting for handshake..."
        );

        let conn = match connecting.await {
            Ok(c) => c,
            Err(e) => {
                let err_str = e.to_string();
                log_error!(self.logger, "[connect_peer] Handshake failed: {err_str}");
                // If the server refused because a connection already exists (race), treat as OK if we have (or soon get) an inbound mapping
                if err_str.contains("the server refused to accept a new connection") {
                    // Soft wait for inbound to correlate
                    let mut attempts = 0u8;
                    while attempts < 5 {
                        if self.state.peers.contains_key(&peer_node_id) {
                            log_debug!(self.logger, "[connect_peer] Detected existing inbound connection for {peer_node_id}; treating connect as success");
                            return Ok(());
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        attempts += 1;
                    }
                }
                // Increase backoff for next time
                // use local non-blocking random; avoid holding rng across await
                let jitter: u64 = rand::random::<u64>() % 200;
                let (mut attempts, _until) = self
                    .state
                    .dial_backoff
                    .get(&peer_node_id)
                    .map(|e| *e.value())
                    .unwrap_or((0, now));
                attempts = attempts.saturating_add(1);
                let base = 200u64.saturating_mul(2u64.saturating_pow(attempts.min(6)));
                let delay = Duration::from_millis(base.saturating_add(jitter));
                self.state
                    .dial_backoff
                    .insert(peer_node_id.clone(), (attempts, Instant::now() + delay));
                log_debug!(
                    self.logger,
                    "[backoff-incr] peer={peer_node_id} attempts={attempts} delay_ms={}",
                    delay.as_millis()
                );
                return Err(NetworkError::ConnectionError(format!(
                    "handshake failed: {err_str}"
                )));
            }
        };

        self.logger
            .debug("[connect_peer] QUIC connection established successfully");

        // wrap connection in Arc for sharing
        let conn_arc = Arc::new(conn);
        let local_nonce = Self::generate_nonce();
        let local_node_id = self.local_node_id.clone();
        // store peer if still not connected (idempotent connect)
        if !self.state.peers.contains_key(&peer_node_id) {
            // Tentative insert with placeholder dup-metadata; real values will be set after handshake
            self.state.peers.insert(
                peer_node_id.clone(),
                PeerState::new(
                    conn_arc.clone(),
                    0,
                    local_node_id.clone(),
                    0,
                    peer_node_id.clone(),
                    0,
                ),
            );
            log_debug!(self.logger, "🔍 [connect_peer] Peer stored in peer map");
        } else {
            log_debug!(
                self.logger,
                "🔍 [connect_peer] Peer already present in map (race dedup): {peer_node_id}"
            );
        }

        // spawn stream accept loops for that connection
        let task = self
            .clone()
            .spawn_connection_tasks(peer_node_id.clone(), conn_arc.clone());
        self.tasks.lock().await.push(task);
        log_debug!(self.logger, "🔍 [connect_peer] Connection tasks spawned");

        // do handshake on a fresh bi stream
        log_debug!(
            self.logger,
            "🔍 [connect_peer] Starting application-level handshake..."
        );
        let responder_nonce = match self
            .handshake_outbound(&peer_node_id, &conn_arc, local_nonce)
            .await
        {
            Ok(nonce) => nonce,
            Err(e) => {
                log_error!(
                    self.logger,
                    "[connect_peer] Application handshake failed: {e}"
                );
                log_error!(self.logger, "handshake failed: {e}");
                // If an inbound connection was established concurrently, accept that.
                // Give it a brief window to appear (duplicate-resolution race).
                let mut attempts = 0u8;
                while attempts < 8 {
                    if self.state.peers.contains_key(&peer_node_id) {
                        log_debug!(self.logger, "[connect_peer] Inbound connection detected after outbound handshake error for {peer_node_id}; keeping inbound");
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(60)).await;
                    attempts = attempts.saturating_add(1);
                }
                // If still absent, remove the tentative placeholder and back off
                self.state.peers.remove(&peer_node_id);
                let jitter: u64 = rand::random::<u64>() % 200;
                let (mut attempts, _until) = self
                    .state
                    .dial_backoff
                    .get(&peer_node_id)
                    .map(|e| *e.value())
                    .unwrap_or((0, now));
                attempts = attempts.saturating_add(1);
                let base = 200u64.saturating_mul(2u64.saturating_pow(attempts.min(6)));
                let delay = Duration::from_millis(base.saturating_add(jitter));
                self.state
                    .dial_backoff
                    .insert(peer_node_id.clone(), (attempts, Instant::now() + delay));
                return Err(e);
            }
        };

        log_debug!(
            self.logger,
            "[connect_peer] Application handshake completed successfully"
        );
        // Decide winner deterministically using the same logic as inbound path to avoid clobbering an inbound winner
        let _kept = self
            .replace_or_keep_connection(
                &peer_node_id,
                conn_arc.clone(),
                local_node_id,
                local_nonce,
                peer_node_id.clone(),
                responder_nonce,
            )
            .await;

        // Reset backoff on success
        self.state.dial_backoff.remove(&peer_node_id);
        // Cancel any outstanding dial waiters (if any)
        if let Some((_, n)) = self.state.dial_cancel.remove(&peer_node_id) {
            n.notify_waiters();
        }
        Ok(())
    }

    fn get_local_address(&self) -> String {
        // Prefer the actual bound address from the live endpoint if available (non-blocking)
        if let Ok(guard) = self.endpoint.try_read() {
            if let Some(ep) = guard.as_ref() {
                if let Ok(addr) = ep.local_addr() {
                    return addr.to_string();
                }
            }
        }
        self.bind_addr.to_string()
    }

    async fn update_peers(&self, node_info: NodeInfo) -> Result<(), NetworkError> {
        // Get all connected peers
        if self.state.peers.is_empty() {
            self.logger
                .debug("No peers connected, skipping peer update");
            return Ok(());
        }

        // Create handshake message with updated node info wrapped in HandshakeData
        let handshake_data = HandshakeData {
            node_info,
            nonce: 0, // Use 0 for update messages since this is not a new connection
            role: ConnectionRole::Initiator, // Use Initiator role for updates
        };

        let payload_bytes = serde_cbor::to_vec(&handshake_data).map_err(|e| {
            NetworkError::MessageError(format!("Failed to serialize handshake data: {e}"))
        })?;

        let local_node_id = self.local_node_id.clone();

        let message = NetworkMessage {
            source_node_id: local_node_id,
            destination_node_id: String::new(), // Will be set per peer
            message_type: super::MESSAGE_TYPE_HANDSHAKE,
            payload: super::NetworkMessagePayloadItem {
                path: "handshake".to_string(),
                payload_bytes,
                correlation_id: uuid::Uuid::new_v4().to_string(),
                profile_public_keys: vec![],
                network_public_key: None, // Update message doesn't need network context
            },
        };

        // Send to each connected peer
        for entry in self.state.peers.iter() {
            let peer_id = entry.key();
            let _peer_state = entry.value();

            log_debug!(
                self.logger,
                "🔍 [update_peers] Sending handshake to {peer_id}"
            );

            let mut send = tokio::time::timeout(
                self.options.open_stream_timeout,
                self.open_uni_active(peer_id),
            )
            .await
            .map_err(|_| NetworkError::TransportError("open_uni timeout".into()))??;

            self.write_message(&mut send, &message).await?;
            send.finish().map_err(|e| {
                NetworkError::TransportError(format!("Failed to finish send to {peer_id}: {e}"))
            })?;

            self.logger
                .debug(format!("Updated peer {peer_id} with new node info"));
        }

        log_debug!(
            self.logger,
            "Updated {} peers with new node info",
            self.state.peers.len()
        );
        Ok(())
    }
}
