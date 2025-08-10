use std::{net::SocketAddr, sync::Arc};
use tokio::sync::watch;

use async_trait::async_trait;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use runar_common::compact_ids::compact_id;
use runar_common::logging::Logger;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::RwLock;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::{GeneralName, ParsedExtension};
use dashmap::DashMap;

use crate::network::discovery::{multicast_discovery::PeerInfo, NodeInfo};
use crate::network::transport::{MessageContext, NetworkError, NetworkMessage, NetworkTransport};
use crate::routing::TopicPath;
use runar_serializer::{ArcValue, SerializationContext};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use rustls_pki_types::ServerName;

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
    one_way_message_handler: Option<super::OneWayMessageHandler>,
    connection_callback: Option<super::ConnectionCallback>,
    logger: Option<Arc<Logger>>,
    keystore: Option<Arc<dyn runar_serializer::traits::EnvelopeCrypto>>,
    label_resolver: Option<Arc<dyn runar_serializer::traits::LabelResolver>>,
    // Cache TTL for idempotent response replay
    response_cache_ttl: Duration,
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
                "connection_callback",
                &if self.connection_callback.is_some() {
                    "Some(ConnectionCallback)"
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

impl Default for QuicTransportOptions {
    fn default() -> Self {
        Self {
            certificates: None,
            private_key: None,
            root_certificates: None,
            // Provide sane non-zero defaults to avoid immediate handshake/idle timeouts
            connection_idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(5),

            local_node_info: None,
            bind_addr: None,
            message_handler: None,
            one_way_message_handler: None,
            connection_callback: None,
            logger: None,
            keystore: None,
            label_resolver: None,
            response_cache_ttl: Duration::from_secs(5),
        }
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

    pub fn with_one_way_message_handler(mut self, handler: super::OneWayMessageHandler) -> Self {
        self.one_way_message_handler = Some(handler);
        self
    }

    pub fn with_connection_callback(mut self, callback: super::ConnectionCallback) -> Self {
        self.connection_callback = Some(callback);
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

    pub fn with_response_cache_ttl(mut self, ttl: Duration) -> Self {
        self.response_cache_ttl = ttl;
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

    pub fn one_way_message_handler(&self) -> Option<&super::OneWayMessageHandler> {
        self.one_way_message_handler.as_ref()
    }

    pub fn connection_callback(&self) -> Option<&super::ConnectionCallback> {
        self.connection_callback.as_ref()
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

    pub fn response_cache_ttl(&self) -> Duration {
        self.response_cache_ttl
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
            one_way_message_handler: None, // OneWayMessageHandler doesn't implement Clone
            connection_callback: self.connection_callback.clone(),
            logger: self.logger.clone(),
            keystore: self.keystore.clone(),
            label_resolver: self.label_resolver.clone(),
            response_cache_ttl: self.response_cache_ttl,
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
        .collect()
}

#[derive(Clone, Debug)]
struct SharedState {
    peers: PeerMap,
    connection_id_to_peer_id: Arc<DashMap<usize, String>>,
    dial_backoff: Arc<DashMap<String, (u32, Instant)>>,
    dial_cancel: Arc<DashMap<String, Arc<Notify>>>,
}
type PeerMap = Arc<RwLock<HashMap<String, PeerState>>>;
type ConnectionIdToPeerIdMap = Arc<DashMap<usize, String>>;

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
    one_way_message_handler: super::OneWayMessageHandler,
    connection_callback: Option<super::ConnectionCallback>,

    // crypto helpers
    keystore: Arc<dyn runar_serializer::traits::EnvelopeCrypto>,
    label_resolver: Arc<dyn runar_serializer::traits::LabelResolver>,

    // shared runtime state (peers + broadcast)
    state: SharedState,

    // short-lived cache to deduplicate REQUEST handling by correlation_id
    response_cache: dashmap::DashMap<String, (Instant, Arc<NetworkMessage>)>,
    response_cache_ttl: Duration,

    // background tasks
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,

    running: tokio::sync::RwLock<bool>,
}

impl QuicTransport {
    fn generate_nonce() -> u64 {
        rand::random::<u64>()
    }

    fn local_node_id(&self) -> String {
        compact_id(&self.local_node_info.node_public_key)
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
        self.logger.debug(format!(
            "🔁 [dup] evaluate peer={peer_node_id} new_id={new_id} init=({initiator_peer_id},{initiator_nonce}) resp=({responder_peer_id},{responder_nonce})"
        ));
        // Cancel any pending outbound dial to this peer and reset backoff on successful inbound
        {
            if let Some((_, n)) = self.state.dial_cancel.remove(peer_node_id) {
                n.notify_waiters();
            }
        }
        {
            self.state.dial_backoff.remove(peer_node_id);
        }
        let mut peers = self.state.peers.write().await;
        let existing_opt = peers.get(peer_node_id).cloned();
        if let Some(existing) = existing_opt {
            self.logger.debug(format!(
                "🔁 [dup] existing for peer={peer_node_id} existing_id={} init=({},{}) resp=({},{})",
                existing.connection_id,
                existing.initiator_peer_id,
                existing.initiator_nonce,
                existing.responder_peer_id,
                existing.responder_nonce
            ));
            // If existing entry is a placeholder (no dup-metadata), always replace with the real connection
            if existing.initiator_nonce == 0 && existing.responder_nonce == 0 {
                self.logger.debug(format!(
                    "🔁 [dup] Replacing placeholder connection for peer {peer_node_id} with established connection"
                ));
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
                peers.insert(peer_node_id.to_string(), new_state);
                // Update mapping for the connection id
                self.state
                    .connection_id_to_peer_id
                    .insert(new_id, peer_node_id.to_string());
                // Activate the winner
                if let Some(state) = peers.get(peer_node_id) {
                    let _ = state.activation_tx.send(true);
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
            let local_id = self.local_node_id();
            let desired_local_role = if local_id.as_str() < peer_node_id {
                ConnectionRole::Initiator
            } else {
                ConnectionRole::Responder
            };

            let existing_local_role = if existing.initiator_peer_id == local_id {
                ConnectionRole::Initiator
            } else {
                ConnectionRole::Responder
            };
            let candidate_local_role = if initiator_peer_id == local_id {
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
                self.logger.debug(format!(
                    "🔁 [dup] Candidate wins (desired={desired_local_role:?}, existing={existing_local_role:?}, candidate={candidate_local_role:?}) for peer {peer_node_id}"
                ));
                let new_state = PeerState::new(
                    new_conn,
                    existing.node_info_version,
                    initiator_peer_id,
                    initiator_nonce,
                    responder_peer_id,
                    responder_nonce,
                );
                let conn_id = new_state.connection_id;
                peers.insert(peer_node_id.to_string(), new_state);
                self.state
                    .connection_id_to_peer_id
                    .insert(conn_id, peer_node_id.to_string());
                if existing.connection_id != conn_id {
                    existing
                        .connection
                        .close(0u32.into(), b"duplicate-replaced");
                }
                if let Some(state) = peers.get(peer_node_id) {
                    let _ = state.activation_tx.send(true);
                }
                true
            } else {
                self.logger.debug(format!(
                    "🔁 [dup] Existing kept (desired={desired_local_role:?}, existing={existing_local_role:?}, candidate={candidate_local_role:?}) for peer {peer_node_id}; closing new"
                ));
                new_conn.close(0u32.into(), b"duplicate-loser");
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
            peers.insert(peer_node_id.to_string(), new_state);
                            self.state
                    .connection_id_to_peer_id
                    .insert(conn_id, peer_node_id.to_string());
            if let Some(state) = peers.get(peer_node_id) {
                let _ = state.activation_tx.send(true);
            }
            true
        }
    }
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
        let one_way_message_handler = options
            .one_way_message_handler
            .take()
            .ok_or("one_way_message_handler is required")?;
        let connection_callback = options.connection_callback.take();
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

        let cache_ttl = options.response_cache_ttl();
        Ok(Self {
            local_node_info,
            bind_addr,
            options,
            endpoint: Arc::new(RwLock::new(None)),
            logger: Arc::new(logger),
            message_handler,
            one_way_message_handler,
            connection_callback,
            keystore,
            label_resolver,
            state: Self::shared_state(),
            tasks: Mutex::new(Vec::new()),
            running: tokio::sync::RwLock::new(false),
            response_cache: dashmap::DashMap::new(),
            response_cache_ttl: cache_ttl,
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
        let mut server_config = ServerConfig::with_single_cert(certs.clone(), key.clone_key())
            .map_err(|e| {
                NetworkError::ConfigurationError(format!("Failed to create server config: {e}"))
            })?;
        server_config.transport_config(transport_config.clone());

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

    fn spawn_accept_loop(self: Arc<Self>, _endpoint: Endpoint) -> tokio::task::JoinHandle<()> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            loop {
                // If transport is no longer running, break the loop
                if !*self_clone.running.read().await {
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
                    .get(&connection_id)
                {
                    Some(entry) => entry.value().clone(),
                    None => {
                        self_clone.logger.error(format!("Connection id {connection_id} not found in connection id to peer id map"));
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
                let peers_guard = self_clone.state.peers.read().await;
                matches!(peers_guard.get(&resolved_peer_id), Some(current) if current.connection_id == connection_id)
            };
            if should_remove {
                tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                let mut peers_guard = self_clone.state.peers.write().await;
                if let Some(current) = peers_guard.get(&resolved_peer_id) {
                    if current.connection_id == connection_id {
                        peers_guard.remove(&resolved_peer_id);
                        removed = true;
                    } else {
                        self_clone.logger.debug(format!(
                            "(post-grace) connection tasks for old conn_id={} exited; current conn_id={} remains for peer {}",
                            connection_id, current.connection_id, resolved_peer_id
                        ));
                    }
                }
            } else {
                self_clone.logger.debug(format!(
                    "connection tasks for old conn_id={connection_id} exited; current active differs for peer {resolved_peer_id}"
                ));
            }
            if removed {
                // Reset backoff so that future dials are allowed promptly after a clean disconnect
                self_clone
                    .state
                    .dial_backoff
                    .remove(&resolved_peer_id);
                // Cancel any pending dial waits
                if let Some((_, n)) = self_clone
                    .state
                    .dial_cancel
                    .remove(&resolved_peer_id)
                {
                    n.notify_waiters();
                }
                self_clone.logger.debug(format!("connection tasks exited for peer_node_id: {resolved_peer_id} - local node_id: {local_node_id}", local_node_id=compact_id(&self_clone.local_node_info.node_public_key)));

                // Grace period: avoid flapping during duplicate-connection resolution.
                // Only emit on_down if the peer remains absent after a short delay.
                if let Some(cb) = &self_clone.connection_callback {
                    let cb = cb.clone();
                    let self_check = self_clone.clone();
                    let peer_for_check = resolved_peer_id.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                        let still_disconnected = !self_check
                            .state
                            .peers
                            .read()
                            .await
                            .contains_key(&peer_for_check);
                        if still_disconnected {
                            let _ = (cb)(peer_for_check.clone(), false, None).await;
                        } else {
                            self_check.logger.debug(format!("disconnect suppressed for {peer_for_check} due to new active connection"));
                        }
                    });
                }
            }
        })
    }

    async fn uni_accept_loop(&self, conn: Arc<quinn::Connection>) -> Result<(), NetworkError> {
        loop {
            let mut recv = conn
                .accept_uni()
                .await
                .map_err(|e| NetworkError::TransportError(e.to_string()))?;
            let msg = self.read_message(&mut recv).await?;
            // Use the one-way message handler for unidirectional streams
            (self.one_way_message_handler)(msg).await?;
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
            // Accept bidirectional streams; do not fail the whole loop on timeouts
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(v) => v,
                Err(e) => {
                    return Err(NetworkError::TransportError(e.to_string()));
                }
            };
            let msg = self.read_message(&mut recv).await?;

            self.logger.debug(format!("🔍 [bi_accept_loop] Received message: type={type}, source={source}, dest={dest}", 
                     type=msg.message_type, source=msg.source_node_id, dest=msg.destination_node_id));

            if msg.message_type == super::MESSAGE_TYPE_HANDSHAKE {
                self.logger
                    .debug("🔍 [bi_accept_loop] Processing handshake message");

                let mut response_nonce: u64 = 0;
                let mut should_send_response = false;
                if let Some(payload) = msg.payloads.first() {
                    // Try new HandshakeData (with nonce/role); fall back to raw NodeInfo for compatibility
                    let parsed: Result<HandshakeData, _> =
                        serde_cbor::from_slice(&payload.value_bytes);
                    if let Ok(hs) = parsed {
                        let peer_node_id = msg.source_node_id.clone();
                        let node_info = hs.node_info;
                        let node_info_version = node_info.version;
                        let remote_nonce = hs.nonce;
                        let remote_role = hs.role;
                        let local_role = ConnectionRole::Responder;
                        let local_nonce = Self::generate_nonce();
                        response_nonce = local_nonce;

                        self.logger.debug(format!("🔍 [bi_accept_loop] HS v2 from {peer_node_id} ver={node_info_version} role={remote_role:?} nonce={remote_nonce}"));
                        let candidate_initiator = match (remote_role, local_role) {
                            (ConnectionRole::Initiator, ConnectionRole::Responder) => (
                                peer_node_id.clone(),
                                remote_nonce,
                                self.local_node_id(),
                                local_nonce,
                            ),
                            (ConnectionRole::Responder, ConnectionRole::Responder) => (
                                peer_node_id.clone(),
                                remote_nonce,
                                self.local_node_id(),
                                local_nonce,
                            ),
                            (ConnectionRole::Initiator, ConnectionRole::Initiator) => (
                                peer_node_id.clone(),
                                remote_nonce,
                                self.local_node_id(),
                                local_nonce,
                            ),
                            (ConnectionRole::Responder, ConnectionRole::Initiator) => (
                                self.local_node_id(),
                                local_nonce,
                                peer_node_id.clone(),
                                remote_nonce,
                            ),
                        };
                        self.logger.debug(format!(
                            "🔍 [bi_accept_loop] candidate dup key init=({},{}) resp=({},{})",
                            candidate_initiator.0,
                            candidate_initiator.1,
                            candidate_initiator.2,
                            candidate_initiator.3
                        ));
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
                            continue;
                        }
                        // Mark active after surviving dup-resolution
                        if let Some(state) = self.state.peers.read().await.get(&peer_node_id) {
                            let _ = state.activation_tx.send(true);
                        }
                        should_send_response = true;
                        let _ = (self.message_handler)(msg.clone()).await;
                        if needs_to_correlate_peer_id {
                            self.state
                                .connection_id_to_peer_id
                                .insert(conn.stable_id(), peer_node_id);
                        }
                    } else {
                        match serde_cbor::from_slice::<NodeInfo>(&payload.value_bytes) {
                            Ok(node_info) => {
                                let peer_node_id = msg.source_node_id.clone();
                                let node_info_version = node_info.version;

                                self.logger.debug(format!("🔍 [bi_accept_loop] Handshake NodeInfo peer_node_id: {peer_node_id} node info version: {node_info_version}"));
                                // Legacy path: we don't have nonces/roles; treat this as inbound responder wins
                                let kept = self
                                    .replace_or_keep_connection(
                                        &peer_node_id,
                                        conn.clone(),
                                        self.local_node_id(),
                                        0,
                                        peer_node_id.clone(),
                                        0,
                                    )
                                    .await;
                                if !kept {
                                    continue;
                                }
                                if let Some(state) =
                                    self.state.peers.read().await.get(&peer_node_id)
                                {
                                    let _ = state.activation_tx.send(true);
                                }
                                should_send_response = true;
                                let _ = (self.message_handler)(msg.clone()).await;
                                if needs_to_correlate_peer_id {
                                    self.state
                                        .connection_id_to_peer_id
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
                }

                // Send handshake response only if this connection is the surviving winner
                if should_send_response {
                    self.logger
                        .debug("🔍 [bi_accept_loop] Sending handshake response");
                    let response_hs = HandshakeData {
                        node_info: self.local_node_info.clone(),
                        nonce: response_nonce, // include responder nonce (0 for legacy), so both sides can compute tie-break keys
                        role: ConnectionRole::Responder,
                    };
                    let response_msg = NetworkMessage {
                        source_node_id: compact_id(&self.local_node_info.node_public_key),
                        destination_node_id: msg.source_node_id,
                        message_type: super::MESSAGE_TYPE_HANDSHAKE,
                        payloads: vec![super::NetworkMessagePayloadItem {
                            path: "handshake".to_string(),
                            value_bytes: serde_cbor::to_vec(&response_hs).unwrap_or_default(),
                            correlation_id: msg
                                .payloads
                                .first()
                                .map(|p| p.correlation_id.clone())
                                .unwrap_or_default(),
                            context: None,
                        }],
                    };

                    // Let upper layer process our handshake response (capabilities) as well
                    // so both sides can register remote services. First, send it to peer:
                    self.write_message(&mut send, &response_msg).await?;
                    send.finish()
                        .map_err(|e| NetworkError::TransportError(e.to_string()))?;
                    self.logger
                        .debug("✅ [bi_accept_loop] Handshake response sent");
                }
                // Notify connection up
                if let Some(cb) = &self.connection_callback {
                    // Resolve peer id strictly from mapping, otherwise skip (avoid bogus IP-based ids)
                    let connection_id = conn.stable_id();
                    if let Some(resolved_peer_id) = self
                        .state
                        .connection_id_to_peer_id
                        .get(&connection_id)
                        .map(|entry| entry.value().clone())
                    {
                        let _ = (cb)(resolved_peer_id, true, None).await;
                    } else {
                        self.logger.debug("[bi_accept_loop] Skipping on_up callback due to missing peer-id mapping");
                    }
                }
                continue;
            }

            // Extract fields needed for error handling before moving msg
            let source_node_id = msg.source_node_id.clone();
            let payloads = msg.payloads.clone();

            // For REQUEST messages, attempt idempotent handling using correlation_id
            if msg.message_type == super::MESSAGE_TYPE_REQUEST {
                if let Some(corr_id_ref) = msg.payloads.first().map(|p| p.correlation_id.as_str()) {
                    if let Some(entry) = self.response_cache.get(corr_id_ref) {
                        let (ts, cached) = entry.value();
                        let now = Instant::now();
                        if now.saturating_duration_since(*ts) <= self.response_cache_ttl {
                            self.write_message(&mut send, cached).await?;
                            send.finish()
                                .map_err(|e| NetworkError::TransportError(e.to_string()))?;
                            continue;
                        }
                    }
                }
            }

            match (self.message_handler)(msg).await {
                Ok(Some(reply)) => {
                    // Cache the successful response for a short period to deduplicate retries
                    if reply.message_type == super::MESSAGE_TYPE_RESPONSE {
                        if let Some(corr_id) =
                            reply.payloads.first().map(|p| p.correlation_id.clone())
                        {
                            let now = Instant::now();
                            self.response_cache
                                .insert(corr_id, (now, Arc::new(reply.clone())));
                        }
                    }
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
        local_nonce: u64,
    ) -> Result<u64, NetworkError> {
        self.logger.debug(format!(
            "🔍 [handshake_outbound] Starting handshake with peer: {peer_id}"
        ));

        self.logger
            .debug("🔍 [handshake_outbound] Serializing local HandshakeData");
        let hs = HandshakeData {
            node_info: self.local_node_info.clone(),
            nonce: local_nonce,
            role: ConnectionRole::Initiator,
        };
        let payload_bytes = serde_cbor::to_vec(&hs).map_err(|e| {
            self.logger.error(format!(
                "❌ [handshake_outbound] Failed to serialize HandshakeData: {e}"
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
            .debug("🔍 [handshake_outbound] Opening bi stream for handshake (v2)");
        // Open a fresh bi-directional stream for handshake
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| {
            self.logger.error(format!(
                "❌ [handshake_outbound] Failed to open bi stream: {e}"
            ));
            NetworkError::TransportError(e.to_string())
        })?;

        self.logger
            .debug("🔍 [handshake_outbound] Writing handshake message");
        self.write_message(&mut send, &msg).await?;
        send.finish().map_err(|e| {
            self.logger.error(format!(
                "❌ [handshake_outbound] Failed to finish send: {e}"
            ));
            NetworkError::TransportError(e.to_string())
        })?;

        self.logger
            .debug("🔍 [handshake_outbound] Waiting for handshake response with timeout");
        let reply = tokio::time::timeout(Duration::from_secs(2), self.read_message(&mut recv))
            .await
            .map_err(|_| NetworkError::TransportError("handshake response timeout".into()))??;

        self.logger
            .debug("🔍 [handshake_outbound] Received handshake response, processing...");

        // Parse responder handshake (prefer v2), fall back to v1 NodeInfo
        let mut responder_nonce: u64 = 0;
        if let Some(payload) = reply.payloads.first() {
            if let Ok(hs) = serde_cbor::from_slice::<HandshakeData>(&payload.value_bytes) {
                responder_nonce = hs.nonce;
            } else if let Ok(_node_info) = serde_cbor::from_slice::<NodeInfo>(&payload.value_bytes)
            {
                responder_nonce = 0;
            }
        }

        //send to node to handle handshake response and store peer node info
        let _ = (self.message_handler)(reply).await;

        // Notify connection up
        if let Some(cb) = &self.connection_callback {
            let _ = (cb)(peer_id.to_string(), true, None).await;
        }

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
            let maybe_peer = {
                let peers_read = self.state.peers.read().await;
                peers_read.get(peer_node_id).cloned()
            };
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
            connection_id_to_peer_id: Arc::new(DashMap::new()),
            dial_backoff: Arc::new(DashMap::new()),
            dial_cancel: Arc::new(DashMap::new()),
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
                        self.logger.warn(format!(
                            "[start] Bind failed with EADDRINUSE, retrying attempt {}...",
                            attempt + 1
                        ));
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
                if !*prune_self.running.read().await {
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

        // Snapshot and clear peers under a write lock to avoid deadlocks
        self.logger.debug("Closing all connections");
        let connections_to_close: Vec<quinn::Connection> = {
            let mut peers_guard = self.state.peers.write().await;
            let conns = peers_guard
                .values()
                .map(|p| p.connection.as_ref().clone())
                .collect::<Vec<_>>();
            peers_guard.clear();
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
        self.logger.debug("canceling all remaining tasks");
        let mut tasks = self.tasks.lock().await;
        while let Some(t) = tasks.pop() {
            t.abort();
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

        let network_id = topic_path.network_id();
        let correlation_id = uuid::Uuid::new_v4().to_string();
        let profile_public_key = context.profile_public_key.clone();

        let serialization_context = SerializationContext {
            keystore: self.keystore.clone(),
            resolver: self.label_resolver.clone(),
            network_id,
            profile_public_key: Some(profile_public_key.clone()),
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

        let response_msg = loop {
            self.logger
                .info("🔍 [request] Opening bidirectional stream");
            let (mut send, mut recv) = self.open_bi_active(peer_node_id).await?;

            self.logger
                .info("🔍 [request] Writing request message to stream");
            if let Err(e) = self.write_message(&mut send, &msg).await {
                self.logger
                    .error(format!("❌ [request] Failed to write request: {e}"));
                break Err(e);
            }

            self.logger.info("🔍 [request] Finishing send stream");
            if let Err(e) = send.finish() {
                self.logger
                    .error(format!("❌ [request] Failed to finish send stream: {e}"));
                tokio::time::sleep(Duration::from_millis(70)).await;
                continue;
            }

            self.logger.info("🔍 [request] Reading response message");
            match self.read_message(&mut recv).await {
                Ok(resp) => break Ok(resp),
                Err(e) => {
                    let s = e.to_string();
                    let should_retry = s.contains("connection lost")
                        || s.contains("duplicate")
                        || s.contains("aborted by peer")
                        || s.contains("closed");
                    if should_retry {
                        tokio::time::sleep(Duration::from_millis(70)).await;
                        continue;
                    }
                    break Err(e);
                }
            }
        }?;
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
        let av = ArcValue::deserialize(bytes, Some(self.keystore.clone())).map_err(|e| {
            self.logger
                .error(format!("❌ [request] Failed to deserialize response: {e}"));
            NetworkError::MessageError(format!("deserialize response: {e}"))
        })?;

        self.logger
            .info("✅ [request] Request completed successfully");
        Ok(av)
    }

    async fn publish(
        &self,
        topic_path: &TopicPath,
        params: Option<ArcValue>,
        peer_node_id: &str,
    ) -> Result<(), NetworkError> {
        let network_id = topic_path.network_id();
        let correlation_id = uuid::Uuid::new_v4().to_string();

        let serialization_context = SerializationContext {
            keystore: self.keystore.clone(),
            resolver: self.label_resolver.clone(),
            network_id,
            profile_public_key: None,
        };
        // Create the NetworkMessage internally
        let message = NetworkMessage {
            source_node_id: compact_id(&self.local_node_info.node_public_key),
            destination_node_id: peer_node_id.to_string(),
            message_type: super::MESSAGE_TYPE_EVENT,
            payloads: vec![super::NetworkMessagePayloadItem {
                path: topic_path.to_string(),
                value_bytes: if let Some(v) = params {
                    v.serialize(Some(&serialization_context))
                        .map_err(|e| NetworkError::MessageError(e.to_string()))?
                } else {
                    ArcValue::null()
                        .serialize(Some(&serialization_context))
                        .map_err(|e| NetworkError::MessageError(e.to_string()))?
                },
                correlation_id,
                context: None,
            }],
        };

        let mut send = self.open_uni_active(peer_node_id).await?;
        self.write_message(&mut send, &message).await?;
        send.finish()
            .map_err(|e| NetworkError::TransportError(format!("finish uni failed: {e}")))?;
        Ok(())
    }

    async fn connect_peer(self: Arc<Self>, discovery_msg: PeerInfo) -> Result<(), NetworkError> {
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
            match guard.as_ref().cloned() {
                Some(ep) => ep,
                None => {
                    self.logger.debug("[connect_peer] Endpoint not started (transport stopping or stopped); coalescing to no-op");
                    return Ok(());
                }
            }
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
        // Deterministic dial-direction gate: Higher node-id yields to inbound
        let local_id = self.local_node_id();
        let prefer_inbound = local_id.as_str() > peer_node_id.as_str();
        if prefer_inbound {
            // If we prefer inbound and no connection exists yet, wait briefly for inbound acceptance
            // This avoids simultaneous dials and reduces duplicate-resolution churn
            let mut attempts = 0u8;
            while attempts < 6 {
                if self.state.peers.read().await.contains_key(&peer_node_id) {
                    self.logger.debug(format!("[connect_peer] Prefer inbound and detected mapping for {peer_node_id}; skipping outbound dial"));
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
                        self.logger.debug(format!("[connect_peer] Prefer inbound; cancel signal received for {peer_node_id}"));
                        return Ok(());
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                attempts = attempts.saturating_add(1);
            }
            // Fall through to dial if inbound did not arrive in time
            self.logger.debug(format!(
                "[connect_peer] Prefer inbound but none arrived; proceeding to dial {peer_node_id}"
            ));
        }
        self.logger.debug(format!("🔍 [connect_peer] Connecting to {peer_node_id} (DNS-safe: {dns_safe_peer_id}) at {addr}"));

        // Per-peer cancel Notify (created if absent)
        let cancel_notify = {
            self.state.dial_cancel
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
                self.logger.debug(format!(
                    "⏳ [backoff] peer={peer_node_id} attempts={attempts} remaining_ms={wait_ms}"
                ));
                tokio::select! {
                    _ = tokio::time::sleep(until.saturating_duration_since(now)) => {},
                    _ = cancel_notify.notified() => {
                        self.logger.debug(format!("🚫 [dial-cancel] peer={peer_node_id} reason=inbound-connected"));
                        return Ok(());
                    }
                }
            }
        }

        let connecting = endpoint.connect(addr, &dns_safe_peer_id).map_err(|e| {
            self.logger
                .error(format!("❌ [connect_peer] Connect failed: {e}"));
            NetworkError::ConnectionError(format!("connect: {e}"))
        })?;

        self.logger
            .debug("🔍 [connect_peer] Connection initiated, waiting for handshake...");

        let conn = match connecting.await {
            Ok(c) => c,
            Err(e) => {
                let err_str = e.to_string();
                self.logger
                    .error(format!("❌ [connect_peer] Handshake failed: {err_str}"));
                // If the server refused because a connection already exists (race), treat as OK if we have (or soon get) an inbound mapping
                if err_str.contains("the server refused to accept a new connection") {
                    // Soft wait for inbound to correlate
                    let mut attempts = 0u8;
                    while attempts < 5 {
                        if self.state.peers.read().await.contains_key(&peer_node_id) {
                            self.logger.debug(format!("[connect_peer] Detected existing inbound connection for {peer_node_id}; treating connect as success"));
                            return Ok(());
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        attempts += 1;
                    }
                }
                // Increase backoff for next time
                // use local non-blocking random; avoid holding rng across await
                let jitter: u64 = rand::random::<u64>() % 200;
                let (mut attempts, _until) = self.state.dial_backoff.get(&peer_node_id).map(|e| *e.value()).unwrap_or((0, now));
                attempts = attempts.saturating_add(1);
                let base = 200u64.saturating_mul(2u64.saturating_pow(attempts.min(6)));
                let delay = Duration::from_millis(base.saturating_add(jitter));
                self.state.dial_backoff.insert(peer_node_id.clone(), (attempts, Instant::now() + delay));
                self.logger.debug(format!(
                    "⏫ [backoff-incr] peer={peer_node_id} attempts={attempts} delay_ms={}",
                    delay.as_millis()
                ));
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

        // store peer if still not connected (idempotent connect)
        {
            let mut peers = self.state.peers.write().await;
            if !peers.contains_key(&peer_node_id) {
                // Tentative insert with placeholder dup-metadata; real values will be set after handshake
                peers.insert(
                    peer_node_id.clone(),
                    PeerState::new(
                        conn_arc.clone(),
                        0,
                        self.local_node_id(),
                        0,
                        peer_node_id.clone(),
                        0,
                    ),
                );
                self.logger
                    .debug("🔍 [connect_peer] Peer stored in peer map");
            } else {
                self.logger.debug(format!(
                    "🔍 [connect_peer] Peer already present in map (race dedup): {peer_node_id}"
                ));
            }
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
        let responder_nonce = match self
            .handshake_outbound(&peer_node_id, &conn_arc, local_nonce)
            .await
        {
            Ok(nonce) => nonce,
            Err(e) => {
                self.logger.error(format!(
                    "❌ [connect_peer] Application handshake failed: {e}"
                ));
                self.logger.error(format!("handshake failed: {e}"));
                // If an inbound connection was established concurrently, accept that.
                // Give it a brief window to appear (duplicate-resolution race).
                let mut attempts = 0u8;
                while attempts < 8 {
                    if self.state.peers.read().await.contains_key(&peer_node_id) {
                        self.logger.debug(format!("[connect_peer] Inbound connection detected after outbound handshake error for {peer_node_id}; keeping inbound"));
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(60)).await;
                    attempts = attempts.saturating_add(1);
                }
                // If still absent, remove the tentative placeholder and back off
                self.state.peers.write().await.remove(&peer_node_id);
                let jitter: u64 = rand::random::<u64>() % 200;
                let (mut attempts, _until) = self.state.dial_backoff.get(&peer_node_id).map(|e| *e.value()).unwrap_or((0, now));
                attempts = attempts.saturating_add(1);
                let base = 200u64.saturating_mul(2u64.saturating_pow(attempts.min(6)));
                let delay = Duration::from_millis(base.saturating_add(jitter));
                self.state.dial_backoff.insert(peer_node_id.clone(), (attempts, Instant::now() + delay));
                return Err(e);
            }
        };

        self.logger
            .debug("[connect_peer] Application handshake completed successfully");
        // Decide winner deterministically using the same logic as inbound path to avoid clobbering an inbound winner
        let _kept = self
            .replace_or_keep_connection(
                &peer_node_id,
                conn_arc.clone(),
                self.local_node_id(),
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
        for (peer_id, _peer_state) in peers.iter() {
            let mut send = self.open_uni_active(peer_id).await.map_err(|e| {
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
