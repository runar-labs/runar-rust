use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use runar_common::compact_ids::compact_id;
use runar_common::logging::Logger;
use std::collections::HashMap;
use std::time::Duration;
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

#[derive(Default)]
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

    pub fn with_one_way_message_handler(mut self, handler: super::OneWayMessageHandler) -> Self {
        self.one_way_message_handler = Some(handler);
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

    pub fn one_way_message_handler(&self) -> Option<&super::OneWayMessageHandler> {
        self.one_way_message_handler.as_ref()
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
            one_way_message_handler: None, // OneWayMessageHandler doesn't implement Clone
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
        .collect()
}

#[derive(Clone, Debug)]
struct SharedState {
    peers: PeerMap,
    connection_id_to_peer_id: ConnectionIdToPeerIdMap,
}
type PeerMap = Arc<RwLock<HashMap<String, PeerState>>>;
type ConnectionIdToPeerIdMap = Arc<RwLock<HashMap<usize, String>>>;

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
        let one_way_message_handler = options
            .one_way_message_handler
            .take()
            .ok_or("one_way_message_handler is required")?;
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
            one_way_message_handler,
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
                                    // Only update if the incoming version is strictly greater than the stored version
                                    if node_info_version <= peer.node_info_version {
                                        self.logger.debug(format!("🔍 [bi_accept_loop] Known peer_node_id: {peer_node_id} with version: {node_info_version} is not newer than stored version {stored_version} - no update needed - we will skip sending the handshake response", stored_version = peer.node_info_version));
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
        let av = ArcValue::deserialize(bytes, Some(self.keystore.clone()))
            .map_err(|e| {
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

        let peers = self.state.peers.read().await;
        let peer = peers.get(peer_node_id).ok_or_else(|| {
            NetworkError::ConnectionError(format!("not connected to peer {peer_node_id}"))
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
