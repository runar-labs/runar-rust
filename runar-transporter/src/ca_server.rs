//! CA Node QUIC Server Implementation
//!
//! This module implements a dedicated QUIC server for CA Node operations, separate from
//! the existing P2P QUIC server. It provides two bind modes:
//! - Bootstrap bind (server-auth only): for enrollment before clients have certificates
//! - Authenticated bind (mTLS): for all other CA operations requiring client certificates
//!
//! Endpoints:
//! - Bootstrap: $ca/{network_id}/enroll, $ca/{network_id}/chain
//! - Authenticated: $ca/{network_id}/renew, $ca/{network_id}/revoke, $ca/{network_id}/crl, $ca/{network_id}/status

use anyhow::Result;
use quinn::{Endpoint, ServerConfig};
use runar_common::logging::Logger;
use runar_keys::{
    ca_node::CANode,
    ca_node_types::{
        CaErrorResponse, ChainRequest, ChainResponse, CrlRequest, CrlResponse, CsrEnrollRequest,
        CsrEnrollResponse, RenewRequest, RenewResponse, RevokeRequest, RevokeResponse,
        StatusRequest, StatusResponse,
    },
    certificate::EcdsaKeyPair,
};
use rustls::{server::WebPkiClientVerifier, RootCertStore, ServerConfig as RustlsServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde_cbor;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::RwLock;
use x509_parser::prelude::FromDer;

/// CA Node message types for binary protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaMessageType {
    // Bootstrap requests
    CsrEnrollRequest = 0x0001,
    ChainRequest = 0x0002,

    // Bootstrap responses
    CsrEnrollResponse = 0x1001,
    ChainResponse = 0x1002,

    // Authenticated requests
    RenewRequest = 0x0003,
    RevokeRequest = 0x0004,
    CrlRequest = 0x0005,
    StatusRequest = 0x0006,

    // Authenticated responses
    RenewResponse = 0x1003,
    RevokeResponse = 0x1004,
    CrlResponse = 0x1005,
    StatusResponse = 0x1006,

    // Error response
    ErrorResponse = 0x2000,
}

impl CaMessageType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x0001 => Some(CaMessageType::CsrEnrollRequest),
            0x0002 => Some(CaMessageType::ChainRequest),
            0x1001 => Some(CaMessageType::CsrEnrollResponse),
            0x1002 => Some(CaMessageType::ChainResponse),
            0x0003 => Some(CaMessageType::RenewRequest),
            0x0004 => Some(CaMessageType::RevokeRequest),
            0x0005 => Some(CaMessageType::CrlRequest),
            0x0006 => Some(CaMessageType::StatusRequest),
            0x1003 => Some(CaMessageType::RenewResponse),
            0x1004 => Some(CaMessageType::RevokeResponse),
            0x1005 => Some(CaMessageType::CrlResponse),
            0x1006 => Some(CaMessageType::StatusResponse),
            0x2000 => Some(CaMessageType::ErrorResponse),
            _ => None,
        }
    }

    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

/// CA Node QUIC Server configuration
#[derive(Debug, Clone)]
pub struct CaServerConfig {
    /// Bootstrap bind address (server-auth only)
    pub bootstrap_bind: SocketAddr,
    /// Authenticated bind address (mTLS required)
    pub authenticated_bind: SocketAddr,
    /// Network ID for this CA Node
    pub network_id: String,
    /// Rate limiting configuration
    pub rate_limit_config: RateLimitConfig,
    /// Admin SKI allowlist for admin-only endpoints
    pub admin_skis: Vec<String>,
}

/// Rate limiting configuration for bootstrap endpoints
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Burst limit (requests per window)
    pub burst_limit: u32,
    /// Sustained limit (requests per hour)
    pub sustained_limit: u32,
    /// Time window for burst limit
    pub burst_window: Duration,
    /// Time window for sustained limit
    pub sustained_window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            burst_limit: 5,
            sustained_limit: 30,
            burst_window: Duration::from_secs(60), // 1 minute
            sustained_window: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// Rate limiting entry for tracking requests
#[derive(Debug, Clone)]
struct RateLimitEntry {
    burst_count: u32,
    sustained_count: u32,
    burst_reset: SystemTime,
    sustained_reset: SystemTime,
}

/// CA Node QUIC Server
#[derive(Clone)]
pub struct CaServer {
    config: CaServerConfig,
    #[allow(dead_code)]
    ca_node: Arc<RwLock<CANode>>,
    logger: Arc<Logger>,
    #[allow(dead_code)]
    rate_limits: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    bootstrap_endpoint: Option<Arc<Endpoint>>,
    authenticated_endpoint: Option<Arc<Endpoint>>,
    admin_skis: Arc<Vec<String>>,
}

impl CaServer {
    /// Create a new CA Node QUIC Server
    pub fn new(config: CaServerConfig, ca_node: Arc<RwLock<CANode>>, logger: Arc<Logger>) -> Self {
        Self {
            config,
            ca_node,
            logger,
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            bootstrap_endpoint: None,
            authenticated_endpoint: None,
            admin_skis: Arc::new(Vec::new()),
        }
    }

    /// Start the CA Node server with both bootstrap and authenticated binds
    pub async fn start(&mut self) -> Result<()> {
        self.logger.info("Starting CA Node QUIC server");

        // Start bootstrap server (server-auth only)
        self.start_bootstrap_server().await?;
        self.logger.info(format!(
            "Bootstrap server started on {}",
            self.config.bootstrap_bind
        ));

        // Start authenticated server (mTLS required)
        self.start_authenticated_server().await?;
        self.logger.info(format!(
            "Authenticated server started on {}",
            self.config.authenticated_bind
        ));

        self.logger.info("CA Node QUIC server fully started");
        Ok(())
    }

    /// Start the bootstrap server (server-auth only)
    async fn start_bootstrap_server(&mut self) -> Result<()> {
        self.logger
            .info("Starting bootstrap QUIC server (server-auth only)");

        // For now, create a self-signed certificate for the bootstrap server
        // In real implementation, this would get the issuing CA certificate from CANode
        let (server_cert, server_key) = self.create_bootstrap_certificate().await?;

        // Build server certificate chain
        let cert_chain = vec![CertificateDer::from(server_cert.der_bytes().to_vec())];

        // Build rustls server config (server-auth only, no client auth required)
        let server_config = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                cert_chain,
                PrivateKeyDer::from(rustls_pki_types::PrivatePkcs8KeyDer::from(
                    server_key.private_key_der()?.to_vec(),
                )),
            )?;

        // Convert to Quinn server config
        let server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)?;
        let server_config = ServerConfig::with_crypto(Arc::new(server_crypto));

        // Create QUIC endpoint
        let endpoint = Endpoint::server(server_config, self.config.bootstrap_bind)?;

        // Store endpoint and start accepting connections
        let endpoint_arc = Arc::new(endpoint);
        self.bootstrap_endpoint = Some(endpoint_arc.clone());

        // Spawn connection handler
        let server = self.clone();
        tokio::spawn(async move {
            while let Some(conn) = endpoint_arc.accept().await {
                let server = server.clone();
                tokio::spawn(async move {
                    if let Err(e) = server.handle_bootstrap_connection(conn).await {
                        server
                            .logger
                            .error(format!("Bootstrap connection error: {e}"));
                    }
                });
            }
        });

        self.logger.info(format!(
            "Bootstrap server started on {}",
            self.config.bootstrap_bind
        ));
        Ok(())
    }

    /// Start the authenticated server (mTLS required)
    async fn start_authenticated_server(&mut self) -> Result<()> {
        self.logger
            .info("Starting authenticated QUIC server (mTLS required)");

        // For now, create a self-signed certificate for the authenticated server
        // In real implementation, this would get the issuing CA certificate from CANode
        let (server_cert, server_key) = self.create_authenticated_certificate().await?;

        // Build root store for client certificate validation
        let mut root_store = RootCertStore::empty();
        root_store.add(CertificateDer::from(server_cert.der_bytes().to_vec()))?;

        // Build client verifier for mTLS
        let client_verifier = WebPkiClientVerifier::builder(root_store.into()).build()?;

        // Build server certificate chain
        let cert_chain = vec![CertificateDer::from(server_cert.der_bytes().to_vec())];

        // Build rustls server config with client auth required
        let server_config = RustlsServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                cert_chain,
                PrivateKeyDer::from(rustls_pki_types::PrivatePkcs8KeyDer::from(
                    server_key.private_key_der()?.to_vec(),
                )),
            )?;

        // Convert to Quinn server config
        let server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)?;
        let server_config = ServerConfig::with_crypto(Arc::new(server_crypto));

        // Create QUIC endpoint
        let endpoint = Endpoint::server(server_config, self.config.authenticated_bind)?;

        // Store endpoint and start accepting connections
        let endpoint_arc = Arc::new(endpoint);
        self.authenticated_endpoint = Some(endpoint_arc.clone());

        // Spawn connection handler
        let server = self.clone();
        tokio::spawn(async move {
            while let Some(conn) = endpoint_arc.accept().await {
                let server = server.clone();
                tokio::spawn(async move {
                    if let Err(e) = server.handle_authenticated_connection(conn).await {
                        server
                            .logger
                            .error(format!("Authenticated connection error: {e}"));
                    }
                });
            }
        });

        self.logger.info(format!(
            "Authenticated server started on {}",
            self.config.authenticated_bind
        ));
        Ok(())
    }

    /// Configure admin SKI allowlist for admin endpoints
    pub fn configure_admin_skis(&mut self, admin_skis: Vec<String>) {
        self.admin_skis = Arc::new(admin_skis);
    }

    /// Create a self-signed certificate for bootstrap server
    async fn create_bootstrap_certificate(
        &self,
    ) -> Result<(runar_keys::X509Certificate, EcdsaKeyPair)> {
        // Create a temporary key pair and self-signed certificate for bootstrap
        let key_pair = EcdsaKeyPair::new()?;
        // For now, create a simple certificate - in real implementation this would use proper CA certificate
        let cert_der = vec![1, 2, 3, 4]; // Placeholder
        let cert = runar_keys::X509Certificate::from_der(cert_der)?;
        Ok((cert, key_pair))
    }

    /// Create a self-signed certificate for authenticated server
    async fn create_authenticated_certificate(
        &self,
    ) -> Result<(runar_keys::X509Certificate, EcdsaKeyPair)> {
        // Create a temporary key pair and self-signed certificate for authenticated server
        let key_pair = EcdsaKeyPair::new()?;
        // For now, create a simple certificate - in real implementation this would use proper CA certificate
        let cert_der = vec![5, 6, 7, 8]; // Placeholder
        let cert = runar_keys::X509Certificate::from_der(cert_der)?;
        Ok((cert, key_pair))
    }

    /// Handle bootstrap QUIC connection
    async fn handle_bootstrap_connection(&self, conn: quinn::Incoming) -> Result<()> {
        let connection = conn.await?;
        self.logger.debug("Bootstrap connection established");

        // Accept bidirectional streams
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_bootstrap_stream(send, recv).await {
                            server.logger.error(format!("Bootstrap stream error: {e}"));
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    self.logger.debug("Bootstrap connection closed by client");
                    break;
                }
                Err(e) => {
                    self.logger
                        .error(format!("Bootstrap connection error: {e}"));
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle authenticated QUIC connection
    async fn handle_authenticated_connection(&self, conn: quinn::Incoming) -> Result<()> {
        let connection = conn.await?;
        self.logger.debug("Authenticated connection established");

        // Accept bidirectional streams
        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_authenticated_stream(send, recv).await {
                            server
                                .logger
                                .error(format!("Authenticated stream error: {e}"));
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    self.logger
                        .debug("Authenticated connection closed by client");
                    break;
                }
                Err(e) => {
                    self.logger
                        .error(format!("Authenticated connection error: {e}"));
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle bootstrap stream (server-auth only)
    async fn handle_bootstrap_stream(
        &self,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> Result<()> {
        // Read request data
        let request_data = recv.read_to_end(1024 * 1024).await?;

        // Parse binary protocol header
        if request_data.len() < 8 {
            return Err(anyhow::anyhow!("Invalid message: too short"));
        }

        let message_type = u32::from_be_bytes([
            request_data[0],
            request_data[1],
            request_data[2],
            request_data[3],
        ]);
        let payload_length = u32::from_be_bytes([
            request_data[4],
            request_data[5],
            request_data[6],
            request_data[7],
        ]) as usize;

        if request_data.len() < 8 + payload_length {
            return Err(anyhow::anyhow!("Invalid message: payload length mismatch"));
        }

        let payload = &request_data[8..8 + payload_length];
        let message_type = CaMessageType::from_u32(message_type)
            .ok_or_else(|| anyhow::anyhow!("Unknown message type: 0x{:04x}", message_type))?;

        // Handle the request based on message type
        let response_data = self.handle_bootstrap_message(message_type, payload).await?;

        // Send response
        send.write_all(&response_data).await?;
        send.finish()?;

        Ok(())
    }

    /// Handle authenticated stream (mTLS)
    async fn handle_authenticated_stream(
        &self,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> Result<()> {
        // Read request data
        let request_data = recv.read_to_end(1024 * 1024).await?;

        // Parse binary protocol header
        if request_data.len() < 8 {
            return Err(anyhow::anyhow!("Invalid message: too short"));
        }

        let message_type = u32::from_be_bytes([
            request_data[0],
            request_data[1],
            request_data[2],
            request_data[3],
        ]);
        let payload_length = u32::from_be_bytes([
            request_data[4],
            request_data[5],
            request_data[6],
            request_data[7],
        ]) as usize;

        if request_data.len() < 8 + payload_length {
            return Err(anyhow::anyhow!("Invalid message: payload length mismatch"));
        }

        let payload = &request_data[8..8 + payload_length];
        let message_type = CaMessageType::from_u32(message_type)
            .ok_or_else(|| anyhow::anyhow!("Unknown message type: 0x{:04x}", message_type))?;

        // Handle the request based on message type
        let response_data = self
            .handle_authenticated_message(message_type, payload)
            .await?;

        // Send response
        send.write_all(&response_data).await?;
        send.finish()?;

        Ok(())
    }

    /// Handle enroll request (binary protocol)
    async fn handle_enroll_request_binary(
        &self,
        request: CsrEnrollRequest,
    ) -> Result<CsrEnrollResponse> {
        // Validate network_id
        if request.network_id != self.config.network_id {
            return Err(anyhow::anyhow!("Invalid network_id"));
        }

        // For now, return a placeholder response
        // In real implementation, this would call CANode methods
        Ok(CsrEnrollResponse {
            certificate_der: vec![1, 2, 3, 4],
            issuing_ca_der: vec![5, 6, 7, 8],
            root_ca_der: Some(vec![9, 10, 11, 12]),
            expires_at: 1234567890,
        })
    }

    /// Handle chain request (binary protocol)
    async fn handle_chain_request_binary(&self, request: ChainRequest) -> Result<ChainResponse> {
        // Validate network_id
        if request.network_id != self.config.network_id {
            return Err(anyhow::anyhow!("Invalid network_id"));
        }

        // For now, return a placeholder response
        Ok(ChainResponse {
            issuing_ca_der: vec![5, 6, 7, 8],
            root_ca_der: Some(vec![9, 10, 11, 12]),
        })
    }

    /// Handle renew request (binary protocol)
    async fn handle_renew_request_binary(&self, request: RenewRequest) -> Result<RenewResponse> {
        // Validate network_id
        if request.network_id != self.config.network_id {
            return Err(anyhow::anyhow!("Invalid network_id"));
        }

        // For now, return a placeholder response
        Ok(RenewResponse {
            certificate_der: vec![1, 2, 3, 4],
            issuing_ca_der: vec![5, 6, 7, 8],
            expires_at: 1234567890,
        })
    }

    /// Handle revoke request (binary protocol)
    async fn handle_revoke_request_binary(&self, request: RevokeRequest) -> Result<RevokeResponse> {
        // Validate network_id
        if request.network_id != self.config.network_id {
            return Err(anyhow::anyhow!("Invalid network_id"));
        }

        // For now, return a placeholder response
        Ok(RevokeResponse { ok: true })
    }

    /// Handle CRL request (binary protocol)
    async fn handle_crl_request_binary(&self, request: CrlRequest) -> Result<CrlResponse> {
        // Validate network_id
        if request.network_id != self.config.network_id {
            return Err(anyhow::anyhow!("Invalid network_id"));
        }

        // For now, return a placeholder response
        Ok(CrlResponse {
            network_id: request.network_id,
            issuing_ca_serial: vec![1, 2, 3, 4],
            revoked_serials: vec![],
            next_update: 1234567890,
            signature: vec![5, 6, 7, 8],
        })
    }

    /// Handle status request (binary protocol)
    async fn handle_status_request_binary(&self, request: StatusRequest) -> Result<StatusResponse> {
        // Validate network_id
        if request.network_id != self.config.network_id {
            return Err(anyhow::anyhow!("Invalid network_id"));
        }

        // For now, return a placeholder response
        Ok(StatusResponse {
            issuing_subject: "CN=Test CA".to_string(),
            issuing_serial_hex: "1234567890abcdef".to_string(),
            not_before: 1234567890,
            not_after: 1234567890 + 365 * 24 * 3600,
        })
    }

    /// Handle bootstrap message based on message type
    async fn handle_bootstrap_message(
        &self,
        message_type: CaMessageType,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        match message_type {
            CaMessageType::CsrEnrollRequest => {
                let request: CsrEnrollRequest = serde_cbor::from_slice(payload)?;
                let response = self.handle_enroll_request_binary(request).await?;
                self.create_binary_response(CaMessageType::CsrEnrollResponse, &response)
            }
            CaMessageType::ChainRequest => {
                let request: ChainRequest = serde_cbor::from_slice(payload)?;
                let response = self.handle_chain_request_binary(request).await?;
                self.create_binary_response(CaMessageType::ChainResponse, &response)
            }
            _ => {
                let error = CaErrorResponse {
                    code: "invalid_message_type".to_string(),
                    message: format!("Invalid message type for bootstrap server: {message_type:?}",),
                };
                self.create_binary_response(CaMessageType::ErrorResponse, &error)
            }
        }
    }

    /// Handle authenticated message based on message type
    async fn handle_authenticated_message(
        &self,
        message_type: CaMessageType,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        match message_type {
            CaMessageType::RenewRequest => {
                let request: RenewRequest = serde_cbor::from_slice(payload)?;
                let response = self.handle_renew_request_binary(request).await?;
                self.create_binary_response(CaMessageType::RenewResponse, &response)
            }
            CaMessageType::RevokeRequest => {
                let request: RevokeRequest = serde_cbor::from_slice(payload)?;
                let response = self.handle_revoke_request_binary(request).await?;
                self.create_binary_response(CaMessageType::RevokeResponse, &response)
            }
            CaMessageType::CrlRequest => {
                let request: CrlRequest = serde_cbor::from_slice(payload)?;
                let response = self.handle_crl_request_binary(request).await?;
                self.create_binary_response(CaMessageType::CrlResponse, &response)
            }
            CaMessageType::StatusRequest => {
                let request: StatusRequest = serde_cbor::from_slice(payload)?;
                let response = self.handle_status_request_binary(request).await?;
                self.create_binary_response(CaMessageType::StatusResponse, &response)
            }
            _ => {
                let error = CaErrorResponse {
                    code: "invalid_message_type".to_string(),
                    message: format!(
                        "Invalid message type for authenticated server: {message_type:?}",
                    ),
                };
                self.create_binary_response(CaMessageType::ErrorResponse, &error)
            }
        }
    }

    /// Create binary response with header + CBOR payload
    fn create_binary_response<T>(&self, message_type: CaMessageType, data: &T) -> Result<Vec<u8>>
    where
        T: serde::Serialize,
    {
        let payload = serde_cbor::to_vec(data)?;
        let mut response = Vec::with_capacity(8 + payload.len());

        // Add header
        response.extend_from_slice(&message_type.to_u32().to_be_bytes());
        response.extend_from_slice(&(payload.len() as u32).to_be_bytes());

        // Add payload
        response.extend_from_slice(&payload);

        Ok(response)
    }

    /// Handle bootstrap endpoint requests
    #[allow(dead_code)]
    async fn handle_bootstrap_request(
        &self,
        endpoint: &str,
        request_data: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<Vec<u8>> {
        match endpoint {
            "enroll" => self.handle_enroll_request(request_data, peer_addr).await,
            "chain" => self.handle_chain_request(request_data, peer_addr).await,
            _ => Err(anyhow::anyhow!("Unknown bootstrap endpoint: {}", endpoint)),
        }
    }

    /// Handle authenticated endpoint requests
    #[allow(dead_code)]
    async fn handle_authenticated_request(
        &self,
        endpoint: &str,
        request_data: &[u8],
        peer_addr: SocketAddr,
        peer_cert_der: &[u8],
    ) -> Result<Vec<u8>> {
        match endpoint {
            "renew" => {
                self.handle_renew_request(request_data, peer_addr, peer_cert_der)
                    .await
            }
            "revoke" => {
                self.handle_revoke_request(request_data, peer_addr, peer_cert_der)
                    .await
            }
            "crl" => {
                self.handle_crl_request(request_data, peer_addr, peer_cert_der)
                    .await
            }
            "status" => {
                self.handle_status_request(request_data, peer_addr, peer_cert_der)
                    .await
            }
            _ => Err(anyhow::anyhow!(
                "Unknown authenticated endpoint: {}",
                endpoint
            )),
        }
    }

    /// Handle enrollment request (bootstrap endpoint)
    #[allow(dead_code)]
    async fn handle_enroll_request(
        &self,
        request_data: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<Vec<u8>> {
        // Parse request
        let request: CsrEnrollRequest = serde_cbor::from_slice(request_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse enroll request: {}", e))?;

        // Check rate limiting
        let rate_key = format!("{}:{}", peer_addr, request.enrollment_token.body.token_id);
        if !self.check_rate_limit(&rate_key).await? {
            let error = CaErrorResponse {
                code: "rate_limited".to_string(),
                message: "Rate limit exceeded".to_string(),
            };
            return Ok(serde_cbor::to_vec(&error)?);
        }

        // Process enrollment via CA Node
        let response = {
            let mut ca_node = self.ca_node.write().await;
            ca_node.handle_enroll(request, &peer_addr.to_string())?
        };

        // Serialize response
        Ok(serde_cbor::to_vec(&response)?)
    }

    /// Handle chain request (bootstrap endpoint)
    #[allow(dead_code)]
    async fn handle_chain_request(
        &self,
        _request_data: &[u8],
        _peer_addr: SocketAddr,
    ) -> Result<Vec<u8>> {
        // Process chain request via CA Node
        let response = {
            let ca_node = self.ca_node.read().await;
            ca_node.handle_chain()?
        };

        // Serialize response
        Ok(serde_cbor::to_vec(&response)?)
    }

    /// Handle renewal request (authenticated endpoint)
    #[allow(dead_code)]
    async fn handle_renew_request(
        &self,
        request_data: &[u8],
        _peer_addr: SocketAddr,
        peer_cert_der: &[u8],
    ) -> Result<Vec<u8>> {
        // Parse request
        let request: RenewRequest = serde_cbor::from_slice(request_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse renew request: {}", e))?;

        // Extract peer SKI for device-based authorization
        let peer_ski = self.extract_peer_ski(peer_cert_der)?;

        // Process renewal via CA Node
        let response = {
            let mut ca_node = self.ca_node.write().await;
            ca_node.handle_renew(request, &peer_ski)?
        };

        // Serialize response
        Ok(serde_cbor::to_vec(&response)?)
    }

    /// Handle revocation request (authenticated endpoint, admin-only)
    #[allow(dead_code)]
    async fn handle_revoke_request(
        &self,
        request_data: &[u8],
        _peer_addr: SocketAddr,
        peer_cert_der: &[u8],
    ) -> Result<Vec<u8>> {
        // Parse request
        let request: RevokeRequest = serde_cbor::from_slice(request_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse revoke request: {}", e))?;

        // Extract peer SKI and check admin authorization
        let peer_ski = self.extract_peer_ski(peer_cert_der)?;
        if !self.is_admin_authorized(&peer_ski) {
            let error = CaErrorResponse {
                code: "forbidden".to_string(),
                message: "Admin SKI not authorized".to_string(),
            };
            return Ok(serde_cbor::to_vec(&error)?);
        }

        // Process revocation via CA Node
        let response = {
            let mut ca_node = self.ca_node.write().await;
            ca_node.handle_revoke(request, &peer_ski)?
        };

        // Serialize response
        Ok(serde_cbor::to_vec(&response)?)
    }

    /// Handle CRL request (authenticated endpoint)
    #[allow(dead_code)]
    async fn handle_crl_request(
        &self,
        _request_data: &[u8],
        _peer_addr: SocketAddr,
        _peer_cert_der: &[u8],
    ) -> Result<Vec<u8>> {
        // Process CRL request via CA Node
        let response = {
            let ca_node = self.ca_node.read().await;
            ca_node.handle_crl()?
        };

        // Serialize response
        Ok(serde_cbor::to_vec(&response)?)
    }

    /// Handle status request (authenticated endpoint)
    #[allow(dead_code)]
    async fn handle_status_request(
        &self,
        _request_data: &[u8],
        _peer_addr: SocketAddr,
        _peer_cert_der: &[u8],
    ) -> Result<Vec<u8>> {
        // Process status request via CA Node
        let response = {
            let ca_node = self.ca_node.read().await;
            ca_node.handle_status()?
        };

        // Serialize response
        Ok(serde_cbor::to_vec(&response)?)
    }

    /// Check rate limiting for bootstrap endpoints
    #[allow(dead_code)]
    async fn check_rate_limit(&self, rate_key: &str) -> Result<bool> {
        let now = SystemTime::now();
        let mut rate_limits = self.rate_limits.write().await;

        let entry = rate_limits
            .entry(rate_key.to_string())
            .or_insert(RateLimitEntry {
                burst_count: 0,
                sustained_count: 0,
                burst_reset: now + self.config.rate_limit_config.burst_window,
                sustained_reset: now + self.config.rate_limit_config.sustained_window,
            });

        // Reset counters if windows have expired
        if now > entry.burst_reset {
            entry.burst_count = 0;
            entry.burst_reset = now + self.config.rate_limit_config.burst_window;
        }
        if now > entry.sustained_reset {
            entry.sustained_count = 0;
            entry.sustained_reset = now + self.config.rate_limit_config.sustained_window;
        }

        // Check limits
        if entry.burst_count >= self.config.rate_limit_config.burst_limit
            || entry.sustained_count >= self.config.rate_limit_config.sustained_limit
        {
            return Ok(false);
        }

        // Increment counters
        entry.burst_count += 1;
        entry.sustained_count += 1;

        Ok(true)
    }

    /// Extract peer SKI from certificate DER
    #[allow(dead_code)]
    fn extract_peer_ski(&self, cert_der: &[u8]) -> Result<String> {
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
            .map_err(|e| anyhow::anyhow!("Failed to parse peer certificate: {}", e))?;

        let ski = cert
            .extensions()
            .iter()
            .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
            .and_then(|ext| match ext.parsed_extension() {
                x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(ski) => {
                    Some(ski.0.to_vec())
                }
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("No SKI found in peer certificate"))?;

        Ok(ski
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(""))
    }

    /// Check if peer SKI is authorized for admin operations
    #[allow(dead_code)]
    fn is_admin_authorized(&self, peer_ski: &str) -> bool {
        self.config.admin_skis.contains(&peer_ski.to_string())
    }

    /// Stop the CA Node server
    pub async fn stop(&mut self) -> Result<()> {
        self.logger.info("Stopping CA Node QUIC server");

        // TODO: Implement graceful shutdown
        // - Close QUIC listeners
        // - Wait for active connections to finish
        // - Clean up resources

        self.logger.info("CA Node QUIC server stopped");
        Ok(())
    }
}

/// CA Node QUIC Server builder
pub struct CaServerBuilder {
    config: Option<CaServerConfig>,
    ca_node: Option<Arc<RwLock<CANode>>>,
    logger: Option<Arc<Logger>>,
}

impl CaServerBuilder {
    pub fn new() -> Self {
        Self {
            config: None,
            ca_node: None,
            logger: None,
        }
    }

    pub fn with_config(mut self, config: CaServerConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_ca_node(mut self, ca_node: Arc<RwLock<CANode>>) -> Self {
        self.ca_node = Some(ca_node);
        self
    }

    pub fn with_logger(mut self, logger: Arc<Logger>) -> Self {
        self.logger = Some(logger);
        self
    }

    pub fn build(self) -> Result<CaServer> {
        let config = self
            .config
            .ok_or_else(|| anyhow::anyhow!("Config required"))?;
        let ca_node = self
            .ca_node
            .ok_or_else(|| anyhow::anyhow!("CA Node required"))?;
        let logger = self
            .logger
            .ok_or_else(|| anyhow::anyhow!("Logger required"))?;

        Ok(CaServer::new(config, ca_node, logger))
    }
}

impl Default for CaServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runar_common::logging::Component;
    use runar_keys::{
        ca_node::CANode,
        certificate::{CertificateAuthority, EcdsaKeyPair},
    };

    #[tokio::test]
    async fn test_ca_server_builder() -> Result<()> {
        let logger = Arc::new(Logger::new_root(Component::Transporter));

        // Create test CA Node
        let root_ca = CertificateAuthority::new("CN=Test Root CA,O=Test,C=US")?;
        let issuing_ca_key = EcdsaKeyPair::new()?;
        let issuing_ca_csr = runar_keys::certificate::CertificateRequest::create(
            &issuing_ca_key,
            "CN=Test Issuing CA,O=Test,C=US",
        )?;
        let issuing_ca_cert =
            root_ca.sign_ca_certificate_request_with_serial(&issuing_ca_csr, 365, Some(1))?;

        let ca_node = Arc::new(RwLock::new(CANode::new(
            issuing_ca_key,
            issuing_ca_cert,
            root_ca.ca_certificate().clone(),
            "test_network".to_string(),
        )));

        let config = CaServerConfig {
            bootstrap_bind: "127.0.0.1:0".parse()?,
            authenticated_bind: "127.0.0.1:0".parse()?,
            network_id: "test_network".to_string(),
            rate_limit_config: RateLimitConfig::default(),
            admin_skis: vec!["test_admin_ski".to_string()],
        };

        let server = CaServerBuilder::new()
            .with_config(config)
            .with_ca_node(ca_node)
            .with_logger(logger)
            .build()?;

        assert_eq!(server.config.network_id, "test_network");
        assert_eq!(server.config.admin_skis.len(), 1);
        assert_eq!(server.config.admin_skis[0], "test_admin_ski");

        Ok(())
    }

    #[tokio::test]
    async fn test_rate_limiting() -> Result<()> {
        let logger = Arc::new(Logger::new_root(Component::Transporter));
        let root_ca = CertificateAuthority::new("CN=Test Root CA,O=Test,C=US")?;
        let issuing_ca_key = EcdsaKeyPair::new()?;
        let issuing_ca_csr = runar_keys::certificate::CertificateRequest::create(
            &issuing_ca_key,
            "CN=Test CA,O=Test,C=US",
        )?;
        let issuing_ca_cert =
            root_ca.sign_ca_certificate_request_with_serial(&issuing_ca_csr, 365, Some(1))?;

        let ca_node = Arc::new(RwLock::new(CANode::new(
            issuing_ca_key,
            issuing_ca_cert,
            root_ca.ca_certificate().clone(),
            "test_network".to_string(),
        )));

        let config = CaServerConfig {
            bootstrap_bind: "127.0.0.1:0".parse()?,
            authenticated_bind: "127.0.0.1:0".parse()?,
            network_id: "test_network".to_string(),
            rate_limit_config: RateLimitConfig {
                burst_limit: 2,
                sustained_limit: 5,
                burst_window: Duration::from_secs(60),
                sustained_window: Duration::from_secs(3600),
            },
            admin_skis: vec![],
        };

        let server = CaServer::new(config, ca_node, logger);

        // Test rate limiting
        let rate_key = "127.0.0.1:test_token";

        // First two requests should pass
        assert!(server.check_rate_limit(rate_key).await?);
        assert!(server.check_rate_limit(rate_key).await?);

        // Third request should be rate limited
        assert!(!server.check_rate_limit(rate_key).await?);

        Ok(())
    }
}
