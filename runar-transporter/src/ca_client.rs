//! CA Node QUIC Client Implementation
//!
//! This module implements a QUIC client for CA Node operations, used by both
//! mobile apps and backend nodes to interact with CA Node servers.
//!
//! The client handles:
//! - Bootstrap operations (enrollment, chain fetch) with server-auth only
//! - Authenticated operations (renewal, revocation, CRL, status) with mTLS
//! - CBOR request/response serialization over QUIC
//! - Certificate management and mTLS authentication

use crate::ca_server::CaMessageType;
use anyhow::Result;
use quinn::{ClientConfig, Endpoint};
use runar_common::logging::Logger;
use runar_keys::{
    ca_node_types::{
        CaStatus, ChainResponse, CsrEnrollRequest, CsrEnrollResponse, RenewRequest, RenewResponse,
        RevokeRequest, RevokeResponse,
    },
    node::NodeKeyManager,
};
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;
use serde_cbor;
use std::{net::SocketAddr, sync::Arc, time::Duration};

/// CA Node QUIC Client configuration
#[derive(Debug, Clone)]
pub struct CaClientConfig {
    /// CA Node bootstrap server address (server-auth only)
    pub bootstrap_server: SocketAddr,
    /// CA Node authenticated server address (mTLS required)
    pub authenticated_server: SocketAddr,
    /// Network ID for this client
    pub network_id: String,
    /// Request timeout
    pub request_timeout: Duration,
    /// Maximum retry attempts
    pub max_retries: u32,
}

impl Default for CaClientConfig {
    fn default() -> Self {
        Self {
            bootstrap_server: "127.0.0.1:8443".parse().unwrap(),
            authenticated_server: "127.0.0.1:8444".parse().unwrap(),
            network_id: "default_network".to_string(),
            request_timeout: Duration::from_secs(30),
            max_retries: 3,
        }
    }
}

/// CA Node QUIC Client
pub struct CaClient {
    config: CaClientConfig,
    logger: Arc<Logger>,
    node_key_manager: Option<Arc<std::sync::RwLock<NodeKeyManager>>>,
    root_ca_cert: Option<Vec<u8>>,
    issuing_ca_cert: Option<Vec<u8>>,
}

impl CaClient {
    /// Create a new CA Node QUIC Client
    pub fn new(config: CaClientConfig, logger: Arc<Logger>) -> Self {
        Self {
            config,
            logger,
            node_key_manager: None,
            root_ca_cert: None,
            issuing_ca_cert: None,
        }
    }

    /// Set the node key manager for mTLS operations
    pub fn with_node_key_manager(
        mut self,
        node_key_manager: Arc<std::sync::RwLock<NodeKeyManager>>,
    ) -> Self {
        self.node_key_manager = Some(node_key_manager);
        self
    }

    /// Set the root CA certificate for server certificate validation
    pub fn with_root_ca_cert(mut self, root_ca_cert: Vec<u8>) -> Self {
        self.root_ca_cert = Some(root_ca_cert);
        self
    }

    /// Set the issuing CA certificate for server certificate validation
    pub fn with_issuing_ca_cert(mut self, issuing_ca_cert: Vec<u8>) -> Self {
        self.issuing_ca_cert = Some(issuing_ca_cert);
        self
    }

    /// Get message type for a request
    fn get_message_type_for_request<T>(&self, _request: &T) -> Result<CaMessageType> {
        // For now, we'll determine the message type based on the request type
        // This is a simplified approach - in a real implementation, we'd use generics or traits
        Ok(CaMessageType::CsrEnrollRequest)
    }

    /// Enroll a new device (bootstrap operation)
    pub async fn enroll(&self, request: CsrEnrollRequest) -> Result<CsrEnrollResponse> {
        let endpoint = format!("$ca/{}/enroll", self.config.network_id);
        let response_data = self.send_bootstrap_request(&endpoint, &request).await?;

        let response: CsrEnrollResponse = serde_cbor::from_slice(&response_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse enroll response: {}", e))?;

        Ok(response)
    }

    /// Fetch certificate chain (bootstrap operation)
    pub async fn fetch_chain(&self) -> Result<ChainResponse> {
        let endpoint = format!("$ca/{}/chain", self.config.network_id);
        let request_data = serde_cbor::to_vec(&serde_json::Value::Object(serde_json::Map::new()))?;
        let response_data = self
            .send_bootstrap_request(&endpoint, &request_data)
            .await?;

        let response: ChainResponse = serde_cbor::from_slice(&response_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse chain response: {}", e))?;

        Ok(response)
    }

    /// Renew device certificate (authenticated operation)
    pub async fn renew(&self, request: RenewRequest) -> Result<RenewResponse> {
        let endpoint = format!("$ca/{}/renew", self.config.network_id);
        let response_data = self.send_authenticated_request(&endpoint, &request).await?;

        let response: RenewResponse = serde_cbor::from_slice(&response_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse renew response: {}", e))?;

        Ok(response)
    }

    /// Revoke device certificate (authenticated operation, admin-only)
    pub async fn revoke(&self, request: RevokeRequest) -> Result<RevokeResponse> {
        let endpoint = format!("$ca/{}/revoke", self.config.network_id);
        let response_data = self.send_authenticated_request(&endpoint, &request).await?;

        let response: RevokeResponse = serde_cbor::from_slice(&response_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse revoke response: {}", e))?;

        Ok(response)
    }

    /// Fetch CRL (authenticated operation)
    pub async fn fetch_crl(&self) -> Result<runar_keys::ca_node_types::CaRevocationList> {
        let endpoint = format!("$ca/{}/crl", self.config.network_id);
        let request_data = serde_cbor::to_vec(&serde_json::Value::Object(serde_json::Map::new()))?;
        let response_data = self
            .send_authenticated_request(&endpoint, &request_data)
            .await?;

        let response: runar_keys::ca_node_types::CaRevocationList =
            serde_cbor::from_slice(&response_data)
                .map_err(|e| anyhow::anyhow!("Failed to parse CRL response: {}", e))?;

        Ok(response)
    }

    /// Get CA status (authenticated operation)
    pub async fn get_status(&self) -> Result<CaStatus> {
        let endpoint = format!("$ca/{}/status", self.config.network_id);
        let request_data = serde_cbor::to_vec(&serde_json::Value::Object(serde_json::Map::new()))?;
        let response_data = self
            .send_authenticated_request(&endpoint, &request_data)
            .await?;

        let response: CaStatus = serde_cbor::from_slice(&response_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse status response: {}", e))?;

        Ok(response)
    }

    /// Send a bootstrap request (server-auth only)
    async fn send_bootstrap_request<T>(&self, endpoint: &str, request: &T) -> Result<Vec<u8>>
    where
        T: serde::Serialize,
    {
        let payload = serde_cbor::to_vec(request)?;

        // Create binary protocol message with header
        let mut request_data = Vec::with_capacity(8 + payload.len());

        // Add header (message type + payload length)
        let message_type = self.get_message_type_for_request(request)?;
        request_data.extend_from_slice(&message_type.to_u32().to_be_bytes());
        request_data.extend_from_slice(&(payload.len() as u32).to_be_bytes());

        // Add payload
        request_data.extend_from_slice(&payload);

        self.logger.debug(format!(
            "Sending bootstrap request to {}: {} bytes (header: 8, payload: {})",
            endpoint,
            request_data.len(),
            payload.len()
        ));

        // Build root store for server certificate validation
        let mut root_store = RootCertStore::empty();
        // Add the root CA certificate to the trust store
        if let Some(root_ca_cert) = &self.root_ca_cert {
            if let Err(e) = root_store.add(CertificateDer::from(root_ca_cert.clone())) {
                self.logger.warn(format!(
                    "Failed to add root CA certificate to root store: {e}"
                ));
            }
        }
        // Add the issuing CA certificate to the trust store
        if let Some(issuing_ca_cert) = &self.issuing_ca_cert {
            if let Err(e) = root_store.add(CertificateDer::from(issuing_ca_cert.clone())) {
                self.logger.warn(format!(
                    "Failed to add issuing CA certificate to root store: {e}"
                ));
            }
        }

        // Build rustls client config (server-auth only, no client cert)
        let client_config = RustlsClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Convert to Quinn client config
        let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_config)?;
        let client_config = ClientConfig::new(Arc::new(client_crypto));

        // Create QUIC endpoint
        let mut endpoint = Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))?;
        endpoint.set_default_client_config(client_config);

        // Connect to bootstrap server
        let connection = endpoint
            .connect(self.config.bootstrap_server, "ca-node")?
            .await?;

        // Open bidirectional stream
        let (mut send, mut recv) = connection.open_bi().await?;

        // Send request
        send.write_all(&request_data).await?;
        send.finish()?;

        // Read response
        let response_data = recv.read_to_end(1024 * 1024).await?;

        self.logger.debug(format!(
            "Received bootstrap response: {} bytes",
            response_data.len()
        ));

        // Parse binary protocol response
        if response_data.len() < 8 {
            return Err(anyhow::anyhow!("Invalid response: too short"));
        }

        let response_message_type = u32::from_be_bytes([
            response_data[0],
            response_data[1],
            response_data[2],
            response_data[3],
        ]);
        let response_payload_length = u32::from_be_bytes([
            response_data[4],
            response_data[5],
            response_data[6],
            response_data[7],
        ]) as usize;

        if response_data.len() < 8 + response_payload_length {
            return Err(anyhow::anyhow!("Invalid response: payload length mismatch"));
        }

        let response_payload = &response_data[8..8 + response_payload_length];
        Ok(response_payload.to_vec())
    }

    /// Send an authenticated request (mTLS required)
    async fn send_authenticated_request<T>(&self, endpoint: &str, request: &T) -> Result<Vec<u8>>
    where
        T: serde::Serialize,
    {
        let request_data = serde_cbor::to_vec(request)?;

        // Check if we have a node key manager for mTLS
        let node_key_manager = self.node_key_manager.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Node key manager required for authenticated requests")
        })?;

        self.logger.debug(format!(
            "Sending authenticated request to {}: {} bytes",
            endpoint,
            request_data.len()
        ));

        // Get client certificate from node key manager
        let cert_config = node_key_manager
            .read()
            .unwrap()
            .get_quic_certificate_config()?;
        let certificate_chain: Vec<CertificateDer> =
            cert_config.certificate_chain.into_iter().collect();
        let private_key = cert_config.private_key;

        // Build root store for server certificate validation
        let mut root_store = RootCertStore::empty();
        // Add the root CA certificate to the trust store
        if let Some(root_ca_cert) = &self.root_ca_cert {
            if let Err(e) = root_store.add(CertificateDer::from(root_ca_cert.clone())) {
                self.logger.warn(format!(
                    "Failed to add root CA certificate to root store: {e}"
                ));
            }
        }
        // Add the issuing CA certificate to the trust store
        if let Some(issuing_ca_cert) = &self.issuing_ca_cert {
            if let Err(e) = root_store.add(CertificateDer::from(issuing_ca_cert.clone())) {
                self.logger.warn(format!(
                    "Failed to add issuing CA certificate to root store: {e}"
                ));
            } else {
                self.logger.debug("Successfully added issuing CA certificate to root store for authenticated request");
            }
        }

        // Build rustls client config with client auth
        let client_config = RustlsClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certificate_chain, private_key)?;

        // Convert to Quinn client config
        let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_config)?;
        let client_config = ClientConfig::new(Arc::new(client_crypto));

        // Create QUIC endpoint
        let mut endpoint = Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))?;
        endpoint.set_default_client_config(client_config);

        // Connect to authenticated server
        let connection = endpoint
            .connect(self.config.authenticated_server, "ca-node")?
            .await?;

        // Open bidirectional stream
        let (mut send, mut recv) = connection.open_bi().await?;

        // Send request
        send.write_all(&request_data).await?;
        send.finish()?;

        // Read response
        let response_data = recv.read_to_end(1024 * 1024).await?;

        self.logger.debug(format!(
            "Received authenticated response: {} bytes",
            response_data.len()
        ));

        Ok(response_data)
    }

    /// Get the network ID for this client
    pub fn network_id(&self) -> &str {
        &self.config.network_id
    }

    /// Update the network ID
    pub fn set_network_id(&mut self, network_id: String) {
        self.config.network_id = network_id;
    }

    /// Get the bootstrap server address
    pub fn bootstrap_server(&self) -> SocketAddr {
        self.config.bootstrap_server
    }

    /// Get the authenticated server address
    pub fn authenticated_server(&self) -> SocketAddr {
        self.config.authenticated_server
    }
}

/// CA Node QUIC Client builder
pub struct CaClientBuilder {
    config: Option<CaClientConfig>,
    logger: Option<Arc<Logger>>,
    node_key_manager: Option<Arc<std::sync::RwLock<NodeKeyManager>>>,
}

impl CaClientBuilder {
    pub fn new() -> Self {
        Self {
            config: None,
            logger: None,
            node_key_manager: None,
        }
    }

    pub fn with_config(mut self, config: CaClientConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_logger(mut self, logger: Arc<Logger>) -> Self {
        self.logger = Some(logger);
        self
    }

    pub fn with_node_key_manager(
        mut self,
        node_key_manager: Arc<std::sync::RwLock<NodeKeyManager>>,
    ) -> Self {
        self.node_key_manager = Some(node_key_manager);
        self
    }

    pub fn build(self) -> Result<CaClient> {
        let config = self.config.unwrap_or_default();
        let logger = self
            .logger
            .ok_or_else(|| anyhow::anyhow!("Logger required"))?;

        let mut client = CaClient::new(config, logger);
        if let Some(node_key_manager) = self.node_key_manager {
            client = client.with_node_key_manager(node_key_manager);
        }

        Ok(client)
    }
}

impl Default for CaClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience methods for common CA operations
impl CaClient {
    /// Complete enrollment flow for a new device
    pub async fn complete_enrollment(
        &self,
        csr_der: Vec<u8>,
        enrollment_token: runar_keys::enrollment_token::EnrollmentToken,
    ) -> Result<CsrEnrollResponse> {
        let request = CsrEnrollRequest {
            network_id: self.config.network_id.clone(),
            csr_der,
            enrollment_token,
        };

        self.enroll(request).await
    }

    /// Complete renewal flow for an existing device
    pub async fn complete_renewal(&self, csr_der: Vec<u8>) -> Result<RenewResponse> {
        let request = RenewRequest {
            network_id: self.config.network_id.clone(),
            csr_der,
        };
        self.renew(request).await
    }

    /// Complete revocation flow for a device certificate
    pub async fn complete_revocation(
        &self,
        certificate_serial: Vec<u8>,
        reason: String,
    ) -> Result<RevokeResponse> {
        let request = RevokeRequest {
            network_id: self.config.network_id.clone(),
            certificate_serial,
            reason,
        };
        self.revoke(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runar_common::logging::Component;
    use runar_keys::{
        enrollment_token::{EnrollmentToken, EnrollmentTokenBody},
        node::NodeKeyManager,
    };
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_ca_client_builder() -> Result<()> {
        let logger = Arc::new(Logger::new_root(Component::Transporter));

        let config = CaClientConfig {
            bootstrap_server: "127.0.0.1:8443".parse()?,
            authenticated_server: "127.0.0.1:8444".parse()?,
            network_id: "test_network".to_string(),
            request_timeout: Duration::from_secs(30),
            max_retries: 3,
        };

        let client = CaClientBuilder::new()
            .with_config(config)
            .with_logger(logger)
            .build()?;

        assert_eq!(client.network_id(), "test_network");
        assert_eq!(client.bootstrap_server().port(), 8443);
        assert_eq!(client.authenticated_server().port(), 8444);

        Ok(())
    }

    #[tokio::test]
    async fn test_ca_client_with_node_key_manager() -> Result<()> {
        let logger = Arc::new(Logger::new_root(Component::Transporter));
        let mut node_key_manager = NodeKeyManager::new(logger.clone())?;
        node_key_manager.generate_keys()?;
        let node_key_manager = Arc::new(std::sync::RwLock::new(node_key_manager));

        let client = CaClientBuilder::new()
            .with_logger(logger)
            .with_node_key_manager(node_key_manager)
            .build()?;

        // Client should have node key manager set
        assert!(client.node_key_manager.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_ca_client_network_id_update() -> Result<()> {
        let logger = Arc::new(Logger::new_root(Component::Transporter));
        let mut client = CaClient::new(CaClientConfig::default(), logger);

        assert_eq!(client.network_id(), "default_network");

        client.set_network_id("updated_network".to_string());
        assert_eq!(client.network_id(), "updated_network");

        Ok(())
    }

    #[tokio::test]
    async fn test_ca_client_convenience_methods() -> Result<()> {
        // Install default crypto provider
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .map_err(|e| anyhow::anyhow!("Failed to install crypto provider: {:?}", e))?;
        let logger = Arc::new(Logger::new_root(Component::Transporter));
        let client = CaClient::new(CaClientConfig::default(), logger);

        // Test that convenience methods exist and return appropriate errors
        // (since QUIC client is not yet implemented)

        let csr_der = vec![1, 2, 3, 4, 5];
        let enrollment_token = EnrollmentToken {
            body: EnrollmentTokenBody::new(
                "test_token".to_string(),
                "test_network".to_string(),
                Some("test_subject".to_string()),
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600,
                [0; 16],
                vec!["enroll".to_string()],
            ),
            signature: vec![0; 64],
            signer_id: "test_signer".to_string(),
        };

        // These should fail with "not yet implemented" errors
        assert!(client
            .complete_enrollment(csr_der, enrollment_token)
            .await
            .is_err());
        assert!(client.complete_renewal(vec![1, 2, 3]).await.is_err());
        assert!(client
            .complete_revocation(vec![1, 2, 3], "test".to_string())
            .await
            .is_err());

        Ok(())
    }
}
