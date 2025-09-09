use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{Endpoint, ServerConfig};
use rustls::{RootCertStore, ServerConfig as RustlsServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde_cbor::value::to_value;
use tokio::sync::RwLock;

use runar_keys::{
    ca_node::CANode,
    ca_node_types::{
        CaErrorResponse, CaStatus, ChainResponse, CsrEnrollRequest, CsrEnrollResponse,
        RenewRequest, RenewResponse, RevokeRequest, RevokeResponse,
    },
    error::{KeyError, Result},
};

/// CA Node server configuration
#[derive(Debug)]
pub struct CaNodeServerConfig {
    /// Network ID this server serves
    pub network_id: String,
    /// Server bind address
    pub bind_addr: SocketAddr,
    /// Root CA certificate for client validation
    pub root_ca_cert: CertificateDer<'static>,
    /// Issuing CA certificate for server authentication
    pub issuing_ca_cert: CertificateDer<'static>,
    /// Issuing CA private key for server authentication
    pub issuing_ca_key: PrivateKeyDer<'static>,
    /// Transport configuration
    pub transport_config: Arc<quinn::TransportConfig>,
}

/// CA Node server implementation
pub struct CaNodeServer {
    config: CaNodeServerConfig,
    ca_node: Arc<RwLock<CANode>>,
    endpoint: Option<Endpoint>,
}

impl CaNodeServer {
    /// Create a new CA Node server
    pub fn new(config: CaNodeServerConfig, ca_node: CANode) -> Self {
        Self {
            config,
            ca_node: Arc::new(RwLock::new(ca_node)),
            endpoint: None,
        }
    }

    /// Start the CA Node server
    pub async fn start(&mut self) -> Result<()> {
        // Build root cert store for client validation
        let mut root_store = RootCertStore::empty();
        root_store
            .add(self.config.root_ca_cert.clone())
            .map_err(|e| KeyError::ValidationError(format!("Failed to add root cert: {e}")))?;

        // Build client verifier
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| {
                KeyError::ValidationError(format!("Failed to build client verifier: {e}"))
            })?;

        // Build rustls server config
        let rustls_server = RustlsServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![self.config.issuing_ca_cert.clone()],
                self.config.issuing_ca_key.clone_key(),
            )
            .map_err(|e| {
                KeyError::ValidationError(format!("Failed to build rustls server config: {e}"))
            })?;

        // Convert to Quinn server config
        use quinn::crypto::rustls::QuicServerConfig;
        let server_crypto = QuicServerConfig::try_from(rustls_server).map_err(|e| {
            KeyError::ValidationError(format!("Failed to convert to Quinn config: {e}"))
        })?;

        let mut server_config = ServerConfig::with_crypto(Arc::new(server_crypto));
        server_config.transport_config(self.config.transport_config.clone());

        // Create QUIC endpoint
        let endpoint = Endpoint::server(server_config, self.config.bind_addr).map_err(|e| {
            KeyError::ValidationError(format!("Failed to create QUIC endpoint: {e}"))
        })?;

        self.endpoint = Some(endpoint);

        // Start accepting connections
        self.accept_connections().await
    }

    /// Accept incoming connections and handle requests
    async fn accept_connections(&self) -> Result<()> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| KeyError::ValidationError("Server not started".to_string()))?;

        let ca_node = Arc::clone(&self.ca_node);

        while let Some(conn) = endpoint.accept().await {
            let ca_node = Arc::clone(&ca_node);
            let network_id = self.config.network_id.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(conn, ca_node, network_id).await {
                    eprintln!("Connection handling error: {e}");
                }
            });
        }

        Ok(())
    }

    /// Handle a single connection
    async fn handle_connection(
        conn: quinn::Incoming,
        ca_node: Arc<RwLock<CANode>>,
        network_id: String,
    ) -> Result<()> {
        let connection = conn
            .await
            .map_err(|e| KeyError::ValidationError(format!("Connection failed: {e}")))?;

        // Handle bidirectional streams
        while let Ok(stream) = connection.accept_bi().await {
            let (send, recv) = stream;

            let ca_node = Arc::clone(&ca_node);
            let network_id = network_id.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_stream(send, recv, ca_node, network_id).await {
                    eprintln!("Stream handling error: {e}");
                }
            });
        }

        Ok(())
    }

    /// Handle a single stream
    async fn handle_stream(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        ca_node: Arc<RwLock<CANode>>,
        _network_id: String,
    ) -> Result<()> {
        // Read request
        let request_data = recv
            .read_to_end(usize::MAX)
            .await
            .map_err(|e| KeyError::ValidationError(format!("Failed to read request: {e}")))?;

        // Parse request (assuming CBOR format)
        let request: serde_cbor::Value = serde_cbor::from_slice(&request_data)
            .map_err(|e| KeyError::ValidationError(format!("Failed to parse request: {e}")))?;

        // Route request based on path (simplified routing)
        let response: Result<serde_cbor::Value> = if let Some(path) = match &request {
            serde_cbor::Value::Map(map) => map
                .get(&serde_cbor::Value::Text("path".to_string()))
                .and_then(|v| match v {
                    serde_cbor::Value::Text(s) => Some(s.as_str()),
                    _ => None,
                }),
            _ => None,
        } {
            match path {
                path if path.ends_with("/enroll") => {
                    Self::handle_enroll_request(&request, &ca_node)
                        .await
                        .map(|resp| to_value(resp).unwrap())
                }
                path if path.ends_with("/chain") => Self::handle_chain_request(&ca_node)
                    .await
                    .map(|resp| to_value(resp).unwrap()),
                path if path.ends_with("/renew") => Self::handle_renew_request(&request, &ca_node)
                    .await
                    .map(|resp| to_value(resp).unwrap()),
                path if path.ends_with("/revoke") => {
                    Self::handle_revoke_request(&request, &ca_node)
                        .await
                        .map(|resp| to_value(resp).unwrap())
                }
                path if path.ends_with("/status") => Self::handle_status_request(&ca_node)
                    .await
                    .map(|resp| to_value(resp).unwrap()),
                _ => Err(KeyError::ValidationError("Unknown endpoint".to_string())),
            }
        } else {
            Err(KeyError::ValidationError(
                "Missing path in request".to_string(),
            ))
        };

        // Send response
        let response_data = match response {
            Ok(response) => serde_cbor::to_vec(&response).map_err(|e| {
                KeyError::EncodingError(format!("Failed to serialize response: {e}"))
            })?,
            Err(e) => serde_cbor::to_vec(&CaErrorResponse {
                code: "error".to_string(),
                message: e.to_string(),
            })
            .map_err(|e| KeyError::EncodingError(format!("Failed to serialize error: {e}")))?,
        };

        send.write_all(&response_data)
            .await
            .map_err(|e| KeyError::ValidationError(format!("Failed to send response: {e}")))?;
        send.finish()
            .map_err(|e| KeyError::ValidationError(format!("Failed to finish stream: {e}")))?;

        Ok(())
    }

    /// Handle enrollment request
    async fn handle_enroll_request(
        request: &serde_cbor::Value,
        ca_node: &Arc<RwLock<CANode>>,
    ) -> Result<CsrEnrollResponse> {
        let enroll_request: CsrEnrollRequest =
            serde_cbor::from_slice(&serde_cbor::to_vec(request).map_err(|e| {
                KeyError::ValidationError(format!("Failed to serialize request: {e}"))
            })?)
            .map_err(|e| KeyError::ValidationError(format!("Invalid enroll request: {e}")))?;

        let mut ca_node = ca_node.write().await;
        let remote_addr = "127.0.0.1"; // TODO: Extract from connection context
        ca_node.handle_enroll(enroll_request, remote_addr)
    }

    /// Handle chain request
    async fn handle_chain_request(ca_node: &Arc<RwLock<CANode>>) -> Result<ChainResponse> {
        let ca_node = ca_node.read().await;
        ca_node.handle_chain()
    }

    /// Handle renew request
    async fn handle_renew_request(
        request: &serde_cbor::Value,
        ca_node: &Arc<RwLock<CANode>>,
    ) -> Result<RenewResponse> {
        let renew_request: RenewRequest =
            serde_cbor::from_slice(&serde_cbor::to_vec(request).map_err(|e| {
                KeyError::ValidationError(format!("Failed to serialize request: {e}"))
            })?)
            .map_err(|e| KeyError::ValidationError(format!("Invalid renew request: {e}")))?;

        let mut ca_node = ca_node.write().await;
        let peer_ski = "admin_ski"; // TODO: Extract from mTLS peer certificate
        ca_node.handle_renew(renew_request, peer_ski)
    }

    /// Handle revoke request
    async fn handle_revoke_request(
        request: &serde_cbor::Value,
        ca_node: &Arc<RwLock<CANode>>,
    ) -> Result<RevokeResponse> {
        let revoke_request: RevokeRequest =
            serde_cbor::from_slice(&serde_cbor::to_vec(request).map_err(|e| {
                KeyError::ValidationError(format!("Failed to serialize request: {e}"))
            })?)
            .map_err(|e| KeyError::ValidationError(format!("Invalid revoke request: {e}")))?;

        let mut ca_node = ca_node.write().await;
        let peer_ski = "admin_ski"; // TODO: Extract from mTLS peer certificate
        ca_node.handle_revoke(revoke_request, peer_ski)
    }

    /// Handle status request
    async fn handle_status_request(ca_node: &Arc<RwLock<CANode>>) -> Result<CaStatus> {
        let ca_node = ca_node.read().await;
        ca_node.handle_status()
    }

    /// Stop the server
    pub fn stop(&mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(0u32.into(), b"Server shutdown");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runar_keys::certificate::CertificateAuthority;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_ca_node_server_creation() -> Result<()> {
        // Create test CA
        let ca_authority = CertificateAuthority::new("CN=Test CA,O=Test,C=US")?;
        let ca_key = ca_authority.ca_key_pair().clone();
        let ca_cert = ca_authority.ca_certificate().clone();

        // Create root CA
        let root_authority = CertificateAuthority::new("CN=Test Root CA,O=Test,C=US")?;
        let root_cert = root_authority.ca_certificate().clone();

        // Create CA Node
        let ca_node = CANode::new(
            ca_key.clone(),
            ca_cert.clone(),
            root_cert.clone(),
            "test_network".to_string(),
        );

        // Create server config
        let config = CaNodeServerConfig {
            network_id: "test_network".to_string(),
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            root_ca_cert: CertificateDer::from(root_cert.der_bytes().to_vec()),
            issuing_ca_cert: CertificateDer::from(ca_cert.der_bytes().to_vec()),
            issuing_ca_key: ca_key.to_rustls_private_key()?,
            transport_config: Arc::new(quinn::TransportConfig::default()),
        };

        // Create server
        let server = CaNodeServer::new(config, ca_node);
        assert_eq!(server.config.network_id, "test_network");

        Ok(())
    }
}
