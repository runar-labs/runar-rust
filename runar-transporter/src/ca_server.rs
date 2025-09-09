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

use crate::transport::quic_transport::{QuicTransport, QuicTransportOptions};
use anyhow::Result;
use runar_common::logging::Logger;
use runar_keys::{
    ca_node::CANode,
    ca_node_types::{CaErrorResponse, CsrEnrollRequest, RenewRequest, RevokeRequest},
};
use serde_cbor;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::RwLock;
// use tokio_rustls::TlsAcceptor; // TODO: Add when implementing actual QUIC
use x509_parser::prelude::FromDer;

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
pub struct CaServer {
    config: CaServerConfig,
    ca_node: Arc<RwLock<CANode>>,
    logger: Arc<Logger>,
    rate_limits: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    bootstrap_transport: Option<QuicTransport>,
    authenticated_transport: Option<QuicTransport>,
}

impl CaServer {
    /// Create a new CA Node QUIC Server
    pub fn new(config: CaServerConfig, ca_node: Arc<RwLock<CANode>>, logger: Arc<Logger>) -> Self {
        Self {
            config,
            ca_node,
            logger,
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            bootstrap_transport: None,
            authenticated_transport: None,
        }
    }

    /// Start the CA Node server with both bootstrap and authenticated binds
    pub async fn start(&mut self) -> Result<()> {
        self.logger.info("Starting CA Node QUIC server");

        // Start bootstrap server (server-auth only)
        self.start_bootstrap_server().await?;
        self.logger.info(&format!(
            "Bootstrap server started on {}",
            self.config.bootstrap_bind
        ));

        // Start authenticated server (mTLS required)
        self.start_authenticated_server().await?;
        self.logger.info(&format!(
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

        // TODO: Implement actual QUIC server for bootstrap endpoints
        // This would create a QUIC server that:
        // 1. Listens on bootstrap_bind
        // 2. Accepts connections without requiring client certificates
        // 3. Routes requests to handle_bootstrap_request based on endpoint
        // 4. Handles $ca/{network_id}/enroll and $ca/{network_id}/chain

        self.logger.info(&format!(
            "Bootstrap server configured for {} (QUIC implementation pending)",
            self.config.bootstrap_bind
        ));
        Ok(())
    }

    /// Start the authenticated server (mTLS required)
    async fn start_authenticated_server(&mut self) -> Result<()> {
        self.logger
            .info("Starting authenticated QUIC server (mTLS required)");

        // TODO: Implement actual QUIC server for authenticated endpoints
        // This would create a QUIC server that:
        // 1. Listens on authenticated_bind
        // 2. Requires client certificates (mTLS)
        // 3. Routes requests to handle_authenticated_request based on endpoint
        // 4. Handles $ca/{network_id}/renew, $ca/{network_id}/revoke, $ca/{network_id}/crl, $ca/{network_id}/status

        self.logger.info(&format!(
            "Authenticated server configured for {} (QUIC implementation pending)",
            self.config.authenticated_bind
        ));
        Ok(())
    }

    /// Handle bootstrap endpoint requests
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
    async fn handle_chain_request(
        &self,
        _request_data: &[u8],
        peer_addr: SocketAddr,
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
    async fn handle_renew_request(
        &self,
        request_data: &[u8],
        peer_addr: SocketAddr,
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
    async fn handle_revoke_request(
        &self,
        request_data: &[u8],
        peer_addr: SocketAddr,
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
    async fn handle_crl_request(
        &self,
        _request_data: &[u8],
        peer_addr: SocketAddr,
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
    async fn handle_status_request(
        &self,
        _request_data: &[u8],
        peer_addr: SocketAddr,
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
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(""))
    }

    /// Check if peer SKI is authorized for admin operations
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
    use std::time::SystemTime;

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
