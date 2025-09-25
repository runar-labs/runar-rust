//! Comprehensive Runar E2E test following runar_e2e_test.md
//!
//! Phases implemented here:
//! - CA Node + QUIC servers
//! - Deep-link token generation and parsing
//! - Enrollment of 3 mobile app simulators (NodeKeyManager) via REAL QUIC
//! - Start 2 backend nodes and validate secure P2P remote action (foundation for full 4-node net)

use anyhow::Result;
use runar_keys::ca_node_types::CsrEnrollRequest;
use runar_keys::{
    ca_node::CANode,
    certificate::{CertificateAuthority, CertificateRequest, EcdsaKeyPair},
    enrollment_token::{EnrollmentToken, EnrollmentTokenBody},
    node::NodeKeyManager,
};
use runar_logging::{Component, LogLevel, Logger, LoggingConfig};
use runar_transporter::ca_client::{CaClientBuilder, CaClientConfig};
use runar_transporter::ca_server::{CaServerBuilder, CaServerConfig, RateLimitConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use tokio::time::{sleep, Duration};

// Note: P2P node bring-up lives in runar-node-tests. This transporter test focuses on CA flows.

fn setup_logging() {
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);
    logging_config.apply();
}

fn create_deep_link(token: &EnrollmentToken, ca_addr: SocketAddr, network_id: &str) -> String {
    // Minimal deep link per spec: scheme + token (CBOR hex) + CA bootstrap address + network
    let token_bytes = serde_cbor::to_vec(token).expect("Failed to serialize token to CBOR");
    let token_hex = to_hex(&token_bytes);
    format!(
        "runar://join-network?token={token_hex}&ca={ca_addr}&network={network_id}"
    )
}

fn parse_deep_link(dl: &str) -> Result<HashMap<String, String>> {
    // Very small parser for the expected format
    let parts: Vec<&str> = dl.split('?').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("invalid deep link: missing query"));
    }
    let mut map = HashMap::new();
    for pair in parts[1].split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    Ok(map)
}

fn token_from_deep_link(map: &HashMap<String, String>) -> Result<EnrollmentToken> {
    let b64 = map
        .get("token")
        .ok_or_else(|| anyhow::anyhow!("missing token in deep link"))?;
    let bytes = from_hex(b64)?;
    let token: EnrollmentToken = serde_cbor::from_slice(bytes.as_slice())
        .map_err(|e| anyhow::anyhow!(format!("Failed to parse token: {e}")))?;
    Ok(token)
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn from_hex(s: &str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(anyhow::anyhow!("hex string length must be even"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let val = |c: u8| -> Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(anyhow::anyhow!("invalid hex digit")),
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        let hi = val(bytes[i])?;
        let lo = val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

#[tokio::test]
async fn test_runar_e2e() -> Result<()> {
    setup_logging();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let logger = Arc::new(Logger::new_root(Component::Transporter));

    // === Phase 1/2: CA hierarchy + CA server (bootstrap + authenticated) ===
    let root_ca = CertificateAuthority::new("CN=E2E Root CA,O=Runar,C=US")?;
    let root_ca_cert = root_ca.ca_certificate().clone();

    let issuing_ca_key = EcdsaKeyPair::new()?;
    let issuing_ca_csr = CertificateRequest::create(&issuing_ca_key, "CN=E2E Issuing CA,O=Runar,C=US")?;
    let issuing_ca_cert = root_ca.sign_ca_certificate_request_with_serial(&issuing_ca_csr, 365, Some(42))?;

    let mut ca_node = CANode::new(
        issuing_ca_key.clone(),
        issuing_ca_cert.clone(),
        root_ca_cert.clone(),
        "e2e_network".to_string(),
        logger.clone(),
    );

    // Enrollment Authority
    let ea_key = EcdsaKeyPair::new()?;
    ca_node.configure_enrollment_authority(vec![ea_key.public_key_bytes()])?;

    let ca_node_arc = Arc::new(RwLock::new(ca_node));
    let server_logger = Arc::new(Logger::new_root(Component::Transporter));
    let server_config = CaServerConfig {
        bootstrap_bind: "127.0.0.1:0".parse()?,
        authenticated_bind: "127.0.0.1:0".parse()?,
        network_id: "e2e_network".to_string(),
        rate_limit_config: RateLimitConfig::default(),
        admin_skis: vec![],
        additional_ca_certs: vec![],
    };
    let mut ca_server = CaServerBuilder::new()
        .with_config(server_config)
        .with_ca_node(ca_node_arc.clone())
        .with_logger(server_logger)
        .build()?;
    let (bootstrap_addr, authenticated_addr) = ca_server.start().await?;
    sleep(Duration::from_millis(100)).await;

    // === Phase 3: (P2P network bring-up happens in runar-node-tests; skipped here) ===

    // === Phase 4: Create 3 mobile app simulators and enroll via deep link ===
    let mut mobile_nodes: Vec<Arc<RwLock<NodeKeyManager>>> = Vec::new();
    for i in 0..3 {
        let logger = Arc::new(Logger::new_root(Component::Keys));
        let mut nk = NodeKeyManager::new(logger)?;
        nk.generate_keys()?;

        // Enrollment token
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token_body = EnrollmentTokenBody::new(
            format!("mobile_token_{i:02}"),
            "e2e_network".to_string(),
            Some(format!("mobile_app_{i}")),
            now - 60,
            now + 3600,
            [i as u8 + 1; 16],
            vec!["enroll".to_string()],
        );
        let token = EnrollmentToken::generate(&ea_key, token_body)?;
        let deep_link = create_deep_link(&token, bootstrap_addr, "e2e_network");
        let parsed = parse_deep_link(&deep_link)?;
        let token_parsed = token_from_deep_link(&parsed)?;

        // CA client for this mobile simulator
        let client_logger = Arc::new(Logger::new_root(Component::Transporter));
        let client_config = CaClientConfig {
            bootstrap_server: bootstrap_addr,
            authenticated_server: authenticated_addr,
            network_id: "e2e_network".to_string(),
            request_timeout: Duration::from_secs(30),
            max_retries: 3,
        };
        let nk_arc = Arc::new(RwLock::new(nk));
        let ca_client = CaClientBuilder::new()
            .with_config(client_config)
            .with_node_key_manager(nk_arc.clone())
            .with_logger(client_logger)
            .build()?
            .with_root_ca_cert(root_ca_cert.der_bytes().to_vec())
            .with_issuing_ca_cert(issuing_ca_cert.der_bytes().to_vec());

        // CSR + enroll
        let csr = nk_arc.write().unwrap().generate_csr()?;
        let enroll_req = CsrEnrollRequest {
            network_id: "e2e_network".to_string(),
            csr_der: csr.csr_der,
            enrollment_token: token_parsed,
        };
        let enroll_resp = ca_client.enroll(enroll_req).await?;

        // Install certificate
        {
            // Reuse helper on MobileKeyManager in full_transport test: here we reconstruct CertificateMessage via CANode types
            // Instead, use NodeKeyManager direct install via from response helper available in MobileKeyManager
            // Create a temporary MobileKeyManager to convert responses using existing API
            use runar_keys::mobile::MobileKeyManager;
            let mlogger = Arc::new(Logger::new_root(Component::Keys));
            let mobile = MobileKeyManager::new(mlogger)?;
            // We only need conversion helpers, no user root needed
            let cert_msg = mobile.from_enroll_response(&enroll_resp)?;
            nk_arc.write().unwrap().install_certificate(cert_msg)?;
        }

        mobile_nodes.push(nk_arc);
    }

    // === Phase 5: CA flow completed; P2P validations covered by runar-node-tests ===

    Ok(())
}


