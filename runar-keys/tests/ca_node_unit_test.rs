//! Unit tests for CANode functionality
//!
//! This module tests individual CANode methods and functionality
//! without the full E2E integration tests.

use runar_keys::{
    ca_node::CANode,
    certificate::{CertificateAuthority, EcdsaKeyPair},
    error::Result,
};
use runar_logging::{Component, Logger};
use std::sync::Arc;

#[test]
fn test_ca_node_creation() -> Result<()> {
    // Create test CA
    let ca_authority = CertificateAuthority::new("CN=Test CA,O=Test,C=US")?;
    let ca_key = ca_authority.ca_key_pair().clone();
    let ca_cert = ca_authority.ca_certificate().clone();

    // Create root CA
    let root_authority = CertificateAuthority::new("CN=Test Root CA,O=Test,C=US")?;
    let root_cert = root_authority.ca_certificate().clone();

    // Create logger
    let logger = Arc::new(Logger::new_root(Component::Keys));

    let ca_node = CANode::new(
        ca_key,
        ca_cert,
        root_cert,
        "test_network".to_string(),
        logger,
    );

    assert_eq!(ca_node.network_id, "test_network");
    assert!(ca_node.enrollment_authorities.is_empty());
    assert!(ca_node.revoked_tokens.is_empty());

    Ok(())
}

#[test]
fn test_enrollment_authority_configuration() -> Result<()> {
    let ca_authority = CertificateAuthority::new("CN=Test CA,O=Test,C=US")?;
    let ca_key = ca_authority.ca_key_pair().clone();
    let ca_cert = ca_authority.ca_certificate().clone();

    let root_authority = CertificateAuthority::new("CN=Test Root CA,O=Test,C=US")?;
    let root_cert = root_authority.ca_certificate().clone();

    // Create logger
    let logger = Arc::new(Logger::new_root(Component::Keys));

    let mut ca_node = CANode::new(
        ca_key,
        ca_cert,
        root_cert,
        "test_network".to_string(),
        logger,
    );

    // Configure enrollment authority
    let ea_key = EcdsaKeyPair::new()?;
    let ea_public_key = ea_key.public_key().as_bytes().to_vec();
    let signer_id = runar_common::compact_ids::compact_id(&ea_public_key);

    ca_node.configure_enrollment_authority(vec![ea_public_key.clone()])?;

    assert_eq!(ca_node.enrollment_authorities.len(), 1);
    assert!(ca_node.enrollment_authorities.contains_key(&signer_id));
    assert_eq!(
        ca_node.enrollment_authorities.get(&signer_id).unwrap(),
        &ea_public_key
    );

    Ok(())
}

#[test]
fn test_rate_limiting() -> Result<()> {
    let ca_authority = CertificateAuthority::new("CN=Test CA,O=Test,C=US")?;
    let ca_key = ca_authority.ca_key_pair().clone();
    let ca_cert = ca_authority.ca_certificate().clone();

    let root_authority = CertificateAuthority::new("CN=Test Root CA,O=Test,C=US")?;
    let root_cert = root_authority.ca_certificate().clone();

    // Create logger
    let logger = Arc::new(Logger::new_root(Component::Keys));

    let mut ca_node = CANode::new(
        ca_key,
        ca_cert,
        root_cert,
        "test_network".to_string(),
        logger,
    );

    // Should allow initial requests (same token_id to share rate limit)
    for _ in 0..5 {
        assert!(ca_node.check_rate_limit("127.0.0.1", "test_token").is_ok());
    }

    // Should reject after burst limit
    assert!(ca_node.check_rate_limit("127.0.0.1", "test_token").is_err());

    Ok(())
}
