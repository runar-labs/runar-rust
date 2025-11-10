//! Unit tests for certificate functionality
//!
//! This module tests individual certificate methods and functionality
//! without the full E2E integration tests.

use runar_keys::{
    certificate::{CertificateAuthority, CertificateRequest, EcdsaKeyPair, X509Certificate},
    error::Result,
};
use x509_parser::prelude::FromDer;

/// Helper function to check if a certificate is a CA
fn is_ca_certificate(cert: &X509Certificate) -> bool {
    let parsed = match cert.parsed() {
        Ok(p) => p,
        Err(_) => return false,
    };

    for ext in parsed.extensions() {
        if ext.oid == x509_parser::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS {
            if let x509_parser::extensions::ParsedExtension::BasicConstraints(bc) =
                ext.parsed_extension()
            {
                return bc.ca;
            }
        }
    }
    false
}

#[test]
fn test_ca_certificate_signing() -> Result<()> {
    // Create root CA
    let root_ca = CertificateAuthority::new("CN=Test Root CA,O=Test,C=US")?;

    // Create issuing CA key pair
    let issuing_ca_key = EcdsaKeyPair::new()?;

    // Generate CSR for issuing CA using the existing method
    let issuing_ca_csr =
        CertificateRequest::create(&issuing_ca_key, "CN=Test Issuing CA,O=Test,C=US")?;

    // Sign the issuing CA certificate
    let issuing_ca_cert = root_ca.sign_ca_certificate_request_with_serial(
        &issuing_ca_csr,
        365,         // 1 year validity
        Some(12345), // specific serial number
    )?;

    // Verify the certificate was created
    assert!(!issuing_ca_cert.der_bytes().is_empty());

    // Parse and verify the certificate extensions
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(
        issuing_ca_cert.der_bytes(),
    )
    .map_err(|e| {
        runar_keys::error::KeyError::CertificateError(format!(
            "Failed to parse issued CA cert: {e}"
        ))
    })?;

    // Check BasicConstraints
    let mut has_basic_constraints = false;
    let mut is_ca = false;
    for ext in cert.extensions() {
        if ext.oid == x509_parser::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS {
            has_basic_constraints = true;
            if let x509_parser::extensions::ParsedExtension::BasicConstraints(bc) =
                ext.parsed_extension()
            {
                is_ca = bc.ca;
            }
            break;
        }
    }
    assert!(
        has_basic_constraints,
        "CA certificate should have BasicConstraints extension"
    );
    assert!(is_ca, "CA certificate should have CA=true");

    // Check KeyUsage
    let mut has_key_usage = false;
    let mut has_key_cert_sign = false;
    let mut has_crl_sign = false;
    for ext in cert.extensions() {
        if ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE {
            has_key_usage = true;
            if let x509_parser::extensions::ParsedExtension::KeyUsage(ku) = ext.parsed_extension() {
                has_key_cert_sign = ku.key_cert_sign();
                has_crl_sign = ku.crl_sign();
            }
            break;
        }
    }
    assert!(
        has_key_usage,
        "CA certificate should have KeyUsage extension"
    );
    assert!(has_key_cert_sign, "CA certificate should have keyCertSign");
    assert!(has_crl_sign, "CA certificate should have cRLSign");

    Ok(())
}

#[test]
fn test_certificate_authority_from_existing_happy_path() {
    println!("🧪 Testing CertificateAuthority::from_existing() happy path");

    // Create a root CA first to get a valid key pair and certificate
    let root_ca =
        CertificateAuthority::new("CN=Root CA,O=Test,C=US").expect("Failed to create root CA");
    let root_cert = root_ca.ca_certificate().clone();
    let root_key_pair = root_ca.ca_key_pair().clone();

    // Create a CA from existing key pair and certificate
    let ca_from_existing =
        CertificateAuthority::from_existing(root_key_pair.clone(), root_cert.clone());

    // Verify the CA was created correctly
    let cert = ca_from_existing.ca_certificate();
    assert_eq!(cert.subject(), root_cert.subject());
    assert_eq!(cert.issuer(), root_cert.issuer());
    assert_eq!(cert.der_bytes(), root_cert.der_bytes());

    // Verify the key pair matches
    assert_eq!(
        ca_from_existing.ca_key_pair().public_key(),
        root_key_pair.public_key()
    );

    // Verify the CA can perform operations (signing)
    let test_csr = CertificateRequest::create(&root_key_pair, "CN=Test Node,O=Test,C=US")
        .expect("Failed to create test CSR");
    let signed_cert = ca_from_existing
        .sign_ca_certificate_request_with_serial(&test_csr, 365, Some(12345))
        .expect("Failed to sign certificate");

    assert!(is_ca_certificate(&signed_cert));
    assert!(signed_cert.subject().contains("CN=Test Node"));
    assert!(signed_cert.issuer().contains("CN=Root CA"));

    println!("   ✅ CertificateAuthority::from_existing() happy path test passed");
}

#[test]
fn test_certificate_authority_from_existing_mismatched_key_cert() {
    println!("🧪 Testing CertificateAuthority::from_existing() with mismatched key/cert");

    // Create two different CAs
    let ca1 = CertificateAuthority::new("CN=CA1,O=Test,C=US").expect("Failed to create CA1");
    let ca2 = CertificateAuthority::new("CN=CA2,O=Test,C=US").expect("Failed to create CA2");

    // Get key pair from CA1 and certificate from CA2 (mismatched)
    let ca1_key_pair = ca1.ca_key_pair().clone();
    let ca2_cert = ca2.ca_certificate().clone();

    // Create CA from mismatched key pair and certificate
    let ca_from_existing =
        CertificateAuthority::from_existing(ca1_key_pair.clone(), ca2_cert.clone());

    // The CA should be created (from_existing doesn't validate the match)
    // and subsequent operations should work (the key pair is used for signing, not the certificate)
    let test_csr = CertificateRequest::create(&ca1_key_pair, "CN=Test Node,O=Test,C=US")
        .expect("Failed to create test CSR");

    // Signing should work because we're using the correct key pair for signing
    let sign_result =
        ca_from_existing.sign_ca_certificate_request_with_serial(&test_csr, 365, Some(12345));
    assert!(
        sign_result.is_ok(),
        "Signing should work with correct key pair"
    );

    let signed_cert = sign_result.expect("Failed to sign certificate");
    assert!(signed_cert.subject().contains("CN=Test Node"));
    // The issuer will be from the certificate (CA2), not the key pair (CA1)
    assert!(signed_cert.issuer().contains("CN=CA2"));

    println!("   ✅ CertificateAuthority::from_existing() mismatched key/cert test passed");
}

#[test]
fn test_certificate_authority_from_existing_issuing_ca_workflow() {
    println!("🧪 Testing CertificateAuthority::from_existing() in issuing CA workflow");

    // Create root CA
    let root_ca =
        CertificateAuthority::new("CN=Root CA,O=Test,C=US").expect("Failed to create root CA");

    // Create issuing CA key pair
    let issuing_ca_key = EcdsaKeyPair::new().expect("Failed to create issuing CA key");

    // Create CSR for issuing CA
    let issuing_ca_csr = CertificateRequest::create(&issuing_ca_key, "CN=Issuing CA,O=Test,C=US")
        .expect("Failed to create issuing CA CSR");

    // Sign the issuing CA certificate with root CA
    let issuing_ca_cert = root_ca
        .sign_ca_certificate_request_with_serial(&issuing_ca_csr, 365, Some(12345))
        .expect("Failed to sign issuing CA certificate");

    // Create issuing CA from existing key pair and certificate
    let issuing_ca =
        CertificateAuthority::from_existing(issuing_ca_key.clone(), issuing_ca_cert.clone());

    // Verify the issuing CA was created correctly
    let cert = issuing_ca.ca_certificate();
    assert!(cert.subject().contains("CN=Issuing CA"));
    assert!(cert.issuer().contains("CN=Root CA"));
    assert!(is_ca_certificate(cert));

    // Verify the issuing CA can sign certificates
    let node_key = EcdsaKeyPair::new().expect("Failed to create node key");
    let node_csr = CertificateRequest::create(&node_key, "CN=Test Node,O=Test,C=US")
        .expect("Failed to create node CSR");

    // Use sign_certificate_request_with_serial for leaf certificates (not CA certificates)
    let node_cert = issuing_ca
        .sign_certificate_request_with_serial(&node_csr, 30, Some(54321))
        .expect("Failed to sign node certificate");

    assert!(node_cert.subject().contains("CN=Test Node"));
    assert!(node_cert.issuer().contains("CN=Issuing CA"));
    assert!(!is_ca_certificate(&node_cert)); // Node certificate should not be a CA

    println!("   ✅ CertificateAuthority::from_existing() issuing CA workflow test passed");
}
