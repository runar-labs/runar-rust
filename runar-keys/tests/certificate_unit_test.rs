//! Unit tests for certificate functionality
//!
//! This module tests individual certificate methods and functionality
//! without the full E2E integration tests.

use runar_keys::{
    certificate::{CertificateAuthority, CertificateRequest, EcdsaKeyPair},
    error::Result,
};
use x509_parser::prelude::FromDer;

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
