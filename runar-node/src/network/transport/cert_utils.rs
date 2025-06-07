// Certificate Utilities
//
// This module provides utility functions for working with TLS certificates.

use anyhow::Result;
use rcgen;
use rustls::{Certificate, PrivateKey};

/// Generate a self-signed certificate for testing/development
pub fn generate_self_signed_cert() -> Result<(Certificate, PrivateKey)> {
    // Generate self-signed certificates for development/testing
    // In production, these should be replaced with proper certificates
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();
    let priv_key = PrivateKey(priv_key);
    let certificate = Certificate(cert_der);

    Ok((certificate, priv_key))
}
