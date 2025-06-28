// Certificate Utilities
//
// This module provides utility functions for working with TLS certificates.

use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;

use anyhow::Result;
use rcgen;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Generate a self-signed certificate for testing/development
pub fn generate_self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    // Generate self-signed certificates for development/testing
    // In production, these should be replaced with proper certificates
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();
    let priv_key = PrivateKeyDer::try_from(priv_key)
        .map_err(|e| anyhow::anyhow!("Failed to convert private key: {}", e))?;
    let certificate = CertificateDer::from(cert_der);

    Ok((certificate, priv_key))
}
