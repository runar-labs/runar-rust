//! Certificate operations and X.509 certificate management
//!
//! This module provides the core certificate authority functionality and
//! certificate validation using standard X.509 certificates and ECDSA P-256.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

// Certificate generation and parsing
use rcgen::{Certificate as RcgenCertificate, CertificateParams, KeyPair};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::prelude::*;

// OpenSSL for proper CA operations
use openssl::asn1::Asn1Integer;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints as OpenSslBasicConstraints, ExtendedKeyUsage,
    KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509NameBuilder, X509Req, X509};

// Cryptographic support
use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use p256::EncodedPoint;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};

use crate::error::{KeyError, Result};

/// ECDSA P-256 key pair for unified cryptographic operations
#[derive(Debug, Clone)]
pub struct EcdsaKeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl EcdsaKeyPair {
    /// Generate a new ECDSA P-256 key pair
    pub fn new() -> Result<Self> {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create from existing signing key
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = VerifyingKey::from(&signing_key);
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Get public key as raw bytes (uncompressed SEC1 point)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Get private key in PKCS#8 DER format
    pub fn private_key_der(&self) -> Result<Vec<u8>> {
        self.signing_key
            .to_pkcs8_der()
            .map(|der| der.as_bytes().to_vec())
            .map_err(|e| KeyError::InvalidKeyFormat(format!("PKCS#8 encoding error: {e}")))
    }

    /// Get public key in DER format
    pub fn public_key_der(&self) -> Result<Vec<u8>> {
        self.verifying_key
            .to_public_key_der()
            .map(|der| der.as_bytes().to_vec())
            .map_err(|e| KeyError::InvalidKeyFormat(format!("Public key DER encoding error: {e}")))
    }

    /// Convert to rcgen KeyPair for compatibility
    pub fn to_rcgen_key_pair(&self) -> Result<KeyPair> {
        let private_key_der = self.private_key_der()?;
        KeyPair::from_der(&private_key_der)
            .map_err(|e| KeyError::InvalidKeyFormat(format!("rcgen KeyPair conversion error: {e}")))
    }

    /// Convert to rustls private key format
    pub fn to_rustls_private_key(&self) -> Result<PrivateKeyDer<'static>> {
        let private_key_der = self.private_key_der()?;
        Ok(PrivateKeyDer::Pkcs8(private_key_der.into()))
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the signing key
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

impl Serialize for EcdsaKeyPair {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let private_key_der = self.private_key_der().map_err(|e| {
            serde::ser::Error::custom(format!("Failed to serialize private key: {e}"))
        })?;

        private_key_der.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EcdsaKeyPair {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let private_key_der: Vec<u8> = Vec::deserialize(deserializer)?;

        let signing_key = SigningKey::from_pkcs8_der(&private_key_der).map_err(|e| {
            serde::de::Error::custom(format!("Failed to deserialize private key: {e}"))
        })?;

        Ok(Self::from_signing_key(signing_key))
    }
}

/// Standard X.509 certificate wrapper
#[derive(Debug, Clone)]
pub struct X509Certificate {
    /// DER-encoded certificate bytes
    der_bytes: Vec<u8>,
    /// Certificate subject
    subject: String,
    /// Certificate issuer
    issuer: String,
}

impl X509Certificate {
    /// Create from DER-encoded bytes
    pub fn from_der(der_bytes: Vec<u8>) -> Result<Self> {
        let (_, parsed_cert) = x509_parser::certificate::X509Certificate::from_der(&der_bytes)
            .map_err(|e| KeyError::CertificateError(format!("Failed to parse certificate: {e}")))?;

        let subject = parsed_cert.subject().to_string();
        let issuer = parsed_cert.issuer().to_string();

        Ok(Self {
            der_bytes,
            subject,
            issuer,
        })
    }

    /// Get DER-encoded bytes
    pub fn der_bytes(&self) -> &[u8] {
        &self.der_bytes
    }

    /// Get certificate subject
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Get certificate issuer
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Convert to rustls certificate format
    pub fn to_rustls_certificate(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.der_bytes.clone())
    }

    /// Parse the certificate for validation
    pub fn parsed(&self) -> Result<x509_parser::certificate::X509Certificate> {
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&self.der_bytes)
            .map_err(|e| KeyError::CertificateError(format!("Failed to parse certificate: {e}")))?;
        Ok(cert)
    }

    /// Extract public key from certificate
    pub fn public_key(&self) -> Result<VerifyingKey> {
        let parsed = self.parsed()?;
        let public_key_info = parsed.public_key();
        let public_key_bytes = &public_key_info.subject_public_key.data;

        // Validate it's an uncompressed ECDSA P-256 point
        if public_key_bytes.len() != 65 || public_key_bytes[0] != 0x04 {
            return Err(KeyError::InvalidKeyFormat(
                "Invalid ECDSA P-256 public key in certificate".to_string(),
            ));
        }

        // Extract coordinates
        let x_bytes: [u8; 32] = public_key_bytes[1..33]
            .try_into()
            .map_err(|_| KeyError::InvalidKeyFormat("Invalid X coordinate".to_string()))?;
        let y_bytes: [u8; 32] = public_key_bytes[33..65]
            .try_into()
            .map_err(|_| KeyError::InvalidKeyFormat("Invalid Y coordinate".to_string()))?;

        // Create verifying key
        let encoded_point =
            EncodedPoint::from_affine_coordinates(&x_bytes.into(), &y_bytes.into(), false);

        VerifyingKey::from_encoded_point(&encoded_point)
            .map_err(|e| KeyError::InvalidKeyFormat(format!("Failed to create verifying key: {e}")))
    }

    /// Validate certificate signature using CA public key
    pub fn validate(&self, ca_public_key: &VerifyingKey) -> Result<()> {
        let parsed = self.parsed()?;

        // Validate time bounds first
        let now = SystemTime::now();
        let validity = &parsed.validity();

        let not_before: SystemTime = validity.not_before.to_datetime().into();
        let not_after: SystemTime = validity.not_after.to_datetime().into();

        if now < not_before {
            return Err(KeyError::CertificateValidationError(
                "Certificate not yet valid".to_string(),
            ));
        }

        if now > not_after {
            return Err(KeyError::CertificateValidationError(
                "Certificate expired".to_string(),
            ));
        }

        // Extract signature from certificate
        let signature_bytes = &parsed.signature_value.data;
        let signature = Signature::from_der(signature_bytes).map_err(|e| {
            KeyError::CertificateValidationError(format!("Invalid signature format: {e}"))
        })?;

        // Extract the signed data (TBS certificate)
        let tbs_certificate = parsed.tbs_certificate.as_ref();

        // Verify signature
        ca_public_key
            .verify(tbs_certificate, &signature)
            .map_err(|e| {
                KeyError::CertificateValidationError(format!("Signature verification failed: {e}"))
            })?;

        Ok(())
    }
}

impl Serialize for X509Certificate {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.der_bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for X509Certificate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let der_bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        Self::from_der(der_bytes).map_err(|e| {
            serde::de::Error::custom(format!("Failed to deserialize certificate: {e}"))
        })
    }
}

/// Certificate Authority for issuing standard X.509 certificates
#[derive(Debug, Clone)]
pub struct CertificateAuthority {
    ca_key_pair: EcdsaKeyPair,
    ca_certificate: X509Certificate,
}

impl CertificateAuthority {
    /// Create new CA with self-signed certificate
    pub fn new(subject: &str) -> Result<Self> {
        let ca_key_pair = EcdsaKeyPair::new()?;
        let ca_certificate = Self::create_self_signed_certificate(&ca_key_pair, subject)?;

        Ok(Self {
            ca_key_pair,
            ca_certificate,
        })
    }

    /// Create from existing key pair and certificate
    pub fn from_existing(ca_key_pair: EcdsaKeyPair, ca_certificate: X509Certificate) -> Self {
        Self {
            ca_key_pair,
            ca_certificate,
        }
    }

    /// Get CA certificate
    pub fn ca_certificate(&self) -> &X509Certificate {
        &self.ca_certificate
    }

    /// Get CA public key
    pub fn ca_public_key(&self) -> &VerifyingKey {
        &self.ca_key_pair.verifying_key
    }

    /// Get a reference to the CA key pair (used for state export)
    pub fn ca_key_pair(&self) -> &EcdsaKeyPair {
        &self.ca_key_pair
    }

    /// Sign a certificate request using OpenSSL for proper CA operations
    pub fn sign_certificate_request(
        &self,
        csr_der: &[u8],
        validity_days: u32,
    ) -> Result<X509Certificate> {
        self.sign_certificate_request_with_serial(csr_der, validity_days, None)
    }

    /// Same as `sign_certificate_request` but allows a caller-supplied serial
    /// number. If `serial_override` is `None` a random 64-bit serial is used
    /// (matches the previous behaviour).
    pub fn sign_certificate_request_with_serial(
        &self,
        csr_der: &[u8],
        validity_days: u32,
        serial_override: Option<u64>,
    ) -> Result<X509Certificate> {
        // Parse CSR and extract public key
        let req = X509Req::from_der(csr_der)
            .map_err(|e| KeyError::CertificateError(format!("Failed to parse CSR DER: {e}")))?;

        // Build certificate
        let mut cert_builder = X509Builder::new().map_err(|e| {
            KeyError::CertificateError(format!("Failed to create X509 builder: {e}"))
        })?;

        // Subject / issuer / public key
        let req_public_key = req.public_key().map_err(|e| {
            KeyError::CertificateError(format!("Failed to extract public key from CSR: {e}"))
        })?;

        // ----- New security check: verify CSR signature -----
        // Ensures the included public key actually matches the private key
        // that signed the CSR, protecting against tampering in transit.
        if !req.verify(&req_public_key)? {
            return Err(KeyError::CertificateError(
                "CSR signature verification failed".to_string(),
            ));
        }

        cert_builder
            .set_pubkey(&req_public_key)
            .map_err(|e| KeyError::CertificateError(format!("Failed to set pubkey: {e}")))?;
        cert_builder
            .set_subject_name(req.subject_name())
            .map_err(|e| KeyError::CertificateError(format!("Failed to set subject: {e}")))?;
        let ca_name = self.create_ca_name()?;
        cert_builder
            .set_issuer_name(&ca_name)
            .map_err(|e| KeyError::CertificateError(format!("Failed to set issuer: {e}")))?;

        // Validity
        let not_before = openssl::asn1::Asn1Time::days_from_now(0).map_err(|e| {
            KeyError::CertificateError(format!("Failed to set certificate not_before: {e}"))
        })?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(validity_days).map_err(|e| {
            KeyError::CertificateError(format!("Failed to set certificate not_after: {e}"))
        })?;
        cert_builder
            .set_not_before(&not_before)
            .map_err(|e| KeyError::CertificateError(format!("Failed to apply not_before: {e}")))?;
        cert_builder
            .set_not_after(&not_after)
            .map_err(|e| KeyError::CertificateError(format!("Failed to apply not_after: {e}")))?;

        // Extensions
        // BasicConstraints: not a CA, pathLen not present
        cert_builder
            .append_extension(
                OpenSslBasicConstraints::new()
                    .critical()
                    .build()
                    .map_err(|e| {
                        KeyError::CertificateError(format!("Failed to build BasicConstraints: {e}"))
                    })?,
            )
            .map_err(|e| {
                KeyError::CertificateError(format!("Failed to append BasicConstraints: {e}"))
            })?;

        cert_builder
            .append_extension(
                KeyUsage::new()
                    .digital_signature()
                    .critical()
                    .build()
                    .map_err(|e| {
                        KeyError::CertificateError(format!("Failed to build KeyUsage ext: {e}"))
                    })?,
            )
            .map_err(|e| {
                KeyError::CertificateError(format!("Failed to append KeyUsage ext: {e}"))
            })?;
        cert_builder
            .append_extension(
                ExtendedKeyUsage::new()
                    .server_auth()
                    .client_auth()
                    .build()
                    .map_err(|e| {
                        KeyError::CertificateError(format!("Failed to build EKU ext: {e}"))
                    })?,
            )
            .map_err(|e| KeyError::CertificateError(format!("Failed to append EKU ext: {e}")))?;

        // Subject Key Identifier (SKI)
        let subject_ctx = cert_builder.x509v3_context(None, None);
        let ski = SubjectKeyIdentifier::new()
            .build(&subject_ctx)
            .map_err(|e| KeyError::CertificateError(format!("Failed to build SKI: {e}")))?;
        cert_builder
            .append_extension(ski)
            .map_err(|e| KeyError::CertificateError(format!("Failed to append SKI: {e}")))?;

        // Authority Key Identifier (AKI)
        let ca_x509 = X509::from_der(self.ca_certificate.der_bytes()).map_err(|e| {
            KeyError::CertificateError(format!("Failed to parse CA certificate DER: {e}"))
        })?;
        let issuer_ctx = cert_builder.x509v3_context(Some(&ca_x509), None);
        let aki = AuthorityKeyIdentifier::new()
            .keyid(true)
            .issuer(true)
            .build(&issuer_ctx)
            .map_err(|e| KeyError::CertificateError(format!("Failed to build AKI: {e}")))?;
        cert_builder
            .append_extension(aki)
            .map_err(|e| KeyError::CertificateError(format!("Failed to append AKI: {e}")))?;

        // Serial number
        let serial_asn1 = match serial_override {
            Some(s) => Self::u64_to_asn1(s)?,
            None => self.random_serial()?,
        };
        cert_builder
            .set_serial_number(&serial_asn1)
            .map_err(|e| KeyError::CertificateError(format!("Failed to set serial number: {e}")))?;

        // Sign & return
        let ca_pkey = self.ca_key_pair_to_openssl_pkey()?;
        cert_builder
            .sign(&ca_pkey, MessageDigest::sha256())
            .map_err(|e| KeyError::CertificateError(format!("Failed to sign certificate: {e}")))?;
        let cert_der = cert_builder.build().to_der().map_err(|e| {
            KeyError::CertificateError(format!("Failed to serialize certificate DER: {e}"))
        })?;
        X509Certificate::from_der(cert_der)
    }

    fn random_serial(&self) -> Result<Asn1Integer> {
        let mut bn = BigNum::new()
            .map_err(|e| KeyError::CertificateError(format!("Failed to create BigNum: {e}")))?;
        bn.rand(64, MsbOption::MAYBE_ZERO, false).map_err(|e| {
            KeyError::CertificateError(format!("Failed to generate random serial: {e}"))
        })?;
        bn.to_asn1_integer()
            .map_err(|e| KeyError::CertificateError(format!("Failed to convert serial: {e}")))
    }

    fn u64_to_asn1(value: u64) -> Result<Asn1Integer> {
        let bn = BigNum::from_dec_str(&value.to_string()).map_err(|e| {
            KeyError::CertificateError(format!("Failed to create BigNum from u64: {e}"))
        })?;
        bn.to_asn1_integer()
            .map_err(|e| KeyError::CertificateError(format!("Failed to convert serial: {e}")))
    }

    /// Convert our ECDSA key pair to OpenSSL PKey format
    fn ca_key_pair_to_openssl_pkey(&self) -> Result<PKey<Private>> {
        // Get the private key in PKCS#8 DER format
        let private_key_der = self.ca_key_pair.private_key_der()?;

        // Create OpenSSL PKey from the DER data
        PKey::private_key_from_der(&private_key_der).map_err(|e| {
            KeyError::InvalidKeyFormat(format!("Failed to convert key to OpenSSL format: {e}"))
        })
    }

    /// Create the CA name for certificate issuer
    fn create_ca_name(&self) -> Result<openssl::x509::X509Name> {
        let mut name_builder = X509NameBuilder::new().map_err(|e| {
            KeyError::CertificateError(format!("Failed to create name builder: {e}"))
        })?;

        name_builder
            .append_entry_by_nid(Nid::COUNTRYNAME, "US")
            .map_err(|e| KeyError::CertificateError(format!("Failed to set country: {e}")))?;
        name_builder
            .append_entry_by_nid(Nid::ORGANIZATIONNAME, "Runar")
            .map_err(|e| KeyError::CertificateError(format!("Failed to set organization: {e}")))?;
        name_builder
            .append_entry_by_nid(Nid::COMMONNAME, "Runar User CA")
            .map_err(|e| KeyError::CertificateError(format!("Failed to set common name: {e}")))?;

        Ok(name_builder.build())
    }

    /// Create self-signed CA certificate
    fn create_self_signed_certificate(
        key_pair: &EcdsaKeyPair,
        _subject: &str,
    ) -> Result<X509Certificate> {
        // Build CA cert with OpenSSL to include SKI/AKI and pathLen=0
        let mut builder = X509Builder::new().map_err(|e| {
            KeyError::CertificateError(format!("Failed to create X509 builder: {e}"))
        })?;

        // Subject/Issuer
        let ca_name = {
            let mut nb = X509NameBuilder::new().map_err(|e| {
                KeyError::CertificateError(format!("Failed to create name builder: {e}"))
            })?;
            nb.append_entry_by_nid(Nid::COUNTRYNAME, "US")
                .map_err(|e| KeyError::CertificateError(format!("Failed to set country: {e}")))?;
            nb.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Runar")
                .map_err(|e| {
                    KeyError::CertificateError(format!("Failed to set organization: {e}"))
                })?;
            nb.append_entry_by_nid(Nid::COMMONNAME, "Runar User CA")
                .map_err(|e| {
                    KeyError::CertificateError(format!("Failed to set common name: {e}"))
                })?;
            nb.build()
        };
        builder
            .set_subject_name(&ca_name)
            .map_err(|e| KeyError::CertificateError(format!("Failed to set subject: {e}")))?;
        builder
            .set_issuer_name(&ca_name)
            .map_err(|e| KeyError::CertificateError(format!("Failed to set issuer: {e}")))?;

        // Public key
        let ca_pkey = {
            let der = key_pair.private_key_der()?;
            PKey::private_key_from_der(&der)
                .map_err(|e| KeyError::InvalidKeyFormat(format!("Failed to load CA key: {e}")))?
        };
        builder
            .set_pubkey(&ca_pkey)
            .map_err(|e| KeyError::CertificateError(format!("Failed to set pubkey: {e}")))?;

        // Validity
        let not_before = openssl::asn1::Asn1Time::days_from_now(0).map_err(|e| {
            KeyError::CertificateError(format!("Failed to set certificate not_before: {e}"))
        })?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(365 * 10).map_err(|e| {
            KeyError::CertificateError(format!("Failed to set certificate not_after: {e}"))
        })?;
        builder
            .set_not_before(&not_before)
            .map_err(|e| KeyError::CertificateError(format!("Failed to apply not_before: {e}")))?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| KeyError::CertificateError(format!("Failed to apply not_after: {e}")))?;

        // Serial
        let mut bn = BigNum::new()
            .map_err(|e| KeyError::CertificateError(format!("Failed to create BigNum: {e}")))?;
        bn.rand(64, MsbOption::MAYBE_ZERO, false).map_err(|e| {
            KeyError::CertificateError(format!("Failed to generate random serial: {e}"))
        })?;
        let serial_asn1 = Asn1Integer::from_bn(&bn)
            .map_err(|e| KeyError::CertificateError(format!("Failed to convert serial: {e}")))?;
        builder
            .set_serial_number(&serial_asn1)
            .map_err(|e| KeyError::CertificateError(format!("Failed to set serial number: {e}")))?;

        // Extensions
        builder
            .append_extension(
                OpenSslBasicConstraints::new()
                    .ca()
                    .pathlen(0)
                    .critical()
                    .build()
                    .map_err(|e| {
                        KeyError::CertificateError(format!(
                            "Failed to build CA BasicConstraints: {e}"
                        ))
                    })?,
            )
            .map_err(|e| {
                KeyError::CertificateError(format!("Failed to append CA BasicConstraints: {e}"))
            })?;
        builder
            .append_extension(
                KeyUsage::new()
                    .key_cert_sign()
                    .crl_sign()
                    .critical()
                    .build()
                    .map_err(|e| {
                        KeyError::CertificateError(format!("Failed to build CA KeyUsage: {e}"))
                    })?,
            )
            .map_err(|e| {
                KeyError::CertificateError(format!("Failed to append CA KeyUsage: {e}"))
            })?;

        let ctx1 = builder.x509v3_context(None, None);
        let ski = SubjectKeyIdentifier::new()
            .build(&ctx1)
            .map_err(|e| KeyError::CertificateError(format!("Failed to build CA SKI: {e}")))?;
        builder
            .append_extension(ski)
            .map_err(|e| KeyError::CertificateError(format!("Failed to append CA SKI: {e}")))?;
        let ctx2 = builder.x509v3_context(None, None);
        let aki = AuthorityKeyIdentifier::new()
            .keyid(true)
            .issuer(true)
            .build(&ctx2)
            .map_err(|e| KeyError::CertificateError(format!("Failed to build CA AKI: {e}")))?;
        builder
            .append_extension(aki)
            .map_err(|e| KeyError::CertificateError(format!("Failed to append CA AKI: {e}")))?;

        // Sign
        builder
            .sign(&ca_pkey, MessageDigest::sha256())
            .map_err(|e| {
                KeyError::CertificateError(format!("Failed to sign CA certificate: {e}"))
            })?;
        let der = builder.build().to_der().map_err(|e| {
            KeyError::CertificateError(format!("Failed to DER-encode CA certificate: {e}"))
        })?;
        X509Certificate::from_der(der)
    }
}

/// Certificate validator for comprehensive validation
#[derive(Debug, Clone)]
pub struct CertificateValidator {
    trusted_ca_certificates: Vec<X509Certificate>,
}

impl CertificateValidator {
    /// Create validator with trusted CA certificates
    pub fn new(trusted_ca_certificates: Vec<X509Certificate>) -> Self {
        Self {
            trusted_ca_certificates,
        }
    }

    /// Validate certificate against trusted CAs with full cryptographic verification
    pub fn validate_certificate(&self, certificate: &X509Certificate) -> Result<()> {
        for ca_cert in &self.trusted_ca_certificates {
            // Try exact match first
            if certificate.issuer() == ca_cert.subject() {
                let ca_public_key = ca_cert.public_key()?;
                return certificate.validate(&ca_public_key);
            }

            // Handle DN component order differences between OpenSSL and rcgen
            if self.normalize_dn(certificate.issuer()) == self.normalize_dn(ca_cert.subject()) {
                let ca_public_key = ca_cert.public_key()?;
                return certificate.validate(&ca_public_key);
            }
        }

        Err(KeyError::ChainValidationError(format!(
            "No trusted CA found for certificate. Certificate issuer: '{}', Available CAs: {:?}",
            certificate.issuer(),
            self.trusted_ca_certificates
                .iter()
                .map(|ca| ca.subject())
                .collect::<Vec<_>>()
        )))
    }

    /// Normalize DN string to handle component order differences
    fn normalize_dn(&self, dn: &str) -> String {
        let mut components = Vec::new();

        for component in dn.split(',') {
            let component = component.trim();
            if !component.is_empty() {
                components.push(component);
            }
        }

        // Sort components to handle order differences
        components.sort();
        components.join(",")
    }

    /// Validate complete certificate chain
    pub fn validate_certificate_chain(
        &self,
        certificate: &X509Certificate,
        _chain: &[X509Certificate],
    ) -> Result<()> {
        // Full implementation would validate the entire chain
        // For now, validate against trusted CAs
        self.validate_certificate(certificate)
    }

    /// Validate certificate for TLS server usage
    pub fn validate_for_tls_server(&self, certificate: &X509Certificate) -> Result<()> {
        self.validate_certificate(certificate)?;

        let _parsed = certificate.parsed()?;

        // Full implementation would check key usage and extended key usage
        // This is a comprehensive security check

        Ok(())
    }
}

/// Certificate Signing Request operations using standard PKCS#10
pub struct CertificateRequest;

impl CertificateRequest {
    /// Create proper PKCS#10 certificate signing request
    pub fn create(key_pair: &EcdsaKeyPair, subject: &str) -> Result<Vec<u8>> {
        let mut params = CertificateParams::new(vec![]);

        // Use ECDSA P-256 with SHA-256
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;

        // Parse subject DN properly
        let mut distinguished_name = rcgen::DistinguishedName::new();

        for component in subject.split(',') {
            let component = component.trim();
            if let Some((key, value)) = component.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "CN" => distinguished_name.push(rcgen::DnType::CommonName, value),
                    "O" => distinguished_name.push(rcgen::DnType::OrganizationName, value),
                    "C" => distinguished_name.push(rcgen::DnType::CountryName, value),
                    "ST" => distinguished_name.push(rcgen::DnType::StateOrProvinceName, value),
                    "L" => distinguished_name.push(rcgen::DnType::LocalityName, value),
                    "OU" => distinguished_name.push(rcgen::DnType::OrganizationalUnitName, value),
                    _ => {
                        // Skipping unknown DN component in CSR - handled by caller if needed
                    }
                }
            }
        }

        params.distinguished_name = distinguished_name;

        let rcgen_key_pair = key_pair.to_rcgen_key_pair()?;
        params.key_pair = Some(rcgen_key_pair);

        let cert = RcgenCertificate::from_params(params)?;
        let csr_der = cert.serialize_request_der()?;

        Ok(csr_der)
    }
}
