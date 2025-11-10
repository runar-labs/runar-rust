use std::collections::HashMap;
use std::time::SystemTime;

use p256::ecdsa::signature::Verifier;
use runar_logging::Logger;
use runar_logging::{log_debug, log_error, log_trace};
use std::sync::Arc;
use x509_parser::prelude::*;

use crate::{
    ca_node_types::{
        CaRevocationList, CaStatus, ChainResponse, CsrEnrollRequest, CsrEnrollResponse,
        RateLimitState, RenewRequest, RenewResponse, RevokeRequest, RevokeResponse, RevokedSerial,
    },
    certificate::{CertificateAuthority, EcdsaKeyPair, X509Certificate},
    enrollment_token::EnrollmentToken,
    error::{KeyError, Result},
};

/// Core CA Node implementation for certificate issuance and management
pub struct CANode {
    /// Issuing CA key pair for signing certificates
    pub issuing_ca_key: EcdsaKeyPair,
    /// Issuing CA certificate
    pub issuing_ca_cert: X509Certificate,
    /// Root CA certificate
    pub root_ca_cert: X509Certificate,
    /// Network ID this CA Node serves
    pub network_id: String,
    /// Enrollment authority public keys (signer_id -> public_key_bytes)
    pub enrollment_authorities: HashMap<String, Vec<u8>>,
    /// Revoked token IDs with revocation time
    pub revoked_tokens: HashMap<String, SystemTime>,
    /// Rate limiting state per (remote_addr, token_id)
    pub rate_limits: HashMap<String, RateLimitState>,
    /// Revoked certificate serials
    pub revoked_certificates: HashMap<Vec<u8>, RevokedSerial>,
    /// Admin SKI allowlist for admin operations
    pub admin_ski_allowlist: Vec<String>,
    /// Token anti-replay ledger: (token_id, nonce) -> expiry_time
    pub token_replay_ledger: HashMap<(String, [u8; 16]), SystemTime>,
    /// Logger
    logger: Arc<Logger>,
}

impl CANode {
    /// Create a new CA Node with the given issuing CA and root CA
    pub fn new(
        issuing_ca_key: EcdsaKeyPair,
        issuing_ca_cert: X509Certificate,
        root_ca_cert: X509Certificate,
        network_id: String,
        logger: Arc<Logger>,
    ) -> Self {
        Self {
            issuing_ca_key,
            issuing_ca_cert,
            root_ca_cert,
            network_id,
            enrollment_authorities: HashMap::new(),
            revoked_tokens: HashMap::new(),
            rate_limits: HashMap::new(),
            revoked_certificates: HashMap::new(),
            admin_ski_allowlist: Vec::new(),
            token_replay_ledger: HashMap::new(),
            logger,
        }
    }

    /// Install issuing CA and configure enrollment authorities
    pub fn install_issuing_ca(
        &mut self,
        issuing_ca_key_pair: EcdsaKeyPair,
        issuing_ca_certificate: X509Certificate,
        root_ca_certificate: X509Certificate,
        ea_public_keys: Vec<Vec<u8>>,
    ) -> Result<()> {
        self.issuing_ca_key = issuing_ca_key_pair;
        self.issuing_ca_cert = issuing_ca_certificate;
        self.root_ca_cert = root_ca_certificate;

        // Configure enrollment authorities
        for ea_public_key in ea_public_keys {
            let signer_id = runar_common::compact_ids::compact_id(&ea_public_key);
            self.enrollment_authorities.insert(signer_id, ea_public_key);
        }

        Ok(())
    }

    /// Configure enrollment authority public keys
    pub fn configure_enrollment_authority(&mut self, ea_public_keys: Vec<Vec<u8>>) -> Result<()> {
        for ea_public_key in ea_public_keys {
            let signer_id = runar_common::compact_ids::compact_id(&ea_public_key);
            self.enrollment_authorities.insert(signer_id, ea_public_key);
        }
        Ok(())
    }

    /// Validate an enrollment token
    pub fn validate_enrollment_token(&mut self, token: &EnrollmentToken) -> Result<()> {
        log_trace!(self.logger, "validate_enrollment_token called");
        // Check if token is revoked
        if self.revoked_tokens.contains_key(&token.body.token_id) {
            log_error!(self.logger, "Token has been revoked");
            return Err(KeyError::ValidationError(
                "Token has been revoked".to_string(),
            ));
        }
        log_trace!(self.logger, "Token not revoked");

        // Check anti-replay ledger
        log_trace!(self.logger, "Checking anti-replay ledger...");
        let replay_key = (token.body.token_id.clone(), token.body.nonce);
        if let Some(expiry_time) = self.token_replay_ledger.get(&replay_key) {
            if SystemTime::now() < *expiry_time {
                log_error!(self.logger, "Token nonce already used (replay attack)");
                return Err(KeyError::ValidationError(
                    "Token nonce already used (replay attack)".to_string(),
                ));
            }
        }
        log_trace!(self.logger, "No replay attack detected");

        // Get the enrollment authority public key
        log_trace!(
            self.logger,
            "Looking up enrollment authority for signer_id: {}",
            token.signer_id
        );
        log_trace!(
            self.logger,
            "Available enrollment authorities: {:?}",
            self.enrollment_authorities.keys().collect::<Vec<_>>()
        );

        let ea_public_key = self
            .enrollment_authorities
            .get(&token.signer_id)
            .ok_or_else(|| {
                log_error!(
                    self.logger,
                    "Unknown enrollment authority: {}",
                    token.signer_id
                );
                KeyError::ValidationError("Unknown enrollment authority".to_string())
            })?;
        log_trace!(self.logger, "Found enrollment authority public key");

        // Verify token signature
        log_trace!(self.logger, "Verifying token signature...");
        token.verify(ea_public_key)?;
        log_trace!(self.logger, "Token signature verification passed");

        // Validate token for enrollment
        log_trace!(
            self.logger,
            "Validating token for enrollment with network_id: {}",
            self.network_id
        );
        token.validate_for_enrollment(&self.network_id)?;
        log_debug!(self.logger, "Token validation for enrollment passed");

        // Add to anti-replay ledger with token expiry time
        self.token_replay_ledger.insert(
            replay_key,
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(token.body.expires_at),
        );

        // Clean up expired entries from replay ledger
        self.cleanup_expired_replay_entries();

        Ok(())
    }

    /// Check rate limiting for a request
    pub fn check_rate_limit(&mut self, remote_addr: &str, token_id: &str) -> Result<()> {
        let key = format!("{remote_addr}:{token_id}");

        let rate_limit = self.rate_limits.entry(key).or_insert_with(|| {
            RateLimitState::new(5, 30) // 5/min, 30/hour as per design
        });

        if !rate_limit.is_allowed() {
            return Err(KeyError::RateLimitError("Rate limit exceeded".to_string()));
        }

        Ok(())
    }

    /// Handle CSR enrollment request
    pub fn handle_enroll(
        &mut self,
        request: CsrEnrollRequest,
        remote_addr: &str,
    ) -> Result<CsrEnrollResponse> {
        log_trace!(self.logger, "CA Node handle_enroll called");
        // Validate enrollment token
        log_trace!(self.logger, "Validating enrollment token...");
        self.validate_enrollment_token(&request.enrollment_token)?;
        log_trace!(self.logger, "Enrollment token validation passed");

        // Check rate limiting
        log_trace!(self.logger, "Checking rate limiting...");
        self.check_rate_limit(remote_addr, &request.enrollment_token.body.token_id)?;
        log_trace!(self.logger, "Rate limiting check passed");

        // Parse and validate CSR
        log_trace!(self.logger, "Parsing CSR...");
        let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(
            &request.csr_der,
        )
        .map_err(|e| {
            log_error!(self.logger, "CSR parsing failed: {e}");
            KeyError::ValidationError(format!("Invalid CSR: {e}"))
        })?;
        log_trace!(self.logger, "CSR parsed successfully");

        // Extract CN from CSR subject
        log_trace!(self.logger, "Extracting CN from CSR subject...");
        let subject = &csr.certification_request_info.subject;
        let mut cn = None;
        for rdn in subject.iter_common_name() {
            if let Ok(val) = rdn.as_str() {
                cn = Some(val);
                break;
            }
        }
        let cn = cn.ok_or_else(|| {
            log_error!(self.logger, "CSR missing CN");
            KeyError::ValidationError("CSR missing CN".to_string())
        })?;
        log_trace!(self.logger, "CSR CN extracted: {cn}");

        // Validate CN matches compact_id of public key in CSR
        log_trace!(self.logger, "Validating CN matches compact_id...");
        let public_key = &csr
            .certification_request_info
            .subject_pki
            .subject_public_key;
        let public_key_bytes = public_key.data.to_vec();
        let expected_cn = runar_common::compact_ids::compact_id(&public_key_bytes);
        log_trace!(self.logger, "Expected CN: {expected_cn}");

        if cn != expected_cn {
            log_error!(self.logger, "CN mismatch: got {cn}, expected {expected_cn}");
            return Err(KeyError::ValidationError(format!(
                "CSR CN {cn} does not match public key compact_id {expected_cn}"
            )));
        }
        log_debug!(
            self.logger,
            "CSR validation and certificate issuance completed"
        );

        // Create certificate authority for signing
        let ca = CertificateAuthority::from_existing(
            self.issuing_ca_key.clone(),
            self.issuing_ca_cert.clone(),
        );

        // Issue device certificate (7-30 days validity as per design)
        let validity_days = 30;
        let device_cert = ca.sign_certificate_request_with_serial(
            &request.csr_der,
            validity_days,
            None, // Let CA generate serial
        )?;

        // Calculate expiration time
        let expires_at = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + (validity_days as u64 * 24 * 60 * 60);

        Ok(CsrEnrollResponse {
            network_id: request.network_id,
            certificate_der: device_cert.der_bytes().to_vec(),
            issuing_ca_der: self.issuing_ca_cert.der_bytes().to_vec(),
            root_ca_der: Some(self.root_ca_cert.der_bytes().to_vec()),
            expires_at,
        })
    }

    /// Handle certificate renewal request with device-based authorization
    pub fn handle_renew(
        &mut self,
        request: RenewRequest,
        peer_cert_der: &[u8],
    ) -> Result<RenewResponse> {
        // Validate network_id
        if request.network_id != self.network_id {
            return Err(KeyError::ValidationError("Network ID mismatch".to_string()));
        }

        // Parse CSR to extract public key and validate
        let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(
            &request.csr_der,
        )
        .map_err(|e| KeyError::ValidationError(format!("Invalid CSR: {e}")))?;

        // Extract public key from CSR (not used, but kept for clarity)
        let _csr_public_key_bytes = csr
            .certification_request_info
            .subject_pki
            .subject_public_key
            .data
            .to_vec();

        // Parse peer certificate to extract public key
        let (_, peer_cert) = x509_parser::certificate::X509Certificate::from_der(peer_cert_der)
            .map_err(|e| KeyError::ValidationError(format!("Invalid peer certificate: {e}")))?;

        // Extract public key from peer certificate
        let peer_public_key_bytes = peer_cert.public_key().subject_public_key.data.to_vec();

        // Validate that CSR CN matches the peer certificate identity (device-based authorization)
        let peer_compact_id = runar_common::compact_ids::compact_id(&peer_public_key_bytes);
        let csr_cn = csr
            .certification_request_info
            .subject
            .iter_common_name()
            .next()
            .ok_or_else(|| KeyError::ValidationError("CSR missing CN".to_string()))?
            .as_str()
            .map_err(|e| KeyError::ValidationError(format!("Invalid CSR CN: {e}")))?;

        if csr_cn != peer_compact_id {
            return Err(KeyError::AuthorizationError(format!(
                "CSR CN {csr_cn} does not match peer certificate identity {peer_compact_id}"
            )));
        }

        // Note: We don't validate that peer_ski matches CSR public key SKI
        // because renewal allows key rotation - the important check is that
        // the CSR CN matches the peer certificate identity (device), which we did above

        // Create certificate authority for signing
        let ca = CertificateAuthority::from_existing(
            self.issuing_ca_key.clone(),
            self.issuing_ca_cert.clone(),
        );

        // Issue renewed certificate
        let validity_days = 30;
        let renewed_cert =
            ca.sign_certificate_request_with_serial(&request.csr_der, validity_days, None)?;

        // Calculate expiration time
        let expires_at = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + (validity_days as u64 * 24 * 60 * 60);

        Ok(RenewResponse {
            network_id: request.network_id,
            certificate_der: renewed_cert.der_bytes().to_vec(),
            issuing_ca_der: self.issuing_ca_cert.der_bytes().to_vec(),
            expires_at,
        })
    }

    /// Handle certificate revocation request
    pub fn handle_revoke(
        &mut self,
        request: RevokeRequest,
        peer_ski: &str,
    ) -> Result<RevokeResponse> {
        // Validate network_id
        if request.network_id != self.network_id {
            return Err(KeyError::ValidationError("Network ID mismatch".to_string()));
        }

        // Check admin authorization
        if !self.admin_ski_allowlist.contains(&peer_ski.to_string()) {
            return Err(KeyError::AuthorizationError(
                "Admin SKI not authorized".to_string(),
            ));
        }

        // Add to revoked certificates
        let revoked_serial = RevokedSerial {
            serial: request.certificate_serial.clone(),
            revocation_time: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            reason: request.reason,
        };

        self.revoked_certificates
            .insert(request.certificate_serial, revoked_serial);

        Ok(RevokeResponse {
            network_id: request.network_id,
            ok: true,
        })
    }

    /// Handle CA certificate chain request
    pub fn handle_chain(&self, network_id: String) -> Result<ChainResponse> {
        Ok(ChainResponse {
            network_id,
            issuing_ca_der: self.issuing_ca_cert.der_bytes().to_vec(),
            root_ca_der: Some(self.root_ca_cert.der_bytes().to_vec()),
        })
    }

    /// Handle CA status request
    pub fn handle_status(&self, network_id: String) -> Result<CaStatus> {
        // Extract subject and serial from issuing CA certificate
        let issuing_cert_der = self.issuing_ca_cert.der_bytes();
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(issuing_cert_der)
            .map_err(|e| {
                KeyError::ValidationError(format!("Invalid issuing CA certificate: {e}"))
            })?;

        let subject = cert.subject().to_string();
        let serial_hex = format!("{:x}", cert.serial);
        let not_before = cert.validity().not_before.timestamp() as u64;
        let not_after = cert.validity().not_after.timestamp() as u64;

        Ok(CaStatus {
            network_id,
            issuing_subject: subject,
            issuing_serial_hex: serial_hex,
            not_before,
            not_after,
        })
    }

    /// Generate CRL-lite
    pub fn generate_crl_lite(&self) -> Result<CaRevocationList> {
        // Get issuing CA serial and SKI
        let issuing_cert_der = self.issuing_ca_cert.der_bytes();
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(issuing_cert_der)
            .map_err(|e| {
                KeyError::ValidationError(format!("Invalid issuing CA certificate: {e}"))
            })?;
        let issuing_ca_serial_hex = format!("{:x}", cert.serial);

        // Extract SKI from issuing CA certificate
        let mut signer_ski = Vec::new();
        for ext in cert.extensions() {
            if let x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(ski) =
                ext.parsed_extension()
            {
                signer_ski = ski.0.to_vec();
                break;
            }
        }

        // Convert revoked certificates to simple serial list
        let revoked_serials: Vec<Vec<u8>> = self
            .revoked_certificates
            .values()
            .map(|revoked| revoked.serial.clone())
            .collect();

        let mut crl = CaRevocationList {
            network_id: self.network_id.clone(),
            issuing_ca_serial_hex,
            revoked_serials,
            generated_at: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            signature: vec![], // Will be filled after signing
            signer_ski,
            sig_alg: "p256-sha256-der".to_string(),
        };

        // Sign the CRL-lite with the issuing CA key
        let signature = self.sign_crl_lite(&crl)?;
        crl.signature = signature;

        Ok(crl)
    }

    /// Sign a CRL-lite with the issuing CA key
    fn sign_crl_lite(&self, crl: &CaRevocationList) -> Result<Vec<u8>> {
        // Create a copy without the signature for signing
        let mut crl_for_signing = crl.clone();
        crl_for_signing.signature = vec![];

        // Serialize the CRL-lite to CBOR
        let crl_cbor = serde_cbor::to_vec(&crl_for_signing)
            .map_err(|e| KeyError::ValidationError(format!("Failed to serialize CRL: {e}")))?;

        // Sign with ECDSA P-256
        let signature = self.issuing_ca_key.sign(&crl_cbor)?;

        // Return raw signature bytes (already in DER format from ECDSA)
        Ok(signature)
    }

    /// Revoke a certificate
    pub fn revoke_certificate(&mut self, serial: Vec<u8>, reason: String) -> Result<()> {
        let revoked_serial = RevokedSerial {
            serial: serial.clone(),
            revocation_time: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            reason,
        };

        self.revoked_certificates.insert(serial, revoked_serial);
        Ok(())
    }

    /// Add admin SKI to allowlist
    pub fn add_admin_ski(&mut self, ski: String) {
        self.admin_ski_allowlist.push(ski);
    }

    /// Check if a certificate is revoked
    pub fn is_certificate_revoked(&self, serial: &[u8]) -> bool {
        self.revoked_certificates.contains_key(serial)
    }

    /// Handle CRL fetch request
    pub fn handle_crl(&self, network_id: String) -> Result<CaRevocationList> {
        let mut crl = self.generate_crl_lite()?;
        crl.network_id = network_id;
        Ok(crl)
    }

    /// Verify CRL-lite signature
    pub fn verify_crl_lite(&self, crl: &CaRevocationList) -> Result<bool> {
        // Extract the issuing CA public key
        let issuing_cert_der = self.issuing_ca_cert.der_bytes();
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(issuing_cert_der)
            .map_err(|e| {
                KeyError::ValidationError(format!("Invalid issuing CA certificate: {e}"))
            })?;

        // Get the public key from the issuing CA certificate
        let public_key_bytes = cert.public_key().subject_public_key.data.to_vec();
        let public_key = p256::PublicKey::from_sec1_bytes(&public_key_bytes)
            .map_err(|e| KeyError::ValidationError(format!("Invalid public key: {e}")))?;

        // Verify the signer SKI matches the issuing CA SKI
        let mut issuing_ca_ski = Vec::new();
        for ext in cert.extensions() {
            if let x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(ski) =
                ext.parsed_extension()
            {
                issuing_ca_ski = ski.0.to_vec();
                break;
            }
        }

        if crl.signer_ski != issuing_ca_ski {
            return Err(KeyError::ValidationError(
                "CRL signer SKI does not match issuing CA SKI".to_string(),
            ));
        }

        // Verify the signature algorithm
        if crl.sig_alg != "p256-sha256-der" {
            return Err(KeyError::ValidationError(
                "Unsupported signature algorithm".to_string(),
            ));
        }

        // Create a copy of the CRL without the signature for verification
        let mut crl_for_verification = crl.clone();
        crl_for_verification.signature = vec![];

        // Serialize the CRL body (without signature) to CBOR
        let crl_cbor = serde_cbor::to_vec(&crl_for_verification)
            .map_err(|e| KeyError::ValidationError(format!("Failed to serialize CRL: {e}")))?;

        // Verify the signature
        let signature = p256::ecdsa::Signature::from_der(&crl.signature)
            .map_err(|e| KeyError::ValidationError(format!("Invalid signature format: {e}")))?;

        let verifier = p256::ecdsa::VerifyingKey::from(&public_key);
        match verifier.verify(&crl_cbor, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Clean up expired entries from the replay ledger
    fn cleanup_expired_replay_entries(&mut self) {
        let now = SystemTime::now();
        self.token_replay_ledger
            .retain(|_, expiry_time| now < *expiry_time);
    }

    /// Revoke an enrollment token (admin-only)
    pub fn revoke_token(&mut self, token_id: String) -> Result<()> {
        self.revoked_tokens.insert(token_id, SystemTime::now());
        Ok(())
    }

    /// Validate a peer certificate against CRL-lite
    /// This method checks if a certificate is revoked by looking up its serial number
    /// in the current revocation list.
    pub fn validate_certificate_against_crl(&self, certificate_der: &[u8]) -> Result<()> {
        // Parse the certificate to extract serial number
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(certificate_der)
            .map_err(|e| KeyError::ValidationError(format!("Failed to parse certificate: {e}")))?;

        let serial_bytes = cert.serial.to_bytes_be();

        // Check if certificate is revoked
        if self.is_certificate_revoked(&serial_bytes) {
            return Err(KeyError::ValidationError(format!(
                "Certificate with serial {} is revoked",
                cert.serial
            )));
        }

        Ok(())
    }

    /// Validate certificate against CRL with signature verification
    pub fn validate_certificate_against_crl_with_verification(
        &self,
        certificate_der: &[u8],
        crl: &CaRevocationList,
    ) -> Result<()> {
        // First verify the CRL signature
        if !self.verify_crl_lite(crl)? {
            return Err(KeyError::ValidationError(
                "CRL signature verification failed".to_string(),
            ));
        }

        // Parse the certificate to extract serial number
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(certificate_der)
            .map_err(|e| KeyError::ValidationError(format!("Failed to parse certificate: {e}")))?;

        let serial_bytes = cert.serial.to_bytes_be();

        // Check if the certificate serial is in the CRL
        if crl.revoked_serials.contains(&serial_bytes) {
            return Err(KeyError::ValidationError(format!(
                "Certificate with serial {} is revoked according to CRL",
                cert.serial
            )));
        }

        Ok(())
    }
}
