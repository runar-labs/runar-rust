use std::collections::HashMap;
use std::time::SystemTime;

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
}

impl CANode {
    /// Create a new CA Node with the given issuing CA and root CA
    pub fn new(
        issuing_ca_key: EcdsaKeyPair,
        issuing_ca_cert: X509Certificate,
        root_ca_cert: X509Certificate,
        network_id: String,
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
        // Check if token is revoked
        if self.revoked_tokens.contains_key(&token.body.token_id) {
            return Err(KeyError::ValidationError(
                "Token has been revoked".to_string(),
            ));
        }

        // Check anti-replay ledger
        let replay_key = (token.body.token_id.clone(), token.body.nonce);
        if let Some(expiry_time) = self.token_replay_ledger.get(&replay_key) {
            if SystemTime::now() < *expiry_time {
                return Err(KeyError::ValidationError(
                    "Token nonce already used (replay attack)".to_string(),
                ));
            }
        }

        // Get the enrollment authority public key
        let ea_public_key = self
            .enrollment_authorities
            .get(&token.signer_id)
            .ok_or_else(|| KeyError::ValidationError("Unknown enrollment authority".to_string()))?;

        // Verify token signature
        token.verify(ea_public_key)?;

        // Validate token for enrollment
        token.validate_for_enrollment(&self.network_id)?;

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
        // Validate enrollment token
        self.validate_enrollment_token(&request.enrollment_token)?;

        // Check rate limiting
        self.check_rate_limit(remote_addr, &request.enrollment_token.body.token_id)?;

        // Parse and validate CSR
        let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(
            &request.csr_der,
        )
        .map_err(|e| KeyError::ValidationError(format!("Invalid CSR: {e}")))?;

        // Extract CN from CSR subject
        let subject = &csr.certification_request_info.subject;
        let mut cn = None;
        for rdn in subject.iter_common_name() {
            if let Ok(val) = rdn.as_str() {
                cn = Some(val);
                break;
            }
        }
        let cn = cn.ok_or_else(|| KeyError::ValidationError("CSR missing CN".to_string()))?;

        // Validate CN matches compact_id of public key in CSR
        let public_key = &csr
            .certification_request_info
            .subject_pki
            .subject_public_key;
        let public_key_bytes = public_key.data.to_vec();
        let expected_cn = runar_common::compact_ids::compact_id(&public_key_bytes);

        if cn != expected_cn {
            return Err(KeyError::ValidationError(format!(
                "CSR CN {cn} does not match public key compact_id {expected_cn}"
            )));
        }

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
            certificate_der: device_cert.der_bytes().to_vec(),
            issuing_ca_der: self.issuing_ca_cert.der_bytes().to_vec(),
            root_ca_der: Some(self.root_ca_cert.der_bytes().to_vec()),
            expires_at,
        })
    }

    /// Handle certificate renewal request
    pub fn handle_renew(&mut self, request: RenewRequest, peer_ski: &str) -> Result<RenewResponse> {
        // Parse CSR to extract public key and validate
        let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(
            &request.csr_der,
        )
        .map_err(|e| KeyError::ValidationError(format!("Invalid CSR: {e}")))?;

        // Extract public key from CSR
        let public_key_bytes = csr
            .certification_request_info
            .subject_pki
            .subject_public_key
            .data
            .to_vec();

        // Validate that CSR CN matches the peer identity (device-based authorization)
        let expected_cn = runar_common::compact_ids::compact_id(&public_key_bytes);
        let csr_cn = csr
            .certification_request_info
            .subject
            .iter_common_name()
            .next()
            .ok_or_else(|| KeyError::ValidationError("CSR missing CN".to_string()))?
            .as_str()
            .map_err(|e| KeyError::ValidationError(format!("Invalid CSR CN: {e}")))?;

        if csr_cn != expected_cn {
            return Err(KeyError::AuthorizationError(format!(
                "CSR CN {csr_cn} does not match peer identity {expected_cn}"
            )));
        }

        // Validate that peer_ski matches the CSR public key
        let csr_ski = runar_common::compact_ids::compact_id(&public_key_bytes);
        if peer_ski != csr_ski {
            return Err(KeyError::AuthorizationError(format!(
                "Peer SKI {peer_ski} does not match CSR public key SKI {csr_ski}"
            )));
        }

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

        Ok(RevokeResponse { ok: true })
    }

    /// Handle CA certificate chain request
    pub fn handle_chain(&self) -> Result<ChainResponse> {
        Ok(ChainResponse {
            issuing_ca_der: self.issuing_ca_cert.der_bytes().to_vec(),
            root_ca_der: Some(self.root_ca_cert.der_bytes().to_vec()),
        })
    }

    /// Handle CA status request
    pub fn handle_status(&self) -> Result<CaStatus> {
        // Extract subject and serial from issuing CA certificate
        let issuing_cert_der = self.issuing_ca_cert.der_bytes();
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(issuing_cert_der)
            .map_err(|e| {
                KeyError::ValidationError(format!("Invalid issuing CA certificate: {e}"))
            })?;

        let subject = cert.subject().to_string();
        let serial = cert.serial.to_string();
        let not_before = cert.validity().not_before.timestamp() as u64;
        let not_after = cert.validity().not_after.timestamp() as u64;

        Ok(CaStatus {
            issuing_subject: subject,
            issuing_serial_hex: serial,
            not_before,
            not_after,
        })
    }

    /// Generate CRL-lite
    pub fn generate_crl_lite(&self) -> Result<CaRevocationList> {
        let revoked_serials: Vec<RevokedSerial> =
            self.revoked_certificates.values().cloned().collect();

        // Get issuing CA serial
        let issuing_cert_der = self.issuing_ca_cert.der_bytes();
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(issuing_cert_der)
            .map_err(|e| {
                KeyError::ValidationError(format!("Invalid issuing CA certificate: {e}"))
            })?;
        let issuing_ca_serial = cert.serial.to_bytes_be();

        let mut crl = CaRevocationList {
            network_id: self.network_id.clone(),
            issuing_ca_serial,
            revoked_serials,
            next_update: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + 3600, // 1 hour from now
            signature: vec![], // Will be filled after signing
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
    pub fn handle_crl(&self) -> Result<CaRevocationList> {
        self.generate_crl_lite()
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::{CertificateAuthority, EcdsaKeyPair};

    #[test]
    fn test_ca_node_creation() -> Result<()> {
        // Create test CA
        let ca_authority = CertificateAuthority::new("CN=Test CA,O=Test,C=US")?;
        let ca_key = ca_authority.ca_key_pair().clone();
        let ca_cert = ca_authority.ca_certificate().clone();

        // Create root CA
        let root_authority = CertificateAuthority::new("CN=Test Root CA,O=Test,C=US")?;
        let root_cert = root_authority.ca_certificate().clone();

        let ca_node = CANode::new(ca_key, ca_cert, root_cert, "test_network".to_string());

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

        let mut ca_node = CANode::new(ca_key, ca_cert, root_cert, "test_network".to_string());

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

        let mut ca_node = CANode::new(ca_key, ca_cert, root_cert, "test_network".to_string());

        // Should allow initial requests (same token_id to share rate limit)
        for _ in 0..5 {
            assert!(ca_node.check_rate_limit("127.0.0.1", "test_token").is_ok());
        }

        // Should reject after burst limit
        assert!(ca_node.check_rate_limit("127.0.0.1", "test_token").is_err());

        Ok(())
    }
}
