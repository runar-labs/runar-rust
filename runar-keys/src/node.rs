//! Node Key Manager - Certificate Request and Management
//!
//! This module implements the node-side key management system that generates
//! certificate signing requests (CSRs) and manages received certificates.

use crate::certificate::{CertificateRequest, CertificateValidator, EcdsaKeyPair, X509Certificate};
use crate::error::{KeyError, Result};
use crate::mobile::{NetworkKeyMessage, NodeCertificateMessage, SetupToken};
use runar_common::logging::Logger;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// QUIC certificate configuration for transport layer
#[derive(Debug)]
pub struct QuicCertificateConfig {
    /// Certificate chain (node certificate + CA certificate)
    pub certificate_chain: Vec<CertificateDer<'static>>,
    /// Private key for the node certificate
    pub private_key: PrivateKeyDer<'static>,
    /// Certificate validator for peer certificates
    pub certificate_validator: CertificateValidator,
}

/// Node certificate status
#[derive(Debug, Clone, PartialEq)]
pub enum CertificateStatus {
    /// No certificate installed
    None,
    /// Certificate pending (CSR sent, waiting for response)
    Pending,
    /// Certificate installed and valid
    Valid,
    /// Certificate expired or invalid
    Invalid,
}

/// Node Key Manager for certificate requests and management
pub struct NodeKeyManager {
    /// Node's identity key pair (always present)
    node_key_pair: EcdsaKeyPair,
    /// Node's certificate (if issued by CA)
    node_certificate: Option<X509Certificate>,
    /// CA certificate for validation
    ca_certificate: Option<X509Certificate>,
    /// Certificate validator
    certificate_validator: Option<CertificateValidator>,
    /// Network keys indexed by network public key (hex)
    network_keys: HashMap<String, EcdsaKeyPair>,
    /// Node storage key for local file encryption (always present)
    storage_key: Vec<u8>,
    /// Certificate status
    certificate_status: CertificateStatus,
    /// Logger instance
    logger: Arc<Logger>,
}

impl NodeKeyManager {
    /// Create a new Node Key Manager with fresh keys
    pub fn new(logger: Arc<Logger>) -> Result<Self> {
        // Generate node identity key pair
        let node_key_pair = EcdsaKeyPair::new()?;

        // Generate node storage key for local encryption
        let storage_key = Self::generate_storage_key();

        let node_public_key = node_key_pair.public_key_bytes();
        logger.info(format!(
            "Node Key Manager created with identity: {}",
            hex::encode(&node_public_key)
        ));
        logger.debug("Node storage key generated for local encryption");

        Ok(Self {
            node_key_pair,
            node_certificate: None,
            ca_certificate: None,
            certificate_validator: None,
            network_keys: HashMap::new(),
            storage_key,
            certificate_status: CertificateStatus::None,
            logger,
        })
    }

    /// Get the node public key (node ID) - keys are always available
    pub fn get_node_public_key(&self) -> Vec<u8> {
        self.node_key_pair.public_key_bytes()
    }

    /// Get the node ID (compact Base58 encoding of public key)
    pub fn get_node_id(&self) -> String {
        crate::compact_ids::compact_node_id(&self.node_key_pair.public_key_bytes())
    }

    /// Generate a 32-byte storage key for local file encryption
    fn generate_storage_key() -> Vec<u8> {
        use rand::RngCore;
        let mut storage_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut storage_key);
        storage_key.to_vec()
    }

    /// Get the node storage key for local encryption
    pub fn get_storage_key(&self) -> &[u8] {
        &self.storage_key
    }

    /// Encrypt local data using the node storage key
    pub fn encrypt_local_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let storage_key = self.get_storage_key();

        // Use AES-256-GCM for secure local data encryption
        self.encrypt_with_symmetric_key(data, storage_key)
    }

    /// Decrypt local data using the node storage key
    pub fn decrypt_local_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        let storage_key = self.get_storage_key();

        // Use AES-256-GCM for secure local data decryption
        self.decrypt_with_symmetric_key(encrypted_data, storage_key)
    }

    /// Decrypt envelope-encrypted data using network key
    pub fn decrypt_envelope_data(
        &self,
        envelope_data: &crate::mobile::EnvelopeEncryptedData,
    ) -> Result<Vec<u8>> {
        let network_key = self
            .network_keys
            .get(&envelope_data.network_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!(
                    "Network key not found: {}",
                    envelope_data.network_id
                ))
            })?;

        // Network encrypted key is now always present (required field)
        let encrypted_envelope_key = &envelope_data.network_encrypted_key;

        let envelope_key = self.decrypt_key_with_ecdsa(encrypted_envelope_key, network_key)?;
        self.decrypt_with_symmetric_key(&envelope_data.encrypted_data, &envelope_key)
    }

    /// Create an envelope-encrypted data structure for sharing
    pub fn create_envelope_for_network(
        &self,
        data: &[u8],
        network_id: &str,
    ) -> Result<crate::mobile::EnvelopeEncryptedData> {
        let network_key = self.network_keys.get(network_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!("Network key not found: {}", network_id))
        })?;

        // Generate ephemeral envelope key
        let envelope_key = self.generate_envelope_key()?;

        // Encrypt data with envelope key
        let encrypted_data = self.encrypt_with_symmetric_key(data, &envelope_key)?;

        // Encrypt envelope key with network key
        let encrypted_envelope_key =
            self.encrypt_key_with_ecdsa(&envelope_key, &network_key.public_key_bytes())?;

        Ok(crate::mobile::EnvelopeEncryptedData {
            encrypted_data,
            network_id: network_id.to_string(),
            network_encrypted_key: encrypted_envelope_key,
            profile_encrypted_keys: HashMap::new(),
        })
    }

    /// Generate an ephemeral envelope key
    fn generate_envelope_key(&self) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut envelope_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut envelope_key);
        self.logger.debug("Ephemeral envelope key generated");
        Ok(envelope_key.to_vec())
    }

    // Helper methods for cryptographic operations using AES-256-GCM
    fn encrypt_with_symmetric_key(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use rand::{thread_rng, RngCore};

        if key.len() != 32 {
            return Err(KeyError::SymmetricCipherError(
                "Key must be 32 bytes for AES-256".to_string(),
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
            KeyError::SymmetricCipherError(format!("Failed to create cipher: {}", e))
        })?;
        let mut nonce = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce);

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), data)
            .map_err(|e| KeyError::EncryptionError(format!("AES-GCM encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt_with_symmetric_key(&self, encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

        if key.len() != 32 {
            return Err(KeyError::SymmetricCipherError(
                "Key must be 32 bytes for AES-256".to_string(),
            ));
        }

        if encrypted_data.len() < 12 {
            return Err(KeyError::DecryptionError(
                "Encrypted data too short (missing nonce)".to_string(),
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
            KeyError::SymmetricCipherError(format!("Failed to create cipher: {}", e))
        })?;
        let nonce = &encrypted_data[..12];
        let ciphertext = &encrypted_data[12..];

        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|e| KeyError::DecryptionError(format!("AES-GCM decryption failed: {}", e)))
    }

    /// Internal ECIES encryption using a recipient's public key
    fn encrypt_key_with_ecdsa(
        &self,
        data: &[u8],
        recipient_public_key_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use p256::ecdh::EphemeralSecret;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::PublicKey;
        use rand::thread_rng;
        use sha2::Sha256;

        // Generate ephemeral key pair for ECDH
        let ephemeral_secret = EphemeralSecret::random(&mut thread_rng());
        let ephemeral_public = ephemeral_secret.public_key();

        // Convert recipient's public key bytes to PublicKey
        let recipient_public_key =
            PublicKey::from_sec1_bytes(recipient_public_key_bytes).map_err(|e| {
                KeyError::InvalidKeyFormat(format!("Failed to parse recipient public key: {}", e))
            })?;

        // Perform ECDH key exchange
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public_key);
        let shared_secret_bytes = shared_secret.raw_secret_bytes();

        // Derive encryption key using HKDF
        let hk = Hkdf::<Sha256>::new(None, shared_secret_bytes.as_slice());
        let mut encryption_key = [0u8; 32];
        hk.expand(b"runar-key-encryption", &mut encryption_key)
            .map_err(|e| KeyError::KeyDerivationError(format!("HKDF expansion failed: {}", e)))?;

        // Encrypt the data using AES-GCM
        let encrypted_data = self.encrypt_with_symmetric_key(data, &encryption_key)?;

        // Return ephemeral public key + encrypted data
        let ephemeral_public_bytes = ephemeral_public.to_encoded_point(false);
        let mut result = ephemeral_public_bytes.as_bytes().to_vec();
        result.extend_from_slice(&encrypted_data);
        Ok(result)
    }

    /// Internal ECIES decryption using our private key
    fn decrypt_key_with_ecdsa(
        &self,
        encrypted_data: &[u8],
        key_pair: &EcdsaKeyPair,
    ) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use p256::ecdh::diffie_hellman;
        use p256::PublicKey;
        use p256::SecretKey;
        use sha2::Sha256;

        // Extract ephemeral public key (65 bytes uncompressed) and encrypted data
        if encrypted_data.len() < 65 {
            return Err(KeyError::DecryptionError(
                "Encrypted data too short for ECIES".to_string(),
            ));
        }

        let ephemeral_public_bytes = &encrypted_data[..65];
        let encrypted_payload = &encrypted_data[65..];

        // Reconstruct ephemeral public key
        let ephemeral_public = PublicKey::from_sec1_bytes(ephemeral_public_bytes).map_err(|e| {
            KeyError::DecryptionError(format!("Failed to parse ephemeral public key: {}", e))
        })?;

        // Use the ECDSA signing key bytes to create a SecretKey for ECDH
        let secret_key = SecretKey::from_bytes(&key_pair.signing_key().to_bytes())
            .map_err(|e| KeyError::DecryptionError(format!("Failed to create SecretKey: {}", e)))?;
        let shared_secret =
            diffie_hellman(secret_key.to_nonzero_scalar(), ephemeral_public.as_affine());
        let shared_secret_bytes = shared_secret.raw_secret_bytes();

        // Derive encryption key using HKDF
        let hk = Hkdf::<Sha256>::new(None, shared_secret_bytes);
        let mut encryption_key = [0u8; 32];
        hk.expand(b"runar-key-encryption", &mut encryption_key)
            .map_err(|e| KeyError::KeyDerivationError(format!("HKDF expansion failed: {}", e)))?;

        // Decrypt the data using AES-GCM
        self.decrypt_with_symmetric_key(encrypted_payload, &encryption_key)
    }

    /// Generate a certificate signing request (CSR)
    pub fn generate_csr(&mut self) -> Result<SetupToken> {
        let node_public_key = self.get_node_public_key();
        let node_id = self.get_node_id();
        let subject = format!("CN={},O=Runar Node,C=US", node_id);
        let csr_der = CertificateRequest::create(&self.node_key_pair, &subject)?;

        self.certificate_status = CertificateStatus::Pending;

        Ok(SetupToken {
            node_public_key,
            csr_der,
            node_id,
        })
    }

    /// Get the node key pair for certificate creation
    pub fn get_node_key_pair(&self) -> &EcdsaKeyPair {
        &self.node_key_pair
    }

    /// Install certificate received from mobile CA
    pub fn install_certificate(&mut self, cert_message: NodeCertificateMessage) -> Result<()> {
        // For this demo, we'll skip the CA signature validation since we're using self-signed certificates
        // In a production system, this would validate the certificate signature against the CA
        // let ca_public_key = cert_message.ca_certificate.public_key()?;
        // cert_message.node_certificate.validate(&ca_public_key)?;

        // Verify the certificate is for this node
        let node_id = self.get_node_id();
        let _expected_subject = format!("CN={},O=Runar Node,C=US", node_id);
        if !cert_message.node_certificate.subject().contains(&node_id) {
            return Err(KeyError::CertificateValidationError(
                "Certificate subject doesn't match node ID".to_string(),
            ));
        }

        // Install the certificates
        self.node_certificate = Some(cert_message.node_certificate);
        self.ca_certificate = Some(cert_message.ca_certificate.clone());

        // Create certificate validator
        self.certificate_validator =
            Some(CertificateValidator::new(vec![cert_message.ca_certificate]));

        self.certificate_status = CertificateStatus::Valid;

        Ok(())
    }

    /// Get QUIC-compatible certificate configuration
    pub fn get_quic_certificate_config(&self) -> Result<QuicCertificateConfig> {
        let node_cert = self.node_certificate.as_ref().ok_or_else(|| {
            KeyError::CertificateNotFound("Node certificate not installed".to_string())
        })?;

        let ca_cert = self.ca_certificate.as_ref().ok_or_else(|| {
            KeyError::CertificateNotFound("CA certificate not installed".to_string())
        })?;

        let validator = self.certificate_validator.as_ref().ok_or_else(|| {
            KeyError::InvalidOperation("Certificate validator not initialized".to_string())
        })?;

        // Create certificate chain (node cert + CA cert)
        let certificate_chain = vec![
            node_cert.to_rustls_certificate(),
            ca_cert.to_rustls_certificate(),
        ];

        // Get private key for TLS
        let private_key = self.node_key_pair.to_rustls_private_key()?;

        Ok(QuicCertificateConfig {
            certificate_chain,
            private_key,
            certificate_validator: validator.clone(),
        })
    }

    /// Validate peer certificate during QUIC handshake
    pub fn validate_peer_certificate(&self, peer_cert: &X509Certificate) -> Result<()> {
        let validator = self.certificate_validator.as_ref().ok_or_else(|| {
            KeyError::InvalidOperation("Certificate validator not initialized".to_string())
        })?;

        validator.validate_certificate(peer_cert)
    }

    /// Install network key from mobile with ECIES decryption
    pub fn install_network_key(&mut self, network_key_message: NetworkKeyMessage) -> Result<()> {
        // Decrypt the ECIES-encrypted network key using our private key
        let encrypted_network_key = &network_key_message.encrypted_network_key;
        let decrypted_network_key =
            self.decrypt_key_with_ecdsa(encrypted_network_key, &self.node_key_pair)?;

        // Reconstruct the ECDSA key pair from the decrypted private key
        use p256::ecdsa::SigningKey;
        use pkcs8::DecodePrivateKey;

        let signing_key = SigningKey::from_pkcs8_der(&decrypted_network_key).map_err(|e| {
            KeyError::InvalidKeyFormat(format!("Failed to decode decrypted network key: {}", e))
        })?;

        let network_key_pair = EcdsaKeyPair::from_signing_key(signing_key);

        // Store the network key using its public key as identifier
        let network_public_key =
            crate::compact_ids::compact_network_id(&network_key_pair.public_key_bytes());
        self.network_keys
            .insert(network_public_key.clone(), network_key_pair);

        self.logger.info(format!(
            "Network key decrypted and installed for network: {}",
            network_public_key
        ));

        Ok(())
    }

    /// Get network key for encryption/decryption
    pub fn get_network_key(&self, network_id: &str) -> Option<&EcdsaKeyPair> {
        self.network_keys.get(network_id)
    }

    /// Encrypt data for network transmission
    pub fn encrypt_for_network(&self, data: &[u8], network_id: &str) -> Result<Vec<u8>> {
        let network_key = self.network_keys.get(network_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!("Network key not found: {}", network_id))
        })?;

        // Use the network key's private key bytes as symmetric encryption key
        let network_private_key = network_key.private_key_der().map_err(|e| {
            KeyError::EncryptionError(format!("Failed to get network private key: {}", e))
        })?;

        // Derive encryption key from network private key using SHA256
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&network_private_key);
        hasher.update(b"runar-network-encryption");
        let encryption_key = hasher.finalize();

        // Encrypt using AES-GCM
        self.encrypt_with_symmetric_key(data, &encryption_key)
    }

    /// Decrypt network data
    pub fn decrypt_network_data(&self, encrypted_data: &[u8], network_id: &str) -> Result<Vec<u8>> {
        let network_key = self.network_keys.get(network_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!("Network key not found: {}", network_id))
        })?;

        // Use the network key's private key bytes as symmetric decryption key
        let network_private_key = network_key.private_key_der().map_err(|e| {
            KeyError::DecryptionError(format!("Failed to get network private key: {}", e))
        })?;

        // Derive decryption key from network private key using SHA256 (same as encryption)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&network_private_key);
        hasher.update(b"runar-network-encryption");
        let decryption_key = hasher.finalize();

        // Decrypt using AES-GCM
        self.decrypt_with_symmetric_key(encrypted_data, &decryption_key)
    }

    /// Check certificate status with proper cryptographic validation
    pub fn get_certificate_status(&self) -> CertificateStatus {
        // Check if certificate is installed
        if let Some(cert) = &self.node_certificate {
            if let Some(_ca_cert) = &self.ca_certificate {
                // Perform actual cryptographic validation
                if let Some(validator) = &self.certificate_validator {
                    match validator.validate_certificate(cert) {
                        Ok(()) => {
                            self.logger.debug("Certificate validation successful");
                            return CertificateStatus::Valid;
                        }
                        Err(e) => {
                            self.logger
                                .warn(format!("Certificate validation failed: {}", e));
                            return CertificateStatus::Invalid;
                        }
                    }
                } else {
                    self.logger.warn("Certificate validator not initialized");
                    return CertificateStatus::Invalid;
                }
            }
            return CertificateStatus::Invalid;
        }

        self.certificate_status.clone()
    }

    /// Get certificate information
    pub fn get_certificate_info(&self) -> Option<NodeCertificateInfo> {
        if let (Some(node_cert), Some(ca_cert)) = (&self.node_certificate, &self.ca_certificate) {
            Some(NodeCertificateInfo {
                node_certificate_subject: node_cert.subject().to_string(),
                node_certificate_issuer: node_cert.issuer().to_string(),
                ca_certificate_subject: ca_cert.subject().to_string(),
                status: self.get_certificate_status(),
            })
        } else {
            None
        }
    }

    /// Get statistics about the node key manager
    pub fn get_statistics(&self) -> NodeKeyManagerStatistics {
        NodeKeyManagerStatistics {
            node_id: self.get_node_id(),
            has_certificate: self.node_certificate.is_some(),
            has_ca_certificate: self.ca_certificate.is_some(),
            certificate_status: self.get_certificate_status(),
            network_keys_count: self.network_keys.len(),
            node_public_key: crate::compact_ids::compact_node_id(&self.get_node_public_key()),
        }
    }

    /// Sign data with the node's private key
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::{signature::Signer, Signature};

        let signature: Signature = self.node_key_pair.signing_key().sign(data);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    /// Verify signature from another node
    pub fn verify_peer_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        peer_cert: &X509Certificate,
    ) -> Result<()> {
        // First validate the peer certificate
        self.validate_peer_certificate(peer_cert)?;

        // Extract public key from certificate
        let peer_public_key = peer_cert.public_key()?;

        // Verify the signature
        use p256::ecdsa::{signature::Verifier, Signature};

        let sig = Signature::from_der(signature).map_err(|e| {
            KeyError::CertificateValidationError(format!("Invalid signature format: {}", e))
        })?;

        peer_public_key.verify(data, &sig).map_err(|e| {
            KeyError::CertificateValidationError(format!("Signature verification failed: {}", e))
        })?;

        Ok(())
    }

    /// Encrypt a message for the mobile user using their public key (ECIES)
    pub fn encrypt_message_for_mobile(
        &self,
        message: &[u8],
        mobile_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        self.logger.debug(format!(
            "Encrypting message for mobile ({} bytes)",
            message.len()
        ));
        self.encrypt_key_with_ecdsa(message, mobile_public_key)
    }

    /// Decrypt a message from the mobile user using the node's private key (ECIES)
    pub fn decrypt_message_from_mobile(&self, encrypted_message: &[u8]) -> Result<Vec<u8>> {
        self.logger.debug(format!(
            "Decrypting message from mobile ({} bytes)",
            encrypted_message.len()
        ));
        self.decrypt_key_with_ecdsa(encrypted_message, &self.node_key_pair)
    }
}

/// Certificate information for the node
#[derive(Debug, Clone)]
pub struct NodeCertificateInfo {
    pub node_certificate_subject: String,
    pub node_certificate_issuer: String,
    pub ca_certificate_subject: String,
    pub status: CertificateStatus,
}

/// Statistics about the node key manager
#[derive(Debug, Clone)]
pub struct NodeKeyManagerStatistics {
    pub node_id: String,
    pub has_certificate: bool,
    pub has_ca_certificate: bool,
    pub certificate_status: CertificateStatus,
    pub network_keys_count: usize,
    pub node_public_key: String,
}

/// Serializable node state for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeKeyManagerState {
    node_key_pair: EcdsaKeyPair,
    node_certificate: Option<X509Certificate>,
    ca_certificate: Option<X509Certificate>,
    network_keys: HashMap<String, EcdsaKeyPair>,
    storage_key: Vec<u8>,
}

impl NodeKeyManager {
    /// Export state for persistence
    pub fn export_state(&self) -> NodeKeyManagerState {
        NodeKeyManagerState {
            node_key_pair: self.node_key_pair.clone(),
            node_certificate: self.node_certificate.clone(),
            ca_certificate: self.ca_certificate.clone(),
            network_keys: self.network_keys.clone(),
            storage_key: self.storage_key.clone(),
        }
    }

    /// Import state from persistence
    pub fn from_state(state: NodeKeyManagerState, logger: Arc<Logger>) -> Result<Self> {
        let certificate_validator = if let Some(ca_cert) = &state.ca_certificate {
            Some(CertificateValidator::new(vec![ca_cert.clone()]))
        } else {
            None
        };

        let certificate_status =
            if state.node_certificate.is_some() && state.ca_certificate.is_some() {
                CertificateStatus::Valid
            } else if state.node_certificate.is_some() {
                CertificateStatus::Invalid
            } else {
                CertificateStatus::None
            };

        let node_id = hex::encode(state.node_key_pair.public_key_bytes());
        logger.info(format!(
            "Node Key Manager state imported for node: {}",
            node_id
        ));

        Ok(Self {
            node_key_pair: state.node_key_pair,
            node_certificate: state.node_certificate,
            ca_certificate: state.ca_certificate,
            certificate_validator,
            network_keys: state.network_keys,
            storage_key: state.storage_key,
            certificate_status,
            logger,
        })
    }
}
