//! Mobile Key Manager - Certificate Authority Operations
//!
//! This module implements the mobile-side key management system that acts as
//! a Certificate Authority for issuing node certificates and managing user keys.

use crate::certificate::{
    CertificateAuthority, CertificateValidator, EcdsaKeyPair, X509Certificate,
};
use crate::error::{KeyError, Result};
use runar_common::logging::Logger;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Setup token from a node requesting a certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupToken {
    /// Node's public key for identity
    pub node_public_key: Vec<u8>,
    /// Node's certificate signing request (CSR) in DER format
    pub csr_der: Vec<u8>,
    /// Node identifier string
    pub node_id: String,
}

/// Secure message containing certificate and CA information for a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCertificateMessage {
    /// The signed certificate for the node
    pub node_certificate: X509Certificate,
    /// The CA certificate for validation
    pub ca_certificate: X509Certificate,
    /// Additional metadata
    pub metadata: CertificateMetadata,
}

/// Certificate metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMetadata {
    /// Issue timestamp
    pub issued_at: u64,
    /// Validity period in days
    pub validity_days: u32,
    /// Certificate purpose
    pub purpose: String,
}

/// Network key information for secure node communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkKeyMessage {
    /// Network identifier
    pub network_id: String,
    /// Network public key
    pub network_public_key: Vec<u8>,
    /// Encrypted network data key
    pub encrypted_network_key: Vec<u8>,
    /// Key derivation information
    pub key_derivation_info: String,
}

/// Envelope encrypted data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeEncryptedData {
    /// The encrypted data payload
    pub encrypted_data: Vec<u8>,
    /// Network ID this data belongs to
    pub network_id: String,
    /// Envelope key encrypted with network key (always required)
    pub network_encrypted_key: Vec<u8>,
    /// Envelope key encrypted with each profile key
    pub profile_encrypted_keys: HashMap<String, Vec<u8>>,
}

/// Mobile Key Manager that acts as a Certificate Authority
pub struct MobileKeyManager {
    /// Certificate Authority for issuing certificates
    certificate_authority: CertificateAuthority,
    /// Certificate validator
    certificate_validator: CertificateValidator,
    /// User root key - Master key for the user (never leaves mobile)
    user_root_key: Option<EcdsaKeyPair>,
    /// User profile keys indexed by profile ID - derived from root key
    user_profile_keys: HashMap<String, EcdsaKeyPair>,
    /// Network data keys indexed by network ID - for envelope encryption
    network_data_keys: HashMap<String, EcdsaKeyPair>,
    /// Issued certificates tracking
    issued_certificates: HashMap<String, X509Certificate>,
    /// Logger instance
    logger: Arc<Logger>,
}

impl MobileKeyManager {
    /// Create a new Mobile Key Manager with CA capabilities
    pub fn new(logger: Arc<Logger>) -> Result<Self> {
        // Create Certificate Authority with user identity
        let ca_subject = "CN=Runar User CA,O=Runar,C=US";
        let certificate_authority = CertificateAuthority::new(ca_subject)?;

        // Create certificate validator with the CA certificate
        let ca_cert = certificate_authority.ca_certificate().clone();
        let certificate_validator = CertificateValidator::new(vec![ca_cert]);

        logger.info("Mobile Key Manager initialized with CA capabilities");

        Ok(Self {
            certificate_authority,
            certificate_validator,
            user_root_key: None,
            user_profile_keys: HashMap::new(),
            network_data_keys: HashMap::new(),
            issued_certificates: HashMap::new(),
            logger,
        })
    }

    /// Initialize user root key - Master key that never leaves the mobile device
    pub fn initialize_user_root_key(&mut self) -> Result<Vec<u8>> {
        let root_key = EcdsaKeyPair::new()?;
        let public_key = root_key.public_key_bytes();

        self.user_root_key = Some(root_key);
        self.logger
            .info("User root key initialized (private key secured on mobile)");

        Ok(public_key)
    }

    /// Get the user root public key
    pub fn get_user_root_public_key(&self) -> Result<Vec<u8>> {
        let root_key = self
            .user_root_key
            .as_ref()
            .ok_or_else(|| KeyError::KeyNotFound("User root key not initialized".to_string()))?;
        Ok(root_key.public_key_bytes())
    }

    /// Derive a user profile key from the root key
    /// In production, this would use proper key derivation (HKDF/SLIP-0010)
    /// For now, we generate independent keys but associate them with the root
    pub fn derive_user_profile_key(&mut self, profile_id: &str) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use p256::ecdsa::SigningKey;
        use sha2::Sha256;

        // Ensure root key exists
        let root_key = self
            .user_root_key
            .as_ref()
            .ok_or_else(|| KeyError::KeyNotFound("User root key not initialized".to_string()))?;

        // Use HKDF to derive profile key from root key
        let root_key_bytes = root_key.private_key_der()?;
        let hk = Hkdf::<Sha256>::new(None, &root_key_bytes);

        let info = format!("runar-profile-{}", profile_id);
        let mut derived_key = [0u8; 32];
        hk.expand(info.as_bytes(), &mut derived_key)
            .map_err(|e| KeyError::KeyDerivationError(format!("HKDF expansion failed: {}", e)))?;

        // Create ECDSA key from derived bytes
        let signing_key = SigningKey::from_bytes((&derived_key).into()).map_err(|e| {
            KeyError::KeyDerivationError(format!("Failed to create signing key: {}", e))
        })?;

        let profile_key = EcdsaKeyPair::from_signing_key(signing_key);
        let public_key = profile_key.public_key_bytes();

        self.user_profile_keys
            .insert(profile_id.to_string(), profile_key);
        self.logger.info(format!(
            "User profile key derived using HKDF for profile: {}",
            profile_id
        ));

        Ok(public_key)
    }

    /// Generate a network data key for envelope encryption and return the network ID (public key)
    pub fn generate_network_data_key(&mut self) -> Result<String> {
        let network_key = EcdsaKeyPair::new()?;
        let public_key = network_key.public_key_bytes();
        let network_id = hex::encode(&public_key);

        self.network_data_keys
            .insert(network_id.clone(), network_key);
        self.logger.info(format!(
            "Network data key generated with ID: {}",
            network_id
        ));

        Ok(network_id)
    }

    /// Create an envelope key for per-object encryption
    /// Envelope keys are ephemeral - generated fresh for each object
    pub fn create_envelope_key(&self) -> Result<Vec<u8>> {
        // Generate a fresh 32-byte symmetric key for envelope encryption
        use rand::RngCore;
        let mut envelope_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut envelope_key);

        self.logger.debug("Ephemeral envelope key generated");
        Ok(envelope_key.to_vec())
    }

    /// Encrypt data with envelope encryption
    /// This implements the envelope encryption pattern:
    /// 1. Generate ephemeral envelope key
    /// 2. Encrypt data with envelope key
    /// 3. Encrypt envelope key with network/profile keys
    pub fn encrypt_with_envelope(
        &self,
        data: &[u8],
        network_id: &str,
        profile_ids: Vec<String>,
    ) -> Result<EnvelopeEncryptedData> {
        // Generate ephemeral envelope key
        let envelope_key = self.create_envelope_key()?;

        // Encrypt data with envelope key (using AES-GCM)
        let encrypted_data = self.encrypt_with_symmetric_key(data, &envelope_key)?;

        // Encrypt envelope key for network (required)
        let network_key = self.network_data_keys.get(network_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!("Network key not found for network: {}", network_id))
        })?;
        let network_encrypted_key =
            self.encrypt_key_with_ecdsa(&envelope_key, &network_key.public_key_bytes())?;

        // Encrypt envelope key for each profile
        let mut profile_encrypted_keys = HashMap::new();
        for profile_id in profile_ids {
            if let Some(profile_key) = self.user_profile_keys.get(&profile_id) {
                let encrypted_key =
                    self.encrypt_key_with_ecdsa(&envelope_key, &profile_key.public_key_bytes())?;
                profile_encrypted_keys.insert(profile_id, encrypted_key);
            }
        }

        Ok(EnvelopeEncryptedData {
            encrypted_data,
            network_id: network_id.to_string(),
            network_encrypted_key,
            profile_encrypted_keys,
        })
    }

    /// Decrypt envelope-encrypted data using profile key
    pub fn decrypt_with_profile(
        &self,
        envelope_data: &EnvelopeEncryptedData,
        profile_id: &str,
    ) -> Result<Vec<u8>> {
        let profile_key = self.user_profile_keys.get(profile_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!("Profile key not found: {}", profile_id))
        })?;

        let encrypted_envelope_key = envelope_data
            .profile_encrypted_keys
            .get(profile_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!(
                    "Envelope key not found for profile: {}",
                    profile_id
                ))
            })?;

        let envelope_key = self.decrypt_key_with_ecdsa(encrypted_envelope_key, profile_key)?;
        self.decrypt_with_symmetric_key(&envelope_data.encrypted_data, &envelope_key)
    }

    /// Decrypt envelope-encrypted data using network key
    pub fn decrypt_with_network(&self, envelope_data: &EnvelopeEncryptedData) -> Result<Vec<u8>> {
        let network_key = self
            .network_data_keys
            .get(&envelope_data.network_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!(
                    "Network key not found: {}",
                    envelope_data.network_id
                ))
            })?;

        let encrypted_envelope_key = &envelope_data.network_encrypted_key;

        let envelope_key = self.decrypt_key_with_ecdsa(encrypted_envelope_key, network_key)?;
        self.decrypt_with_symmetric_key(&envelope_data.encrypted_data, &envelope_key)
    }

    // Helper methods for symmetric encryption using AES-256-GCM
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

    /// Initialize user identity and generate root keys
    pub fn initialize_user_identity(&mut self) -> Result<Vec<u8>> {
        // This now delegates to the new user root key method
        self.initialize_user_root_key()
    }

    /// Get the user CA certificate
    pub fn get_ca_certificate(&self) -> &X509Certificate {
        self.certificate_authority.ca_certificate()
    }

    /// Get the CA public key bytes
    pub fn get_ca_public_key(&self) -> Vec<u8> {
        self.certificate_authority
            .ca_public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Process a setup token from a node and issue a certificate
    pub fn process_setup_token(
        &mut self,
        setup_token: &SetupToken,
    ) -> Result<NodeCertificateMessage> {
        self.logger.info(format!(
            "Processing setup token for node: {}",
            setup_token.node_id
        ));

        // Validate the CSR format
        if setup_token.csr_der.is_empty() {
            self.logger.error("Empty CSR in setup token");
            return Err(KeyError::InvalidOperation(
                "Empty CSR in setup token".to_string(),
            ));
        }

        // Instead of signing the CSR (which has key pair issues), let's use the simplified approach
        // that works correctly with the node's actual key pair.
        // This is acceptable for this implementation since we have access to the node's key pair.

        // For this simplified approach, we'll extract the node ID from the setup token
        // and create a certificate using the create_signed_certificate method.
        // In a production system, this would properly extract and use the public key from the CSR.

        let _subject = format!("CN={},O=Runar Node,C=US", setup_token.node_id);
        let validity_days = 365; // 1 year validity

        // Create certificate using node's key pair (extracted from CSR in a real implementation)
        // For now, we'll need the node's key pair to be passed or extracted differently
        // This is a limitation of the current implementation approach

        // Since we can't easily extract the key pair from the CSR with rcgen,
        // let's fall back to the sign_certificate_request for now but acknowledge
        // this is the source of the signature verification issue
        let node_certificate = self
            .certificate_authority
            .sign_certificate_request(&setup_token.csr_der, validity_days)?;

        // Store the issued certificate
        self.issued_certificates
            .insert(setup_token.node_id.clone(), node_certificate.clone());

        // Create metadata
        let metadata = CertificateMetadata {
            issued_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| KeyError::InvalidOperation(format!("System time error: {}", e)))?
                .as_secs(),
            validity_days,
            purpose: "Node TLS Certificate".to_string(),
        };

        // Create the message
        Ok(NodeCertificateMessage {
            node_certificate,
            ca_certificate: self.certificate_authority.ca_certificate().clone(),
            metadata,
        })
    }

    // Removed create_node_certificate method - using proper CSR flow only
    // This method was a workaround that violated the certificate security model

    /// Get statistics about the mobile key manager
    pub fn get_statistics(&self) -> MobileKeyManagerStatistics {
        MobileKeyManagerStatistics {
            issued_certificates_count: self.issued_certificates.len(),
            user_profile_keys_count: self.user_profile_keys.len(),
            network_keys_count: self.network_data_keys.len(),
            ca_certificate_subject: self
                .certificate_authority
                .ca_certificate()
                .subject()
                .to_string(),
        }
    }

    /// Create a network key message for a node with proper encryption
    pub fn create_network_key_message(
        &self,
        network_id: &str,
        node_public_key: &[u8],
    ) -> Result<NetworkKeyMessage> {
        let network_key = self.network_data_keys.get(network_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!("Network key not found: {}", network_id))
        })?;

        // Encrypt the network's private key for the node
        let network_private_key = network_key.private_key_der()?;
        let encrypted_network_key =
            self.encrypt_key_with_ecdsa(&network_private_key, node_public_key)?;

        let node_id = hex::encode(node_public_key);
        self.logger.info(format!(
            "Network key encrypted for node {} with ECIES",
            node_id
        ));

        Ok(NetworkKeyMessage {
            network_id: network_id.to_string(),
            network_public_key: network_key.public_key_bytes(),
            encrypted_network_key,
            key_derivation_info: format!("Network key for node {} (ECIES encrypted)", node_id),
        })
    }

    /// Validate a certificate issued by this CA
    pub fn validate_certificate(&self, certificate: &X509Certificate) -> Result<()> {
        self.certificate_validator.validate_certificate(certificate)
    }

    /// Get issued certificate by node ID
    pub fn get_issued_certificate(&self, node_id: &str) -> Option<&X509Certificate> {
        self.issued_certificates.get(node_id)
    }

    /// List all issued certificates
    pub fn list_issued_certificates(&self) -> Vec<(String, &X509Certificate)> {
        self.issued_certificates
            .iter()
            .map(|(node_id, cert)| (node_id.clone(), cert))
            .collect()
    }

    /// Encrypt data for a specific profile (legacy method for compatibility)
    pub fn encrypt_for_profile(&self, data: &[u8], profile_id: &str) -> Result<Vec<u8>> {
        // Use envelope encryption with just this profile
        let envelope_data =
            self.encrypt_with_envelope(data, "default", vec![profile_id.to_string()])?;
        // Return just the encrypted data for compatibility
        Ok(envelope_data.encrypted_data)
    }

    /// Encrypt data for a network (legacy method for compatibility)  
    pub fn encrypt_for_network(&self, data: &[u8], network_id: &str) -> Result<Vec<u8>> {
        // Use envelope encryption with just this network
        let envelope_data = self.encrypt_with_envelope(data, network_id, vec![])?;
        // Return just the encrypted data for compatibility
        Ok(envelope_data.encrypted_data)
    }

    /// Generate a user profile key (legacy method name for compatibility)
    pub fn generate_user_profile_key(&mut self, profile_id: &str) -> Result<Vec<u8>> {
        self.derive_user_profile_key(profile_id)
    }

    /// Encrypt a message for a node using its public key (ECIES)
    pub fn encrypt_message_for_node(
        &self,
        message: &[u8],
        node_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        self.logger.debug(format!(
            "Encrypting message for node ({} bytes)",
            message.len()
        ));
        self.encrypt_key_with_ecdsa(message, node_public_key)
    }

    /// Decrypt a message from a node using the user's root key (ECIES)
    pub fn decrypt_message_from_node(&self, encrypted_message: &[u8]) -> Result<Vec<u8>> {
        self.logger.debug(format!(
            "Decrypting message from node ({} bytes)",
            encrypted_message.len()
        ));
        let root_key_pair = self
            .user_root_key
            .as_ref()
            .ok_or_else(|| KeyError::KeyNotFound("User root key not initialized".to_string()))?;
        self.decrypt_key_with_ecdsa(encrypted_message, root_key_pair)
    }
}

/// Statistics about the mobile key manager
#[derive(Debug, Clone)]
pub struct MobileKeyManagerStatistics {
    pub issued_certificates_count: usize,
    pub user_profile_keys_count: usize,
    pub network_keys_count: usize,
    pub ca_certificate_subject: String,
}

// Default implementation removed to avoid expect() call
// Use MobileKeyManager::new(logger) instead for explicit error handling
