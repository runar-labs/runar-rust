//! Node Key Manager - Certificate Request and Management
//!
//! This module implements the node-side key management system that generates
//! certificate signing requests (CSRs) and manages received certificates.

use crate::certificate::{CertificateRequest, CertificateValidator, EcdsaKeyPair, X509Certificate};
use crate::error::{KeyError, Result};
use crate::mobile::{EnvelopeEncryptedData, NetworkKeyMessage, NodeCertificateMessage, SetupToken};
use crate::{log_debug, log_info, log_warn};
// use p256::ecdsa::SigningKey; // no longer needed here
use crate::keystore::{
    persistence::{load_state, save_state, PersistenceConfig, Role},
    DeviceKeystore,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey as P256SecretKey;
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::RngCore;
use runar_common::compact_ids::compact_id;
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
    /// Network agreement secrets indexed by network id
    network_agreements: HashMap<String, P256SecretKey>,

    /// Network public keys indexed by network id
    network_public_keys: HashMap<String, Vec<u8>>,

    /// Known user profile public keys (id -> public key bytes)
    profile_public_keys: HashMap<String, Vec<u8>>,
    /// Symmetric keys indexed by key name for services
    symmetric_keys: HashMap<String, Vec<u8>>,
    /// Node storage key for local file encryption (always present)
    storage_key: Vec<u8>,
    /// Node agreement private key (used for ECIES)
    node_agreement_secret: P256SecretKey,
    /// Certificate status
    certificate_status: CertificateStatus,
    /// Logger instance
    logger: Arc<Logger>,
    /// Optional device keystore for on-device encrypted persistence
    device_keystore: Option<Arc<dyn DeviceKeystore>>,
    /// Optional persistence configuration
    persistence: Option<PersistenceConfig>,
    /// If true, persist state automatically after mutations
    auto_persist: bool,
}

impl NodeKeyManager {
    /// Create a new Node Key Manager with fresh keys
    pub fn new(logger: Arc<Logger>) -> Result<Self> {
        // Generate node identity key pair
        let node_key_pair = EcdsaKeyPair::new()?;

        // Derive node storage key (HKDF-SHA-256 from node identity master)
        let storage_key = {
            use hkdf::Hkdf;
            use sha2::Sha256;
            let ikm = node_key_pair.signing_key().to_bytes();
            let hk = Hkdf::<Sha256>::new(Some(b"RunarKeyDerivationSalt/v1"), ikm.as_slice());
            let mut key = [0u8; 32];
            hk.expand(b"runar-v1:node-identity:storage", &mut key)
                .map_err(|e| KeyError::KeyDerivationError(format!("HKDF expansion failed: {e}")))?;
            key.to_vec()
        };

        // Derive node agreement key from node master signing key
        let node_agreement_secret = crate::derivation::derive_agreement_from_master(
            &node_key_pair.signing_key().to_bytes(),
            b"runar-v1:node-identity:agreement",
        )?;

        let node_public_key = node_key_pair.public_key_bytes();
        let node_public_key_str = compact_id(&node_public_key);
        log_info!(
            logger,
            "Node Key Manager created with identity: {node_public_key_str}"
        );
        log_debug!(logger, "Node storage key generated for local encryption");

        Ok(Self {
            node_key_pair,
            node_certificate: None,
            ca_certificate: None,
            certificate_validator: None,
            network_agreements: HashMap::new(),
            network_public_keys: HashMap::new(),
            symmetric_keys: HashMap::new(),
            storage_key,
            node_agreement_secret,
            certificate_status: CertificateStatus::None,
            logger,
            profile_public_keys: HashMap::new(),
            device_keystore: None,
            persistence: None,
            auto_persist: true,
        })
    }

    /// Configure the persistence base directory.
    pub fn set_persistence_dir(&mut self, base_dir: std::path::PathBuf) {
        self.persistence = Some(PersistenceConfig::new(base_dir));
    }

    /// Register a device keystore used to encrypt/decrypt persisted state.
    pub fn register_device_keystore(&mut self, keystore: Arc<dyn DeviceKeystore>) {
        self.device_keystore = Some(keystore);
    }

    /// Enable or disable auto persistence.
    pub fn enable_auto_persist(&mut self, enabled: bool) {
        self.auto_persist = enabled;
        if enabled {
            let _ = self.flush_state();
        }
    }

    /// Attempt to load state from disk using the configured keystore.
    /// Returns true if state was loaded, false if not found.
    pub fn probe_and_load_state(&mut self) -> crate::Result<bool> {
        let (Some(keystore), Some(cfg)) = (self.device_keystore.clone(), self.persistence.clone())
        else {
            return Ok(false);
        };
        let node_id = self.get_node_id();
        let role = Role::Node { node_id: &node_id };
        match load_state(&keystore, &cfg, &role) {
            Ok(Some(bytes)) => {
                match serde_cbor::from_slice::<crate::node::NodeKeyManagerState>(&bytes) {
                    Ok(state) => {
                        let logger = self.logger.clone();
                        let (device_keystore, persistence, auto_persist) = (
                            self.device_keystore.clone(),
                            self.persistence.clone(),
                            self.auto_persist,
                        );
                        if let Ok(new_self) = NodeKeyManager::from_state(state, logger) {
                            *self = new_self;
                            self.device_keystore = device_keystore;
                            self.persistence = persistence;
                            self.auto_persist = auto_persist;
                            return Ok(true);
                        }
                    }
                    Err(_) => {}
                }
                Ok(false)
            }
            Ok(None) => Ok(false),
            Err(_) => Ok(false),
        }
    }

    /// Persist current state if auto-persist is enabled and keystore/persistence are configured.
    pub fn flush_state(&self) -> crate::Result<()> {
        if let (Some(keystore), Some(cfg)) =
            (self.device_keystore.as_ref(), self.persistence.as_ref())
        {
            let state = self.export_state();
            let bytes = serde_cbor::to_vec(&state).map_err(|e| {
                KeyError::EncodingError(format!("Failed to encode node state: {e}"))
            })?;
            let node_id = self.get_node_id();
            save_state(keystore, cfg, &Role::Node { node_id: &node_id }, &bytes)?;
        }
        Ok(())
    }

    fn persist_if_enabled(&self) {
        if self.auto_persist {
            let _ = self.flush_state();
        }
    }

    /// Query keystore capabilities if a device keystore is configured.
    pub fn get_keystore_caps(&self) -> Option<crate::keystore::DeviceKeystoreCaps> {
        self.device_keystore.as_ref().map(|k| k.capabilities())
    }

    /// Wipe persisted state file (if configured)
    pub fn wipe_persistence(&self) -> crate::Result<()> {
        if let Some(cfg) = &self.persistence {
            let id = self.get_node_id();
            crate::keystore::persistence::wipe(cfg, &Role::Node { node_id: &id })?;
        }
        Ok(())
    }

    /// Get the node public key (node ID) - keys are always available
    pub fn get_node_public_key(&self) -> Vec<u8> {
        self.node_key_pair.public_key_bytes()
    }

    /// Get the node ID (compact Base58 encoding of public key)
    pub fn get_node_id(&self) -> String {
        compact_id(&self.node_key_pair.public_key_bytes())
    }

    // Removed random storage key generator; storage keys are derived via HKDF from the node master key

    /// Get the node storage key for local encryption
    pub fn get_storage_key(&self) -> &[u8] {
        &self.storage_key
    }

    /// Ensure a symmetric key exists with the given name, creating it if it doesn't exist
    pub fn ensure_symmetric_key(&mut self, key_name: &str) -> Result<Vec<u8>> {
        if let Some(key) = self.symmetric_keys.get(key_name) {
            return Ok(key.clone());
        }

        // Generate a new 32-byte symmetric key
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let key_vec = key.to_vec();

        // Store the key for future use
        self.symmetric_keys
            .insert(key_name.to_string(), key_vec.clone());

        log_debug!(self.logger, "Generated new symmetric key: {key_name}");
        Ok(key_vec)
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
        let network_id = envelope_data
            .network_id
            .as_ref()
            .ok_or_else(|| KeyError::DecryptionError("Envelope missing network_id".to_string()))?;

        let network_key_pair = self.network_agreements.get(network_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!(
                "Network key pair not found for network: {network_id}"
            ))
        })?;

        // Ensure the encrypted envelope key is present
        let encrypted_envelope_key = &envelope_data.network_encrypted_key;
        if encrypted_envelope_key.is_empty() {
            return Err(KeyError::DecryptionError(
                "Envelope missing network_encrypted_key".to_string(),
            ));
        }

        let envelope_key =
            self.decrypt_key_with_agreement(encrypted_envelope_key, network_key_pair)?;
        self.decrypt_with_symmetric_key(&envelope_data.encrypted_data, &envelope_key)
    }

    /// Create an envelope-encrypted data structure for sharing
    pub fn create_envelope_for_network(
        &self,
        data: &[u8],
        network_id: Option<&str>,
    ) -> Result<crate::mobile::EnvelopeEncryptedData> {
        let network_id = network_id
            .ok_or_else(|| KeyError::DecryptionError("Missing network_id".to_string()))?;

        let network_public_key_bytes = self.get_network_public_key(network_id)?;

        // Generate ephemeral envelope key
        let envelope_key = self.generate_envelope_key()?;

        // Encrypt data with envelope key
        let encrypted_data = self.encrypt_with_symmetric_key(data, &envelope_key)?;

        // Encrypt envelope key with network key
        let encrypted_envelope_key =
            self.encrypt_key_with_ecdsa(&envelope_key, &network_public_key_bytes)?;

        Ok(crate::mobile::EnvelopeEncryptedData {
            encrypted_data,
            network_id: Some(network_id.to_string()),
            network_encrypted_key: encrypted_envelope_key,
            profile_encrypted_keys: HashMap::new(),
        })
    }

    /// Generate an ephemeral envelope key
    fn generate_envelope_key(&self) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut envelope_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut envelope_key);
        log_debug!(self.logger, "Ephemeral envelope key generated");
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

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| KeyError::SymmetricCipherError(format!("Failed to create cipher: {e}")))?;
        let mut nonce = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce);

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), data)
            .map_err(|e| KeyError::EncryptionError(format!("AES-GCM encryption failed: {e}")))?;

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

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| KeyError::SymmetricCipherError(format!("Failed to create cipher: {e}")))?;
        let nonce = &encrypted_data[..12];
        let ciphertext = &encrypted_data[12..];

        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|e| KeyError::DecryptionError(format!("AES-GCM decryption failed: {e}")))
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
                KeyError::InvalidKeyFormat(format!("Failed to parse recipient public key: {e}"))
            })?;

        // Perform ECDH key exchange
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public_key);
        let shared_secret_bytes = shared_secret.raw_secret_bytes();

        // Derive encryption key using HKDF-SHA-256
        let hk = Hkdf::<Sha256>::new(None, shared_secret_bytes.as_slice());
        let mut encryption_key = [0u8; 32];
        hk.expand(b"runar-v1:ecies:envelope-key", &mut encryption_key)
            .map_err(|e| KeyError::KeyDerivationError(format!("HKDF expansion failed: {e}")))?;

        // Encrypt the data using AES-GCM
        let encrypted_data = self.encrypt_with_symmetric_key(data, &encryption_key)?;

        // Return ephemeral public key (97 bytes uncompressed) + encrypted data
        let ephemeral_public_bytes = ephemeral_public.to_encoded_point(false);
        let mut result = ephemeral_public_bytes.as_bytes().to_vec();
        result.extend_from_slice(&encrypted_data);
        Ok(result)
    }

    /// Internal ECIES decryption using our private key
    fn decrypt_key_with_ecdsa(
        &self,
        encrypted_data: &[u8],
        _key_pair: &EcdsaKeyPair,
    ) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use p256::ecdh::diffie_hellman;
        use p256::PublicKey;
        // use p256::SecretKey;
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
            KeyError::DecryptionError(format!("Failed to parse ephemeral public key: {e}"))
        })?;

        // Use node's agreement secret for ECDH
        let shared_secret = diffie_hellman(
            self.node_agreement_secret.to_nonzero_scalar(),
            ephemeral_public.as_affine(),
        );
        let shared_secret_bytes = shared_secret.raw_secret_bytes();

        // Derive encryption key using HKDF-SHA-256
        let hk = Hkdf::<Sha256>::new(None, shared_secret_bytes);
        let mut encryption_key = [0u8; 32];
        hk.expand(b"runar-v1:ecies:envelope-key", &mut encryption_key)
            .map_err(|e| KeyError::KeyDerivationError(format!("HKDF expansion failed: {e}")))?;

        // Decrypt the data using AES-GCM
        self.decrypt_with_symmetric_key(encrypted_payload, &encryption_key)
    }

    /// Internal ECIES decryption using an agreement private key
    fn decrypt_key_with_agreement(
        &self,
        encrypted_data: &[u8],
        agreement_secret: &P256SecretKey,
    ) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use p256::ecdh::diffie_hellman;
        use p256::PublicKey;
        use sha2::Sha256;

        if encrypted_data.len() < 65 {
            return Err(KeyError::DecryptionError(
                "Encrypted data too short for ECIES".to_string(),
            ));
        }

        let ephemeral_public_bytes = &encrypted_data[..65];
        let encrypted_payload = &encrypted_data[65..];

        let ephemeral_public = PublicKey::from_sec1_bytes(ephemeral_public_bytes).map_err(|e| {
            KeyError::DecryptionError(format!("Failed to parse ephemeral public key: {e}"))
        })?;

        let shared_secret = diffie_hellman(
            agreement_secret.to_nonzero_scalar(),
            ephemeral_public.as_affine(),
        );
        let shared_secret_bytes = shared_secret.raw_secret_bytes();

        let hk = Hkdf::<Sha256>::new(None, shared_secret_bytes);
        let mut encryption_key = [0u8; 32];
        hk.expand(b"runar-v1:ecies:envelope-key", &mut encryption_key)
            .map_err(|e| KeyError::KeyDerivationError(format!("HKDF expansion failed: {e}")))?;

        self.decrypt_with_symmetric_key(encrypted_payload, &encryption_key)
    }

    /// Generate a certificate signing request (CSR) for this node
    pub fn generate_csr(&mut self) -> Result<SetupToken> {
        let node_public_key = self.get_node_public_key();
        let node_id = self.get_node_id();

        // Convert to DNS-safe format for certificate generation
        let subject = format!("CN={node_id},O=Runar Node,C=US");

        let csr_der = CertificateRequest::create(&self.node_key_pair, &subject)?;

        self.certificate_status = CertificateStatus::Pending;

        // Derive agreement from node master and include public part in token
        let agreement = crate::derivation::derive_agreement_from_master(
            &self.node_key_pair.signing_key().to_bytes(),
            b"runar-v1:node-identity:agreement",
        )?;
        Ok(SetupToken {
            node_public_key,
            node_agreement_public_key: agreement
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
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
        // Validate the certificate signature against the CA's public key
        let ca_public_key = cert_message.ca_certificate.public_key()?;
        cert_message.node_certificate.validate(&ca_public_key)?;

        // Verify the certificate is for this node
        let node_id = self.get_node_id();
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

        let res = Ok(());
        self.persist_if_enabled();
        res
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
        // Decrypt the ECIES-wrapped raw 32-byte scalar using the node's agreement key
        let encrypted_network_key = &network_key_message.encrypted_network_key;
        let decrypted_scalar =
            self.decrypt_key_with_ecdsa(encrypted_network_key, &self.node_key_pair)?;

        if decrypted_scalar.len() != 32 {
            return Err(KeyError::InvalidKeyFormat(
                "Invalid network scalar length".to_string(),
            ));
        }

        // Build an agreement secret from the scalar and store as network public id
        use p256::SecretKey as P256SecretKey;
        let agr = P256SecretKey::from_slice(&decrypted_scalar)
            .map_err(|e| KeyError::InvalidKeyFormat(format!("Invalid network scalar: {e}")))?;

        // Store under its public key ID
        let network_public_key_bytes = agr.public_key().to_encoded_point(false).as_bytes().to_vec();
        let network_public_key = compact_id(&network_public_key_bytes);
        log_debug!(
            self.logger,
            "Installed network agreement key id={network_public_key}"
        );
        // Store under its public key ID
        // Store agreement secret under its id
        self.network_agreements
            .insert(network_public_key.clone(), agr);

        log_info!(
            self.logger,
            "Network agreement scalar installed for network: {network_public_key}"
        );

        let res = Ok(());
        self.persist_if_enabled();
        res
    }

    /// Get network agreement key for decryption
    pub fn get_network_agreement(&self, network_id: &str) -> Result<&P256SecretKey> {
        self.network_agreements.get(network_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!(
                "Network key pair not found for network: {network_id}"
            ))
        })
    }

    pub fn get_network_public_key(&self, network_id: &str) -> Result<Vec<u8>> {
        // Check both network_data_keys and network_public_keys
        if let Some(network_key) = self.network_agreements.get(network_id) {
            Ok(network_key
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec())
        } else if let Some(network_public_key) = self.network_public_keys.get(network_id) {
            Ok(network_public_key.clone())
        } else {
            Err(KeyError::KeyNotFound(format!(
                "Network public key not found for network: {network_id}"
            )))
        }
    }

    /// Encrypt data for network transmission
    pub fn encrypt_for_network(
        &self,
        data: &[u8],
        network_id: &str,
    ) -> Result<EnvelopeEncryptedData> {
        // Use envelope encryption with just this network
        let envelope_data = NodeKeyManager::encrypt_with_envelope(
            self,
            data,
            Some(&network_id.to_string()),
            vec![],
        )?;
        // Return just the encrypted data for compatibility
        Ok(envelope_data)
    }

    /// Decrypt network data
    pub fn decrypt_network_data(&self, envelope_data: &EnvelopeEncryptedData) -> Result<Vec<u8>> {
        let network_id = envelope_data
            .network_id
            .as_ref()
            .ok_or_else(|| KeyError::DecryptionError("Envelope missing network_id".to_string()))?;

        let network_agreement = self.get_network_agreement(network_id)?;

        let encrypted_envelope_key = &envelope_data.network_encrypted_key;

        let decrypted_envelope_key =
            self.decrypt_key_with_agreement(encrypted_envelope_key, network_agreement)?;

        let decrypted_data = self
            .decrypt_with_symmetric_key(&envelope_data.encrypted_data, &decrypted_envelope_key)?;

        Ok(decrypted_data)

        // // Use the network key's private key bytes as symmetric decryption key
        // let network_private_key = network_key_pair.private_key_der().map_err(|e| {
        //     KeyError::DecryptionError(format!("Failed to get network private key: {e}"))
        // })?;

        // // Derive decryption key from network private key using SHA256 (same as encryption)
        // use sha2::{Digest, Sha256};
        // let mut hasher = Sha256::new();
        // hasher.update(&network_private_key);
        // hasher.update(b"runar-network-encryption");
        // let decryption_key = hasher.finalize();

        // // Decrypt using AES-GCM
        // self.decrypt_with_symmetric_key(encrypted_data, &decryption_key)
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
                            log_debug!(self.logger, "Certificate validation successful");
                            return CertificateStatus::Valid;
                        }
                        Err(e) => {
                            log_warn!(self.logger, "Certificate validation failed: {e}");
                            return CertificateStatus::Invalid;
                        }
                    }
                } else {
                    log_warn!(self.logger, "Certificate validator not initialized");
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
            network_keys_count: self.network_agreements.len(),
            node_public_key: compact_id(&self.get_node_public_key()),
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
            KeyError::CertificateValidationError(format!("Invalid signature format: {e}"))
        })?;

        peer_public_key.verify(data, &sig).map_err(|e| {
            KeyError::CertificateValidationError(format!("Signature verification failed: {e}"))
        })?;

        Ok(())
    }

    /// Encrypt a message for the mobile user using their public key (ECIES)
    pub fn encrypt_message_for_mobile(
        &self,
        message: &[u8],
        mobile_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        let message_len = message.len();
        log_debug!(
            self.logger,
            "Encrypting message for mobile ({message_len} bytes)"
        );
        self.encrypt_key_with_ecdsa(message, mobile_public_key)
    }

    /// Decrypt a message from the mobile user using the node's private key (ECIES)
    pub fn decrypt_message_from_mobile(&self, encrypted_message: &[u8]) -> Result<Vec<u8>> {
        let encrypted_message_len = encrypted_message.len();
        log_debug!(
            self.logger,
            "Decrypting message from mobile ({encrypted_message_len} bytes)"
        );
        self.decrypt_key_with_ecdsa(encrypted_message, &self.node_key_pair)
    }

    /// Create an envelope key for per-object encryption
    /// Envelope keys are ephemeral - generated fresh for each object
    pub fn create_envelope_key(&self) -> Result<Vec<u8>> {
        // Generate a fresh 32-byte symmetric key for envelope encryption
        use rand::RngCore;
        let mut envelope_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut envelope_key);
        Ok(envelope_key.to_vec())
    }

    /// Create an envelope‐encrypted payload. For the node side we only
    /// support network recipients – any supplied `profile_ids` will be
    /// ignored. This signature exists solely to allow generic code (e.g.
    /// serializer key-store adapter) to call the same method on both key
    /// manager types without `cfg` branching.
    pub fn encrypt_with_envelope(
        &self,
        data: &[u8],
        network_id: Option<&String>,
        profile_public_keys: Vec<Vec<u8>>,
    ) -> crate::Result<crate::mobile::EnvelopeEncryptedData> {
        let envelope_key = self.create_envelope_key()?;

        // Encrypt data with envelope key
        let encrypted_data = self.encrypt_with_symmetric_key(data, &envelope_key)?;

        // Encrypt envelope key with network key if network_id provided
        let mut network_encrypted_key = Vec::new();
        if let Some(network_id) = network_id {
            // Check both network_data_keys and network_public_keys
            let network_public_key_bytes = self.get_network_public_key(network_id)?;

            network_encrypted_key =
                self.encrypt_key_with_ecdsa(&envelope_key, &network_public_key_bytes)?;
        }

        // Encrypt envelope key for each profile id using stored public key
        let mut profile_encrypted_keys = HashMap::new();
        for profile_public_key in profile_public_keys {
            let encrypted_key = self.encrypt_key_with_ecdsa(&envelope_key, &profile_public_key)?;
            let profile_id = compact_id(&profile_public_key);
            profile_encrypted_keys.insert(profile_id, encrypted_key);
        }

        Ok(crate::mobile::EnvelopeEncryptedData {
            encrypted_data,
            network_id: network_id.cloned(),
            network_encrypted_key,
            profile_encrypted_keys,
        })
    }

    /// Envelope-encrypt for a recipient network public key.
    pub fn encrypt_for_public_key(
        &self,
        data: &[u8],
        public_key: &[u8],
    ) -> Result<crate::mobile::EnvelopeEncryptedData> {
        let network_id = compact_id(public_key);
        self.encrypt_with_envelope(data, Some(&network_id), Vec::new())
    }

    /// Check if the manager holds the private key for the given network public key.
    pub fn has_public_key(&self, public_key: &[u8]) -> bool {
        let network_id = compact_id(public_key);
        self.network_agreements.contains_key(&network_id)
    }

    /// Install a user profile public key so the node can encrypt data for that profile
    pub fn install_profile_public_key(&mut self, public_key: Vec<u8>) {
        let pid = compact_id(&public_key);
        self.profile_public_keys.insert(pid, public_key);
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
    /// Stored as PKCS#8 DER bytes of P-256 SecretKey
    network_agreements: HashMap<String, Vec<u8>>,
    network_public_keys: HashMap<String, Vec<u8>>,
    profile_public_keys: HashMap<String, Vec<u8>>,
    symmetric_keys: HashMap<String, Vec<u8>>,
    storage_key: Vec<u8>,
}

impl NodeKeyManager {
    /// Export state for persistence
    pub fn export_state(&self) -> NodeKeyManagerState {
        NodeKeyManagerState {
            node_key_pair: self.node_key_pair.clone(),
            node_certificate: self.node_certificate.clone(),
            ca_certificate: self.ca_certificate.clone(),
            network_keys: HashMap::new(),
            network_agreements: self
                .network_agreements
                .iter()
                .map(|(id, sk)| (id.clone(), sk.to_pkcs8_der().unwrap().as_bytes().to_vec()))
                .collect(),
            network_public_keys: self.network_public_keys.clone(),
            profile_public_keys: self.profile_public_keys.clone(),
            symmetric_keys: self.symmetric_keys.clone(),
            storage_key: self.storage_key.clone(),
        }
    }

    /// Import state from persistence
    pub fn from_state(state: NodeKeyManagerState, logger: Arc<Logger>) -> Result<Self> {
        let certificate_validator = state
            .ca_certificate
            .as_ref()
            .map(|ca_cert| CertificateValidator::new(vec![ca_cert.clone()]));

        let certificate_status =
            if state.node_certificate.is_some() && state.ca_certificate.is_some() {
                CertificateStatus::Valid
            } else if state.node_certificate.is_some() {
                CertificateStatus::Invalid
            } else {
                CertificateStatus::None
            };

        let node_id = compact_id(&state.node_key_pair.public_key_bytes());
        logger.info(format!(
            "Node Key Manager state imported for node: {node_id}"
        ));

        // Re-derive node agreement on import
        let node_agreement_secret = crate::derivation::derive_agreement_from_master(
            &state.node_key_pair.signing_key().to_bytes(),
            b"runar-v1:node-identity:agreement",
        )?;

        Ok(Self {
            node_key_pair: state.node_key_pair,
            node_certificate: state.node_certificate,
            ca_certificate: state.ca_certificate,
            certificate_validator,
            network_agreements: state
                .network_agreements
                .into_iter()
                .filter_map(|(id, der)| P256SecretKey::from_pkcs8_der(&der).ok().map(|k| (id, k)))
                .collect(),
            network_public_keys: state.network_public_keys,
            profile_public_keys: state.profile_public_keys,
            symmetric_keys: state.symmetric_keys,
            storage_key: state.storage_key,
            node_agreement_secret,
            certificate_status,
            logger,
        })
    }
}

impl crate::EnvelopeCrypto for NodeKeyManager {
    fn encrypt_with_envelope(
        &self,
        data: &[u8],
        network_id: Option<&str>,
        _profile_public_keys: Vec<Vec<u8>>,
    ) -> crate::Result<crate::mobile::EnvelopeEncryptedData> {
        // Nodes only support network-wide encryption.
        self.create_envelope_for_network(data, network_id)
    }

    fn decrypt_envelope_data(
        &self,
        env: &crate::mobile::EnvelopeEncryptedData,
    ) -> crate::Result<Vec<u8>> {
        // Guard: ensure the encrypted key is present
        if env.network_encrypted_key.is_empty() {
            return Err(crate::error::KeyError::DecryptionError(
                "Envelope missing network_encrypted_key".into(),
            ));
        }

        NodeKeyManager::decrypt_envelope_data(self, env)
    }
}
