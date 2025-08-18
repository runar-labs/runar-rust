//! Mobile Key Manager - Certificate Authority Operations
//!
//! This module implements the mobile-side key management system that acts as
//! a Certificate Authority for issuing node certificates and managing user keys.

use crate::certificate::{
    CertificateAuthority, CertificateValidator, EcdsaKeyPair, X509Certificate,
};
use crate::derivation::derive_agreement_from_master;
use crate::error::{KeyError, Result};
use crate::{log_debug, log_error, log_info};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey as P256SecretKey;
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use runar_common::compact_ids::compact_id;
use runar_common::logging::Logger;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Setup token from a node requesting a certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupToken {
    /// Node's public key for identity
    pub node_public_key: Vec<u8>,
    /// Node's ECIES agreement public key (P-256)
    pub node_agreement_public_key: Vec<u8>,
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
    pub network_id: Option<String>,
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
    /// User root signing key - Master key for the user (never leaves mobile)
    user_root_key: Option<EcdsaKeyPair>,
    /// User root agreement key (derived deterministically)
    user_root_agreement: Option<P256SecretKey>,
    /// User profile signing keys indexed by profile ID
    user_profile_keys: HashMap<String, EcdsaKeyPair>,
    /// User profile agreement keys indexed by profile ID
    user_profile_agreements: HashMap<String, P256SecretKey>,
    /// Mapping from human-readable label → compact-id for quick reuse
    label_to_pid: HashMap<String, String>,
    /// Network agreement keys indexed by network ID - for envelope encryption and decryption
    network_data_keys: HashMap<String, P256SecretKey>,
    // network public keys indexed by network ID - for envelope encryption
    network_public_keys: HashMap<String, Vec<u8>>,
    /// Issued certificates tracking
    issued_certificates: HashMap<String, X509Certificate>,
    /// Monotonically-increasing certificate serial number used as the X.509
    /// serial for node certificates. Persisted so restarts keep the sequence
    /// and avoid duplicate serial numbers.
    serial_counter: u64,
    /// Logger instance
    logger: Arc<Logger>,
}

/// Serializable snapshot of the MobileKeyManager. This allows persisting
/// all cryptographic material so a restored instance can continue to operate
/// without regenerating or losing keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileKeyManagerState {
    ca_key_pair: EcdsaKeyPair,
    ca_certificate: X509Certificate,
    user_root_key: Option<EcdsaKeyPair>,
    // Stored as PKCS#8 DER bytes for portability
    user_root_agreement: Option<Vec<u8>>,
    user_profile_keys: HashMap<String, EcdsaKeyPair>,
    user_profile_agreements: HashMap<String, Vec<u8>>,
    label_to_pid: HashMap<String, String>,
    network_data_keys: HashMap<String, Vec<u8>>,
    network_public_keys: HashMap<String, Vec<u8>>,
    issued_certificates: HashMap<String, X509Certificate>,
    serial_counter: u64,
}

impl MobileKeyManager {
    /// Create a new Mobile Key Manager
    pub fn new(logger: Arc<Logger>) -> Result<Self> {
        // Create Certificate Authority with user identity
        let ca_subject = "CN=Runar User CA,O=Runar,C=US";
        let certificate_authority = CertificateAuthority::new(ca_subject)?;
        let certificate_validator =
            CertificateValidator::new(vec![certificate_authority.ca_certificate().clone()]);

        Ok(Self {
            certificate_authority,
            certificate_validator,
            user_root_key: None,
            user_root_agreement: None,
            user_profile_keys: HashMap::new(),
            user_profile_agreements: HashMap::new(),
            label_to_pid: HashMap::new(),
            network_data_keys: HashMap::new(),
            network_public_keys: HashMap::new(),
            issued_certificates: HashMap::new(),
            serial_counter: 1, // Start at 1 to avoid 0
            logger,
        })
    }

    pub fn install_network_public_key(&mut self, network_public_key: &[u8]) -> Result<()> {
        let network_id = compact_id(network_public_key);
        self.network_public_keys
            .insert(network_id.clone(), network_public_key.to_vec());

        log_info!(
            self.logger,
            "Network public key installed with ID: {network_id}"
        );
        Ok(())
    }

    /// Initialize user root key - Master key that never leaves the mobile device
    pub fn initialize_user_root_key(&mut self) -> Result<Vec<u8>> {
        if self.user_root_key.is_some() {
            return Err(KeyError::KeyAlreadyInitialized(
                "User root key already initialized".to_string(),
            ));
        }

        let root_key = EcdsaKeyPair::new()?;

        // Derive agreement key from master signing key deterministically
        let agreement_secret = derive_agreement_from_master(
            &root_key.signing_key().to_bytes(),
            b"runar-v1:user-root:agreement",
        )?;
        self.user_root_key = Some(root_key);
        self.user_root_agreement = Some(agreement_secret);
        log_info!(
            self.logger,
            "User root key initialized (private key secured on mobile)"
        );

        // Return the agreement public key bytes for ECIES recipients
        let agr_pub = self
            .user_root_agreement
            .as_ref()
            .unwrap()
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        Ok(agr_pub)
    }

    /// Get the user root public key
    pub fn get_user_root_public_key(&self) -> Result<Vec<u8>> {
        let root_agreement = self.user_root_agreement.as_ref().ok_or_else(|| {
            KeyError::KeyNotFound("User root agreement key not initialized".to_string())
        })?;
        Ok(root_agreement
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec())
    }

    /// Derive a user profile agreement key from the root key using HKDF-SHA-256.
    ///
    /// - IKM: raw 32-byte scalar of the user root signing key
    /// - info: "runar-v1:profile:agreement:{label}[:{counter}]"
    /// - output: 32-byte scalar interpreted as P-256 SecretKey (with rejection sampling)
    pub fn derive_user_profile_key(&mut self, label: &str) -> Result<Vec<u8>> {
        // Fast-path: if we already derived a key for this label return it.
        if let Some(pid) = self.label_to_pid.get(label) {
            if let Some(agr) = self.user_profile_agreements.get(pid) {
                let pubkey = agr.public_key();
                return Ok(pubkey.to_encoded_point(false).as_bytes().to_vec());
            }
        }

        use hkdf::Hkdf;
        use sha2::Sha256;

        // Ensure the root key exists.
        let root_key = self
            .user_root_key
            .as_ref()
            .ok_or_else(|| KeyError::KeyNotFound("User root key not initialized".to_string()))?;

        // Extract the raw 32-byte scalar of the root private key as IKM
        let root_scalar_bytes = root_key.signing_key().to_bytes();

        // Derive a profile-specific agreement scalar using HKDF-SHA-256 with rejection sampling
        let hk = Hkdf::<Sha256>::new(
            Some(b"RunarKeyDerivationSalt/v1"),
            root_scalar_bytes.as_slice(),
        );
        let mut counter: u32 = 0;
        let profile_agreement = loop {
            let info = if counter == 0 {
                format!("runar-v1:profile:agreement:{label}")
            } else {
                format!("runar-v1:profile:agreement:{label}:{counter}")
            };
            let mut candidate_bytes = [0u8; 32];
            hk.expand(info.as_bytes(), &mut candidate_bytes)
                .map_err(|e| KeyError::KeyDerivationError(format!("HKDF expansion failed: {e}")))?;
            match P256SecretKey::from_slice(&candidate_bytes) {
                Ok(sk) => break sk,
                Err(_) => {
                    counter = counter.saturating_add(1);
                    continue;
                }
            }
        };
        let public_key = profile_agreement
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let pid = compact_id(&public_key);
        // Signing key not required for profile; store only agreement
        self.user_profile_agreements
            .insert(pid.clone(), profile_agreement);
        self.label_to_pid.insert(label.to_string(), pid.clone());

        log_info!(self.logger, "User profile key derived using HKDF for label '{label}' (attempts: {counter}, id: {pid})");

        Ok(public_key)
    }

    pub fn get_network_public_key(&self, network_id: &str) -> Result<Vec<u8>> {
        // Check both network_data_keys and network_public_keys
        if let Some(network_key) = self.network_data_keys.get(network_id) {
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

    /// Generate a network data key for envelope encryption and return the network ID (compact Base64 public key)
    pub fn generate_network_data_key(&mut self) -> Result<String> {
        let network_key = P256SecretKey::random(&mut rand::thread_rng());
        let public_key = network_key
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let network_id = compact_id(&public_key);

        self.network_data_keys
            .insert(network_id.clone(), network_key);
        log_info!(
            self.logger,
            "Network data key generated with ID: {network_id}"
        );

        Ok(network_id)
    }

    /// Create an envelope key for per-object encryption
    /// Envelope keys are ephemeral - generated fresh for each object
    pub fn create_envelope_key(&self) -> Result<Vec<u8>> {
        // Derive a fresh 32-byte symmetric key from the user-root master using HKDF-SHA-384 and a random nonce label
        use hkdf::Hkdf;
        use rand::RngCore;
        use sha2::Sha256;
        let root_key = self
            .user_root_key
            .as_ref()
            .ok_or_else(|| KeyError::KeyNotFound("User root key not initialized".to_string()))?;
        let ikm = root_key.signing_key().to_bytes();
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let hk = Hkdf::<Sha256>::new(Some(b"RunarKeyDerivationSalt/v1"), ikm.as_slice());
        let mut envelope_key = [0u8; 32];
        let mut info = b"runar-v1:user-root:storage:envelope:".to_vec();
        info.extend_from_slice(&nonce);
        hk.expand(&info, &mut envelope_key)
            .map_err(|e| KeyError::KeyDerivationError(format!("HKDF expansion failed: {e}")))?;
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
        network_id: Option<&str>,
        profile_public_keys: Vec<Vec<u8>>,
    ) -> Result<EnvelopeEncryptedData> {
        // Generate ephemeral envelope key
        let envelope_key = self.create_envelope_key()?;

        // Encrypt data with envelope key (using AES-GCM)
        let encrypted_data = self.encrypt_with_symmetric_key(data, &envelope_key)?;

        // Encrypt envelope key for network (optional)
        let mut network_encrypted_key = Vec::new();
        if let Some(network_id) = network_id {
            // Check both network_data_keys and network_public_keys
            let network_public_key_bytes = self.get_network_public_key(network_id)?;

            network_encrypted_key =
                self.encrypt_key_with_ecdsa(&envelope_key, &network_public_key_bytes)?;
        }

        // Encrypt envelope key for each profile
        let mut profile_encrypted_keys = HashMap::new();
        for profile_public_key in profile_public_keys {
            let encrypted_key = self.encrypt_key_with_ecdsa(&envelope_key, &profile_public_key)?;
            let profile_id = compact_id(&profile_public_key);
            profile_encrypted_keys.insert(profile_id, encrypted_key);
        }

        Ok(EnvelopeEncryptedData {
            encrypted_data,
            network_id: network_id.map(|s| s.to_string()),
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
        let profile_agreement = self
            .user_profile_agreements
            .get(profile_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Profile key not found: {profile_id}")))?;

        let encrypted_envelope_key = envelope_data
            .profile_encrypted_keys
            .get(profile_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!("Envelope key not found for profile: {profile_id}"))
            })?;

        let envelope_key =
            self.decrypt_key_with_agreement(encrypted_envelope_key, profile_agreement)?;
        self.decrypt_with_symmetric_key(&envelope_data.encrypted_data, &envelope_key)
    }

    /// Decrypt envelope-encrypted data using network key
    pub fn decrypt_with_network(&self, envelope_data: &EnvelopeEncryptedData) -> Result<Vec<u8>> {
        let network_id = envelope_data
            .network_id
            .as_ref()
            .ok_or_else(|| KeyError::DecryptionError("Envelope missing network_id".to_string()))?;

        let network_key = self.network_data_keys.get(network_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!(
                "Network key pair not found for network: {network_id}"
            ))
        })?;

        let encrypted_envelope_key = &envelope_data.network_encrypted_key;

        if encrypted_envelope_key.is_empty() {
            return Err(KeyError::DecryptionError(
                "Envelope missing network_encrypted_key".to_string(),
            ));
        }

        let envelope_key = self.decrypt_key_with_agreement(encrypted_envelope_key, network_key)?;
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

    /// Internal ECIES encryption using a recipient's agreement public key
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

    /// Internal ECIES decryption using our agreement private key
    fn decrypt_key_with_agreement(
        &self,
        encrypted_data: &[u8],
        agreement_secret: &p256::SecretKey,
    ) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use p256::ecdh::diffie_hellman;
        use p256::PublicKey;
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

        // Use our agreement key for ECDH
        let shared_secret = diffie_hellman(
            agreement_secret.to_nonzero_scalar(),
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
        let node_id = &setup_token.node_id;
        log_info!(self.logger, "Processing setup token for node: {node_id}");

        // Validate the CSR format
        if setup_token.csr_der.is_empty() {
            log_error!(self.logger, "Empty CSR in setup token");
            return Err(KeyError::InvalidOperation(
                "Empty CSR in setup token".to_string(),
            ));
        }

        // ----- Validate CSR subject: CN must equal the claimed node_id -----
        {
            use openssl::nid::Nid;
            use openssl::x509::X509Req;

            let csr = X509Req::from_der(&setup_token.csr_der).map_err(|e| {
                KeyError::CertificateError(format!(
                    "Failed to parse CSR DER for subject validation: {e}"
                ))
            })?;

            let mut cn_matches = false;
            for entry in csr.subject_name().entries_by_nid(Nid::COMMONNAME) {
                if let Ok(data) = entry.data().as_utf8() {
                    if data.to_string() == *node_id {
                        cn_matches = true;
                        break;
                    }
                }
            }

            if !cn_matches {
                return Err(KeyError::InvalidOperation(format!(
                    "CSR CN does not match node ID '{node_id}'",
                )));
            }
        }

        let validity_days = 365; // 1-year validity

        let node_certificate = self
            .certificate_authority
            .sign_certificate_request_with_serial(
                &setup_token.csr_der,
                validity_days,
                Some(self.serial_counter),
            )?;

        // Increment serial for next issuance
        self.serial_counter = self.serial_counter.wrapping_add(1);

        // Store the issued certificate
        self.issued_certificates
            .insert(setup_token.node_id.clone(), node_certificate.clone());

        // Create metadata
        let metadata = CertificateMetadata {
            issued_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| KeyError::InvalidOperation(format!("System time error: {e}")))?
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
        node_agreement_public_key: &[u8],
    ) -> Result<NetworkKeyMessage> {
        let network_key = self.network_data_keys.get(network_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!(
                "Network key pair not found for network: {network_id}"
            ))
        })?;

        // Encrypt the raw 32-byte scalar for the node's agreement public key
        let network_scalar = network_key.to_bytes().to_vec();
        let encrypted_network_key =
            self.encrypt_key_with_ecdsa(&network_scalar, node_agreement_public_key)?;

        let node_id = compact_id(node_agreement_public_key);
        log_info!(
            self.logger,
            "Network key encrypted for node {node_id} with ECIES"
        );

        Ok(NetworkKeyMessage {
            network_id: network_id.to_string(),
            network_public_key: network_key
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            encrypted_network_key,
            key_derivation_info: format!("Network key for node {node_id} (ECIES encrypted)"),
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
        let profile_key_pair = self.user_profile_keys.get(profile_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!(
                "Profile public key not found for profile: {profile_id}"
            ))
        })?;
        // Use envelope encryption with just this profile
        let envelope_data = MobileKeyManager::encrypt_with_envelope(
            self,
            data,
            None,
            vec![profile_key_pair.public_key_bytes()],
        )?;
        // Return just the encrypted data for compatibility
        Ok(envelope_data.encrypted_data)
    }

    /// Encrypt data for a network (legacy method for compatibility)  
    pub fn encrypt_for_network(&self, data: &[u8], network_id: &str) -> Result<Vec<u8>> {
        // Use envelope encryption with just this network
        let envelope_data =
            MobileKeyManager::encrypt_with_envelope(self, data, Some(network_id), vec![])?;
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
        node_agreement_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        let message_len = message.len();
        log_debug!(
            self.logger,
            "Encrypting message for node ({message_len} bytes)"
        );
        self.encrypt_key_with_ecdsa(message, node_agreement_public_key)
    }

    /// Decrypt a message from a node using the user's root key (ECIES)
    pub fn decrypt_message_from_node(&self, encrypted_message: &[u8]) -> Result<Vec<u8>> {
        let encrypted_message_len = encrypted_message.len();
        log_debug!(
            self.logger,
            "Decrypting message from node ({encrypted_message_len} bytes)"
        );
        let root_agreement = self.user_root_agreement.as_ref().ok_or_else(|| {
            KeyError::KeyNotFound("User root agreement key not initialized".to_string())
        })?;
        self.decrypt_key_with_agreement(encrypted_message, root_agreement)
    }

    // ---------------------------------------------------------------------
    // Persistence helpers
    // ---------------------------------------------------------------------

    /// Export all cryptographic material for persistence.
    pub fn export_state(&self) -> MobileKeyManagerState {
        MobileKeyManagerState {
            ca_key_pair: self.certificate_authority.ca_key_pair().clone(),
            ca_certificate: self.certificate_authority.ca_certificate().clone(),
            user_root_key: self.user_root_key.clone(),
            user_root_agreement: self
                .user_root_agreement
                .as_ref()
                .map(|k| k.to_pkcs8_der().unwrap().as_bytes().to_vec()),
            user_profile_keys: self.user_profile_keys.clone(),
            user_profile_agreements: self
                .user_profile_agreements
                .iter()
                .map(|(id, sk)| (id.clone(), sk.to_pkcs8_der().unwrap().as_bytes().to_vec()))
                .collect(),
            label_to_pid: self.label_to_pid.clone(),
            network_data_keys: self
                .network_data_keys
                .iter()
                .map(|(id, sk)| (id.clone(), sk.to_pkcs8_der().unwrap().as_bytes().to_vec()))
                .collect(),
            network_public_keys: self.network_public_keys.clone(),
            issued_certificates: self.issued_certificates.clone(),
            serial_counter: self.serial_counter,
        }
    }

    /// Restore a MobileKeyManager from a previously exported state.
    pub fn from_state(state: MobileKeyManagerState, logger: Arc<Logger>) -> Result<Self> {
        let certificate_authority = CertificateAuthority::from_existing(
            state.ca_key_pair.clone(),
            state.ca_certificate.clone(),
        );

        let certificate_validator = CertificateValidator::new(vec![state.ca_certificate.clone()]);

        log_info!(logger, "Mobile Key Manager state imported");

        Ok(Self {
            certificate_authority,
            certificate_validator,
            user_root_key: state.user_root_key,
            user_root_agreement: state
                .user_root_agreement
                .and_then(|der| P256SecretKey::from_pkcs8_der(&der).ok()),
            user_profile_keys: state.user_profile_keys,
            user_profile_agreements: state
                .user_profile_agreements
                .into_iter()
                .filter_map(|(id, der)| P256SecretKey::from_pkcs8_der(&der).ok().map(|k| (id, k)))
                .collect(),
            label_to_pid: state.label_to_pid,
            network_data_keys: state
                .network_data_keys
                .into_iter()
                .filter_map(|(id, der)| P256SecretKey::from_pkcs8_der(&der).ok().map(|k| (id, k)))
                .collect(),
            network_public_keys: state.network_public_keys,
            issued_certificates: state.issued_certificates,
            serial_counter: state.serial_counter,
            logger,
        })
    }
}

impl crate::EnvelopeCrypto for MobileKeyManager {
    fn encrypt_with_envelope(
        &self,
        data: &[u8],
        network_id: Option<&str>,
        profile_public_keys: Vec<Vec<u8>>,
    ) -> crate::Result<crate::mobile::EnvelopeEncryptedData> {
        MobileKeyManager::encrypt_with_envelope(self, data, network_id, profile_public_keys)
    }

    fn decrypt_envelope_data(
        &self,
        env: &crate::mobile::EnvelopeEncryptedData,
    ) -> crate::Result<Vec<u8>> {
        // Try profiles first
        for pid in env.profile_encrypted_keys.keys() {
            if let Ok(pt) = self.decrypt_with_profile(env, pid) {
                return Ok(pt);
            }
        }
        self.decrypt_with_network(env)
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
