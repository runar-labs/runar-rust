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
#[derive(Clone, Serialize, Deserialize, prost::Message)]
pub struct EnvelopeEncryptedData {
    /// The encrypted data payload
    #[prost(bytes = "vec", tag = "1")]
    pub encrypted_data: Vec<u8>,
    /// Network ID this data belongs to
    #[prost(string, tag = "2")]
    pub network_id: String,
    /// Envelope key encrypted with network key (always required)
    #[prost(bytes = "vec", tag = "3")]
    pub network_encrypted_key: Vec<u8>,
    /// Envelope key encrypted with each profile key
    #[prost(map = "string, bytes", tag = "4")]
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
    user_profile_keys: HashMap<String, EcdsaKeyPair>,
    network_data_keys: HashMap<String, EcdsaKeyPair>,
    issued_certificates: HashMap<String, X509Certificate>,
    serial_counter: u64,
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
            serial_counter: 1,
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

    //TODO lets fix this.. so we have proper key derivation using HKDF/SLIP-0010

    /// Derive a user profile key from the root key using HKDF.
    ///
    /// This implementation follows these steps:
    /// 1.  The secret scalar bytes of the user *root* key are used as the
    ///     Input Key Material (IKM) for HKDF-SHA-256. Using the raw scalar
    ///     avoids the variability and additional metadata present in the
    ///     PKCS#8 representation previously used.
    /// 2.  A domain-separated `info` string (`"runar-profile-{profile_id}"`)
    ///     is supplied to HKDF to ensure every profile receives a unique key
    ///     tied to the caller-supplied identifier.
    /// 3.  HKDF expands to 32 bytes. These bytes are interpreted as a P-256
    ///     scalar.  If the candidate scalar is *not* in the valid field range
    ///     (i.e. ≥ n or zero) we derive a new candidate by appending an
    ///     incrementing counter to the `info` string.  The probability of
    ///     requiring multiple attempts is negligible but this guarantees a
    ///     correct result in constant time.
    /// 4.  The resulting scalar is converted into an `EcdsaKeyPair` which is
    ///     cached so subsequent calls for the same `profile_id` return the
    ///     exact same key without additional computation.
    ///
    /// This approach is deterministic, collision-resistant, and ensures strong
    /// cryptographic separation between the root and profile keys while
    /// remaining compatible with the system-wide ECDSA P-256 algorithm.
    pub fn derive_user_profile_key(&mut self, profile_id: &str) -> Result<Vec<u8>> {
        // Return cached key if we have already derived it before.
        if let Some(existing) = self.user_profile_keys.get(profile_id) {
            return Ok(existing.public_key_bytes());
        }

        use hkdf::Hkdf;
        use p256::ecdsa::SigningKey;
        use sha2::Sha256;

        // Ensure the root key exists.
        let root_key = self
            .user_root_key
            .as_ref()
            .ok_or_else(|| KeyError::KeyNotFound("User root key not initialized".to_string()))?;

        // Extract the raw 32-byte scalar of the root private key.
        // This is a stable representation suitable for HKDF input.
        let root_scalar_bytes = root_key.signing_key().to_bytes();

        // Derive a profile-specific private scalar using HKDF-SHA256.
        let hk = Hkdf::<Sha256>::new(
            Some(b"RunarUserProfileDerivationSalt"),
            root_scalar_bytes.as_slice(),
        );

        // Attempt to create a valid P-256 signing key from the HKDF output.
        // If the candidate scalar is out of range (rare) retry with a counter
        // in the info field until success.
        let mut counter: u32 = 0;
        let signing_key = loop {
            let info = if counter == 0 {
                format!("runar-profile-{profile_id}")
            } else {
                format!("runar-profile-{profile_id}-{counter}")
            };

            let mut candidate_bytes = [0u8; 32];
            hk.expand(info.as_bytes(), &mut candidate_bytes)
                .map_err(|e| KeyError::KeyDerivationError(format!("HKDF expansion failed: {e}")))?;

            match SigningKey::from_bytes((&candidate_bytes).into()) {
                Ok(sk) => break sk,
                Err(_) => {
                    counter += 1;
                    continue; // try again with different info string
                }
            }
        };

        // Wrap the signing key in our convenience type and cache it.
        let profile_key = EcdsaKeyPair::from_signing_key(signing_key);
        let public_key = profile_key.public_key_bytes();
        self.user_profile_keys
            .insert(profile_id.to_string(), profile_key);

        self.logger.info(format!(
            "User profile key derived using HKDF for profile: {profile_id} (attempts: {counter})"
        ));

        Ok(public_key)
    }

    pub fn get_network_public_key(&self, network_id: &str) -> Result<Vec<u8>> {
        let network_key = self
            .network_data_keys
            .get(network_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Network key not found: {network_id}")))?;
        Ok(network_key.public_key_bytes())
    }

    /// Generate a network data key for envelope encryption and return the network ID (compact Base64 public key)
    pub fn generate_network_data_key(&mut self) -> Result<String> {
        let network_key = EcdsaKeyPair::new()?;
        let public_key = network_key.public_key_bytes();
        let network_id = crate::compact_ids::compact_network_id(&public_key);

        self.network_data_keys
            .insert(network_id.clone(), network_key);
        self.logger
            .info(format!("Network data key generated with ID: {network_id}"));

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

        // Encrypt envelope key for network (optional)
        let mut network_encrypted_key = Vec::new();
        if !network_id.is_empty() {
            let network_key = self.network_data_keys.get(network_id).ok_or_else(|| {
                KeyError::KeyNotFound(format!("Network key not found for network: {network_id}"))
            })?;
            network_encrypted_key =
                self.encrypt_key_with_ecdsa(&envelope_key, &network_key.public_key_bytes())?;
        }

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
        let profile_key = self
            .user_profile_keys
            .get(profile_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Profile key not found: {profile_id}")))?;

        let encrypted_envelope_key = envelope_data
            .profile_encrypted_keys
            .get(profile_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!("Envelope key not found for profile: {profile_id}"))
            })?;

        let envelope_key = self.decrypt_key_with_ecdsa(encrypted_envelope_key, profile_key)?;
        self.decrypt_with_symmetric_key(&envelope_data.encrypted_data, &envelope_key)
    }

    /// Decrypt envelope-encrypted data using network key
    pub fn decrypt_with_network(&self, envelope_data: &EnvelopeEncryptedData) -> Result<Vec<u8>> {
        let network_id = envelope_data.network_id.clone();
        let network_key = self
            .network_data_keys
            .get(&network_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Network key not found: {network_id}")))?;

        let encrypted_envelope_key = &envelope_data.network_encrypted_key;

        if encrypted_envelope_key.is_empty() {
            return Err(KeyError::DecryptionError(
                "Envelope missing network_encrypted_key".to_string(),
            ));
        }

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

        // Derive encryption key using HKDF
        let hk = Hkdf::<Sha256>::new(None, shared_secret_bytes.as_slice());
        let mut encryption_key = [0u8; 32];
        hk.expand(b"runar-key-encryption", &mut encryption_key)
            .map_err(|e| KeyError::KeyDerivationError(format!("HKDF expansion failed: {e}")))?;

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
            KeyError::DecryptionError(format!("Failed to parse ephemeral public key: {e}"))
        })?;

        // Use the ECDSA signing key bytes to create a SecretKey for ECDH
        let secret_key = SecretKey::from_bytes(&key_pair.signing_key().to_bytes())
            .map_err(|e| KeyError::DecryptionError(format!("Failed to create SecretKey: {e}")))?;
        let shared_secret =
            diffie_hellman(secret_key.to_nonzero_scalar(), ephemeral_public.as_affine());
        let shared_secret_bytes = shared_secret.raw_secret_bytes();

        // Derive encryption key using HKDF
        let hk = Hkdf::<Sha256>::new(None, shared_secret_bytes);
        let mut encryption_key = [0u8; 32];
        hk.expand(b"runar-key-encryption", &mut encryption_key)
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
        self.logger
            .info(format!("Processing setup token for node: {node_id}"));

        // Validate the CSR format
        if setup_token.csr_der.is_empty() {
            self.logger.error("Empty CSR in setup token");
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
        node_public_key: &[u8],
    ) -> Result<NetworkKeyMessage> {
        let network_key = self
            .network_data_keys
            .get(network_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Network key not found: {network_id}")))?;

        // Encrypt the network's private key for the node
        let network_private_key = network_key.private_key_der()?;
        let encrypted_network_key =
            self.encrypt_key_with_ecdsa(&network_private_key, node_public_key)?;

        let node_id = crate::compact_ids::compact_node_id(node_public_key);
        self.logger.info(format!(
            "Network key encrypted for node {node_id} with ECIES"
        ));

        Ok(NetworkKeyMessage {
            network_id: network_id.to_string(),
            network_public_key: network_key.public_key_bytes(),
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
        // Use envelope encryption with just this profile
        let envelope_data = MobileKeyManager::encrypt_with_envelope(
            self,
            data,
            "default",
            vec![profile_id.to_string()],
        )?;
        // Return just the encrypted data for compatibility
        Ok(envelope_data.encrypted_data)
    }

    /// Encrypt data for a network (legacy method for compatibility)  
    pub fn encrypt_for_network(&self, data: &[u8], network_id: &str) -> Result<Vec<u8>> {
        // Use envelope encryption with just this network
        let envelope_data =
            MobileKeyManager::encrypt_with_envelope(self, data, network_id, vec![])?;
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
        let message_len = message.len();
        self.logger
            .debug(format!("Encrypting message for node ({message_len} bytes)"));
        self.encrypt_key_with_ecdsa(message, node_public_key)
    }

    /// Decrypt a message from a node using the user's root key (ECIES)
    pub fn decrypt_message_from_node(&self, encrypted_message: &[u8]) -> Result<Vec<u8>> {
        let encrypted_message_len = encrypted_message.len();
        self.logger.debug(format!(
            "Decrypting message from node ({encrypted_message_len} bytes)"
        ));
        let root_key_pair = self
            .user_root_key
            .as_ref()
            .ok_or_else(|| KeyError::KeyNotFound("User root key not initialized".to_string()))?;
        self.decrypt_key_with_ecdsa(encrypted_message, root_key_pair)
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
            user_profile_keys: self.user_profile_keys.clone(),
            network_data_keys: self.network_data_keys.clone(),
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

        logger.info("Mobile Key Manager state imported".to_string());

        Ok(Self {
            certificate_authority,
            certificate_validator,
            user_root_key: state.user_root_key,
            user_profile_keys: state.user_profile_keys,
            network_data_keys: state.network_data_keys,
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
        network_id: &str,
        profile_ids: Vec<String>,
    ) -> crate::Result<crate::mobile::EnvelopeEncryptedData> {
        MobileKeyManager::encrypt_with_envelope(self, data, network_id, profile_ids)
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
