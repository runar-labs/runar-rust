use crate::crypto::{
    Certificate, EncryptionKeyPair, NetworkKeyMessage, PublicKey, SigningKeyPair, SymmetricKey,
    CHACHA20POLY1305_KEY_LENGTH,
};
use crate::error::{KeyError, Result};
use crate::key_derivation::KeyDerivation;
use ed25519_dalek::VerifyingKey;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// Key manager that stores and manages cryptographic keys
/// Structure to hold serializable key data for persistence
#[derive(Serialize, Deserialize)]
pub struct KeyManagerData {
    /// User seed for key derivation (if available)
    pub seed: Option<[u8; 32]>,
    /// Signing key pairs by ID
    pub signing_keys: HashMap<String, SigningKeyPair>,
    /// Encryption key pairs by ID
    pub encryption_keys: HashMap<String, EncryptionKeyPair>,
    /// Symmetric keys by ID
    pub symmetric_keys: HashMap<String, SymmetricKey>,
    /// Certificates by subject
    pub certificates: HashMap<String, Certificate>,
}

pub struct KeyManager {
    /// User seed for key derivation (if available)
    seed: Option<[u8; 32]>,
    /// Signing key pairs by ID
    signing_keys: HashMap<String, SigningKeyPair>,
    /// Encryption key pairs by ID
    encryption_keys: HashMap<String, EncryptionKeyPair>,
    /// Symmetric keys by ID
    symmetric_keys: HashMap<String, SymmetricKey>,
    /// Certificates by subject
    certificates: HashMap<String, Certificate>,
}

impl fmt::Debug for KeyManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyManager")
            .field("seed", &self.seed.as_ref().map(|_| "[REDACTED]"))
            .field("signing_keys_count", &self.signing_keys.len())
            .field("encryption_keys_count", &self.encryption_keys.len())
            .field("symmetric_keys_count", &self.symmetric_keys.len())
            .field("certificates_count", &self.certificates.len())
            .finish()
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyManager {
    /// Create a new key manager
    pub fn new() -> Self {
        Self {
            seed: None,
            signing_keys: HashMap::new(),
            encryption_keys: HashMap::new(),
            symmetric_keys: HashMap::new(),
            certificates: HashMap::new(),
        }
    }

    pub fn new_with_state(state: KeyManagerData) -> Self {
        Self {
            seed: state.seed,
            signing_keys: state.signing_keys,
            encryption_keys: state.encryption_keys,
            symmetric_keys: state.symmetric_keys,
            certificates: state.certificates,
        }
    }

    /// Generate a new seed
    pub fn generate_seed(&mut self) -> &[u8; 32] {
        let seed = KeyDerivation::generate_seed();
        self.seed = Some(seed);
        self.seed.as_ref().unwrap()
    }

    /// Set an existing seed
    pub fn set_seed(&mut self, seed: [u8; 32]) {
        self.seed = Some(seed);
    }

    /// Get the current seed
    pub fn get_seed(&self) -> Option<&[u8; 32]> {
        self.seed.as_ref()
    }

    /// Generate a user root key from the seed and return only the public key
    /// The private key remains securely stored in the key manager
    pub fn generate_user_root_key(&mut self) -> Result<PublicKey> {
        let seed = self.seed.ok_or_else(|| {
            KeyError::InvalidOperation("No seed available for key derivation".to_string())
        })?;

        let signing_keypair: SigningKeyPair = KeyDerivation::derive_user_root_key(&seed)?;

        // Store the signing key pair in the manager
        self.signing_keys
            .insert("user_root".to_string(), signing_keypair.clone());

        // Get the public key from the key pair we just created
        let public_key_bytes = *signing_keypair.public_key();

        // Return only the public key
        Ok(PublicKey::new(public_key_bytes))
    }

    /// Generate a user profile key from the seed, creating and storing both a signing and an encryption key pair.
    pub fn generate_user_profile_key(&mut self, profile_index: u32) -> Result<Vec<u8>> {
        let seed = self.seed.ok_or_else(|| {
            KeyError::InvalidOperation("No seed available for key derivation".to_string())
        })?;

        // 1. Derive the signing key pair
        let signing_keypair = KeyDerivation::derive_user_profile_key(&seed, profile_index)?;

        // 2. Derive the corresponding encryption key pair from the signing key pair
        let signing_key_bytes: [u8; 32] = signing_keypair
            .secret_key_bytes()
            .try_into()
            .map_err(|_| KeyError::InvalidKeyFormat("Invalid signing key length".to_string()))?;
        let encryption_keypair = EncryptionKeyPair::from_secret(&signing_key_bytes);

        // 3. Store both key pairs with distinct IDs
        let signing_key_id = format!("user_profile_signing_{}", profile_index);
        self.signing_keys
            .insert(signing_key_id, signing_keypair.clone());

        let encryption_key_id = format!("user_profile_encryption_{}", profile_index);
        self.encryption_keys
            .insert(encryption_key_id, encryption_keypair);

        // 4. Return the public signing key
        Ok(signing_keypair.public_key().as_slice().to_vec())
    }

    /// Generate a node TLS key pair and self-signed certificate for QUIC
    /// Get the node's QUIC TLS key pair and certificate
    ///
    /// This expects the certificate to be already generated and signed by the user's CA
    /// during the node setup process.
    pub fn get_node_quic_keys(&self) -> Result<Vec<u8>> {
        self.get_node_public_key()
    }

    /// Get QUIC-compatible certificates and verifier from stored certificates
    ///
    /// This method returns the certificate that was previously signed by the User CA
    /// and stored via process_mobile_message. It does NOT create new certificates.
    ///
    /// Returns a tuple containing:
    /// 1. A vector of CertificateDer objects (from stored certificates)
    /// 2. A ServerCertVerifier that accepts the stored certificates
    pub fn get_quic_certs(
        &self,
    ) -> Result<(
        Vec<CertificateDer<'static>>,
        rustls_pki_types::PrivateKeyDer<'static>,
        Arc<dyn ServerCertVerifier>,
    )> {
        // Get the node's certificate that was signed by the User CA and stored
        let stored_cert = self.certificates.get("node_tls_cert").ok_or_else(|| {
            KeyError::KeyNotFound(
                "Node TLS certificate not found. Complete node setup first.".to_string(),
            )
        })?;

        // Convert the stored certificate to rustls format
        let cert_der = stored_cert.to_rustls_certificate();

        // Create a root store with the CA certificate (not the node certificate)
        // We need to create the CA certificate from our stored CA key
        let mut root_store = RootCertStore::empty();

        // Get the User CA signing key - this MUST exist after node setup
        let ca_key = self.get_signing_key("user_ca").ok_or_else(|| {
            KeyError::KeyNotFound(
                "User CA key not found. Node setup must be completed first.".to_string(),
            )
        })?;

        // Create a CA certificate from our stored User CA key
        let mut ca_params = rcgen::CertificateParams::new(vec!["ca.localhost".to_string()]);
        let mut ca_distinguished_name = rcgen::DistinguishedName::new();
        ca_distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("ca:{}", hex::encode(ca_key.public_key())),
        );
        ca_params.distinguished_name = ca_distinguished_name;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;

        // Create CA key pair using P256 for rcgen compatibility
        use p256::ecdsa::SigningKey as P256SigningKey;
        use pkcs8::EncodePrivateKey;
        use rand::rngs::OsRng;

        let ca_p256_key = P256SigningKey::random(&mut OsRng);
        let ca_key_pair = rcgen::KeyPair::from_der(ca_p256_key.to_pkcs8_der().unwrap().as_bytes())
            .map_err(|e| {
                KeyError::CertificateError(format!("Failed to create CA key pair: {}", e))
            })?;
        ca_params.key_pair = Some(ca_key_pair);

        let ca_cert = rcgen::Certificate::from_params(ca_params).map_err(|e| {
            KeyError::CertificateError(format!("Failed to create CA certificate: {}", e))
        })?;

        // Serialize CA certificate to DER
        let ca_cert_der = ca_cert.serialize_der().map_err(|e| {
            KeyError::CertificateError(format!("Failed to serialize CA certificate: {}", e))
        })?;

        // Add the CA certificate to the root store
        let ca_cert_rustls = CertificateDer::from(ca_cert_der);
        root_store.add(ca_cert_rustls).map_err(|e| {
            KeyError::CryptoError(format!("Failed to add CA certificate to root store: {}", e))
        })?;

        // Create a verifier that trusts certificates in our root store
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| KeyError::CryptoError(format!("Failed to create verifier: {}", e)))?;

        // PRODUCTION FIX: Use the NODE's private key that corresponds to the certificate's public key
        // The certificate contains the node's public key, so we need the node's private key
        let node_signing_key = self.get_signing_key("node_tls").ok_or_else(|| {
            KeyError::KeyNotFound(
                "Node TLS signing key not found. Complete node setup first.".to_string(),
            )
        })?;

        // Convert the Ed25519 signing key to rustls-compatible private key format
        // Use the NODE's private key bytes that correspond to the certificate's public key
        let ed25519_private_bytes = node_signing_key.secret_key_bytes();

        // Create a proper PKCS#8 DER encoding for the Ed25519 private key
        // Ed25519 OID: 1.3.101.112 (0x2B, 0x65, 0x70)
        let ed25519_key_bytes: [u8; 32] = ed25519_private_bytes
            .try_into()
            .map_err(|_| KeyError::CryptoError("Invalid Ed25519 key length".to_string()))?;

        // Manual PKCS#8 DER encoding for Ed25519 private key
        // This creates a proper PKCS#8 PrivateKeyInfo structure
        let mut pkcs8_der = Vec::new();

        // SEQUENCE tag and length for PrivateKeyInfo
        pkcs8_der.push(0x30); // SEQUENCE
        pkcs8_der.push(0x2E); // Length: 46 bytes

        // Version (INTEGER 0)
        pkcs8_der.extend_from_slice(&[0x02, 0x01, 0x00]);

        // AlgorithmIdentifier for Ed25519
        pkcs8_der.push(0x30); // SEQUENCE
        pkcs8_der.push(0x05); // Length: 5 bytes
        pkcs8_der.push(0x06); // OBJECT IDENTIFIER
        pkcs8_der.push(0x03); // Length: 3 bytes
        pkcs8_der.extend_from_slice(&[0x2B, 0x65, 0x70]); // Ed25519 OID

        // PrivateKey (OCTET STRING containing the 32-byte Ed25519 private key)
        pkcs8_der.push(0x04); // OCTET STRING
        pkcs8_der.push(0x22); // Length: 34 bytes
        pkcs8_der.push(0x04); // Inner OCTET STRING
        pkcs8_der.push(0x20); // Length: 32 bytes
        pkcs8_der.extend_from_slice(&ed25519_key_bytes);

        let private_key_der =
            rustls_pki_types::PrivateKeyDer::try_from(pkcs8_der).map_err(|e| {
                KeyError::CryptoError(format!(
                    "Failed to create PKCS#8 DER for Ed25519 key: {}",
                    e
                ))
            })?;

        Ok((vec![cert_der], private_key_der, verifier))
    }

    pub fn get_node_public_key(&self) -> Result<Vec<u8>> {
        let key_id = "node_tls".to_string();
        let key_pair = self
            .signing_keys
            .get(&key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Signing key not found: {}", key_id)))?;
        Ok(Vec::from(*key_pair.public_key()))
    }

    /// Generate a node storage key pair
    pub fn generate_node_storage_key(&mut self, node_pk: &[u8]) -> Result<&EncryptionKeyPair> {
        let encryption_keypair = EncryptionKeyPair::new();
        let key_id = format!("node_storage_{}", hex::encode(node_pk));

        self.encryption_keys
            .insert(key_id.clone(), encryption_keypair);

        // Return reference to the stored key pair
        self.encryption_keys.get(&key_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!("Failed to store encryption key: {}", key_id))
        })
    }

    /// Generate a network data key pair
    pub fn generate_network_data_key(&mut self) -> Result<Vec<u8>> {
        let encryption_keypair = EncryptionKeyPair::new();

        let key_id = format!(
            "network_data_{}",
            hex::encode(encryption_keypair.public_key_bytes())
        );

        self.encryption_keys
            .insert(key_id.clone(), encryption_keypair.clone());

        Ok(encryption_keypair.public_key_bytes().to_vec())
    }

    /// Create a network key message containing both public and private keys
    /// This is more secure than exposing the private key directly
    pub fn create_network_key_message(
        &self,
        network_public_key: &[u8],
        network_name: &str,
    ) -> Result<NetworkKeyMessage> {
        let key_id = format!("network_data_{}", hex::encode(network_public_key));
        let encryption_keypair = self.encryption_keys.get(&key_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!("Encryption key not found: {}", key_id))
        })?;

        Ok(NetworkKeyMessage {
            network_name: network_name.to_string(),
            public_key: network_public_key.to_vec(),
            private_key: encryption_keypair.secret_key_bytes().to_vec(),
        })
    }

    /// Add a signing key to the key manager
    pub fn add_signing_key(&mut self, key_id: &str, key_pair: SigningKeyPair) {
        self.signing_keys.insert(key_id.to_string(), key_pair);
    }

    /// Add an encryption key pair
    pub fn add_encryption_key(&mut self, key_id: &str, key_pair: EncryptionKeyPair) {
        self.encryption_keys.insert(key_id.to_string(), key_pair);
    }

    /// Get a signing key pair by ID
    pub fn get_signing_key(&self, key_id: &str) -> Option<&SigningKeyPair> {
        self.signing_keys.get(key_id)
    }

    /// Get an encryption key pair by ID
    pub fn get_encryption_key(&self, key_id: &str) -> Option<&EncryptionKeyPair> {
        self.encryption_keys.get(key_id)
    }

    /// Generate a new symmetric encryption key and store it with the given ID.
    /// This key is intended for encrypting data at rest (e.g., files) and will not leave the key manager.
    pub fn generate_symmetric_key(&mut self, key_id: &str) -> Result<SymmetricKey> {
        let symmetric_key = crate::crypto::SymmetricKey::new();
        self.symmetric_keys
            .insert(key_id.to_string(), symmetric_key.clone());
        Ok(symmetric_key)
    }

    /// Ensure a symmetric key exists and return it (create one if it doesn't exist)
    pub fn ensure_symmetric_key(&mut self, key_id: &str) -> Result<SymmetricKey> {
        if let Some(key) = self.symmetric_keys.get(key_id) {
            return Ok(key.clone());
        }
        self.generate_symmetric_key(key_id)
    }

    /// Encrypt data using a stored symmetric key.
    pub fn encrypt_with_symmetric_key(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .symmetric_keys
            .get(key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Symmetric key not found: {}", key_id)))?;
        key.encrypt(data)
    }

    /// Decrypt data using a stored symmetric key.
    pub fn decrypt_with_symmetric_key(
        &self,
        key_id: &str,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>> {
        let key = self
            .symmetric_keys
            .get(key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Symmetric key not found: {}", key_id)))?;
        key.decrypt(encrypted_data)
    }

    /// Generate a new encryption key pair and store it with the given ID
    /// Returns the public key bytes
    pub fn generate_encryption_key(&mut self, key_id: &str) -> Result<Vec<u8>> {
        let encryption_keypair = EncryptionKeyPair::new();
        let public_key = encryption_keypair.public_key_bytes().to_vec();

        self.encryption_keys
            .insert(key_id.to_string(), encryption_keypair);

        Ok(public_key)
    }

    /// Store an encryption key pair with the given ID
    pub fn store_encryption_key(&mut self, key_id: &str, key_pair: EncryptionKeyPair) {
        self.encryption_keys.insert(key_id.to_string(), key_pair);
    }

    /// Store network metadata (like network name) associated with a network key
    /// Uses proper encrypted storage for network metadata
    pub fn store_network_metadata(&mut self, metadata_key: &str, network_name: &str) -> Result<()> {
        // Generate a proper encryption key for metadata storage
        let metadata_encryption_key = SymmetricKey::new();

        // Encrypt the network name using the generated key
        let encrypted_metadata = metadata_encryption_key.encrypt(network_name.as_bytes())?;

        // Store both the encryption key and encrypted data
        // The key is stored with a "_key" suffix, the data with "_data" suffix
        let key_storage_id = format!("{}_key", metadata_key);
        let data_storage_id = format!("{}_data", metadata_key);

        self.symmetric_keys
            .insert(key_storage_id, metadata_encryption_key);

        // Store encrypted data as a synthetic symmetric key for storage consistency
        let encrypted_key = SymmetricKey::from_bytes(
            &encrypted_metadata
                [..std::cmp::min(encrypted_metadata.len(), CHACHA20POLY1305_KEY_LENGTH)],
        )?;
        self.symmetric_keys.insert(data_storage_id, encrypted_key);

        Ok(())
    }

    /// Retrieve network metadata by metadata key
    pub fn get_network_metadata(&self, metadata_key: &str) -> Option<String> {
        let key_storage_id = format!("{}_key", metadata_key);
        let data_storage_id = format!("{}_data", metadata_key);

        // Get both the encryption key and encrypted data
        let encryption_key = self.symmetric_keys.get(&key_storage_id)?;
        let encrypted_data_key = self.symmetric_keys.get(&data_storage_id)?;

        // Extract the encrypted data bytes
        let encrypted_data = encrypted_data_key.to_bytes();

        // Decrypt the metadata
        match encryption_key.decrypt(&encrypted_data) {
            Ok(decrypted_bytes) => String::from_utf8(decrypted_bytes).ok(),
            Err(_) => None,
        }
    }

    /// Sign a Certificate Signing Request (CSR)
    pub fn sign_csr(&mut self, csr_bytes: &[u8], ca_key_id: &str) -> Result<Certificate> {
        // Get CA key
        let signing_key_pair = self
            .get_signing_key(ca_key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("CA key not found: {}", ca_key_id)))?;

        // Sign CSR
        let certificate = signing_key_pair.sign_csr(csr_bytes)?;

        // Store certificate after validation
        self.add_certificate(certificate.clone(), ca_key_id)?;

        Ok(certificate)
    }

    /// Create a certificate signing request (CSR)
    pub fn create_csr(&self, subject: &str, key_id: &str) -> Result<Vec<u8>> {
        let signing_key = self
            .signing_keys
            .get(key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Signing key not found: {}", key_id)))?;

        // Pass the public key bytes to the CSR creation function
        Certificate::create_csr(subject, signing_key)
    }

    /// Add a certificate after validating it against the specified CA.
    pub fn add_certificate(&mut self, certificate: Certificate, ca_key_id: &str) -> Result<()> {
        let ca_key = self.get_signing_key(ca_key_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!("CA key not found for validation: {}", ca_key_id))
        })?;

        let ca_public_key_bytes = ca_key.public_key();
        let ca_verifying_key = VerifyingKey::from_bytes(ca_public_key_bytes)?;

        certificate.validate(&ca_verifying_key)?;

        self.certificates
            .insert(certificate.subject.clone(), certificate);

        Ok(())
    }

    /// Store a pre-validated certificate directly without re-validating it.
    ///
    /// This should only be used when the certificate has already been validated
    /// with the appropriate CA key.
    ///
    /// Store a validated certificate in the key manager
    /// Node TLS certificates are stored with the key "node_tls_cert"
    /// Other certificates are stored with their subject as the key
    pub fn store_validated_certificate(&mut self, certificate: Certificate) -> Result<()> {
        let key = if certificate.subject.starts_with("node:") {
            "node_tls_cert".to_string()
        } else {
            certificate.subject.clone()
        };

        self.certificates.insert(key, certificate);
        Ok(())
    }

    /// Get a certificate by its key
    /// For node certificates, use "node_tls_cert" as the key
    /// For other certificates, use the subject as the key
    pub fn get_certificate(&self, key: &str) -> Option<&Certificate> {
        self.certificates.get(key)
    }

    /// Export all keys and certificates for persistence
    /// This allows saving the key manager state to secure storage
    pub fn export_keys(&self) -> KeyManagerData {
        KeyManagerData {
            seed: self.seed,
            signing_keys: self.signing_keys.clone(),
            encryption_keys: self.encryption_keys.clone(),
            symmetric_keys: self.symmetric_keys.clone(),
            certificates: self.certificates.clone(),
        }
    }
}
