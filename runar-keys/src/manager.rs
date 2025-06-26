use crate::crypto::{
    Certificate, EncryptionKeyPair, NetworkKeyMessage, PublicKey, SigningKeyPair, SymmetricKey,
};
use crate::error::{KeyError, Result};
use crate::key_derivation::KeyDerivation;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;

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
            .insert("user_root".to_string(), signing_keypair);

        // Get the public key from the stored key pair
        let key_pair = self.signing_keys.get("user_root").unwrap();
        let public_key_bytes = *key_pair.public_key();

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
        let encryption_keypair = EncryptionKeyPair::from_secret(signing_keypair.secret_key_bytes());

        // 3. Store both key pairs with distinct IDs
        let signing_key_id = format!("user_profile_signing_{}", profile_index);
        self.signing_keys
            .insert(signing_key_id, signing_keypair.clone());

        let encryption_key_id = format!("user_profile_encryption_{}", profile_index);
        self.encryption_keys
            .insert(encryption_key_id, encryption_keypair);

        // 4. Return the public signing key
        Ok(signing_keypair.public_key().to_vec())
    }

    /// Generate a node TLS key pair
    pub fn generate_node_tls_key(&mut self) -> Result<Vec<u8>> {
        let signing_keypair = SigningKeyPair::new();
        let key_id = format!("node_tls_{}", hex::encode(signing_keypair.public_key()));
        self.signing_keys
            .insert(key_id.clone(), signing_keypair.clone());

        Ok(signing_keypair.public_key().to_vec())
    }

    /// Generate a node storage key pair
    pub fn generate_node_storage_key(&mut self, node_pk: &[u8]) -> Result<&EncryptionKeyPair> {
        let encryption_keypair = EncryptionKeyPair::new();

        let key_id = format!("node_storage_{}", hex::encode(node_pk));
        self.encryption_keys
            .insert(key_id.clone(), encryption_keypair);

        Ok(self.encryption_keys.get(&key_id).unwrap())
    }

    /// Generate a network data key pair
    pub fn generate_network_data_key(&mut self) -> Result<Vec<u8>> {
        let encryption_keypair = EncryptionKeyPair::new();

        let key_id = format!(
            "network_data_{}",
            hex::encode(encryption_keypair.public_key())
        );

        self.encryption_keys
            .insert(key_id.clone(), encryption_keypair.clone());

        Ok(encryption_keypair.public_key().to_vec())
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
            private_key: encryption_keypair.secret_key().to_vec(),
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
        let public_key = encryption_keypair.public_key().to_vec();

        self.encryption_keys
            .insert(key_id.to_string(), encryption_keypair);

        Ok(public_key)
    }

    /// Store an encryption key pair with the given ID
    pub fn store_encryption_key(&mut self, key_id: &str, key_pair: EncryptionKeyPair) {
        self.encryption_keys.insert(key_id.to_string(), key_pair);
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
        Certificate::create_csr(subject, signing_key.public_key())
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
    pub fn store_validated_certificate(&mut self, certificate: Certificate) -> Result<()> {
        self.certificates
            .insert(certificate.subject.clone(), certificate);

        Ok(())
    }

    /// Get a certificate by subject
    pub fn get_certificate(&self, subject: &str) -> Option<&Certificate> {
        self.certificates.get(subject)
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

    /// Import keys and certificates from persistence
    /// This allows restoring the key manager state from secure storage
    pub fn import_keys(&mut self, data: KeyManagerData) {
        self.seed = data.seed;
        self.signing_keys = data.signing_keys;
        self.encryption_keys = data.encryption_keys;
        self.symmetric_keys = data.symmetric_keys;
        self.certificates = data.certificates;
    }
}
