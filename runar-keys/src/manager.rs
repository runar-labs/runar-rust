use crate::crypto::{Certificate, EncryptionKeyPair, SigningKeyPair};
use crate::error::{KeyError, Result};
use crate::key_derivation::KeyDerivation;

use std::collections::HashMap;

/// Key manager that stores and manages cryptographic keys
pub struct KeyManager {
    /// User seed for key derivation (if available)
    seed: Option<[u8; 32]>,
    /// Signing key pairs by ID
    signing_keys: HashMap<String, SigningKeyPair>,
    /// Encryption key pairs by ID
    encryption_keys: HashMap<String, EncryptionKeyPair>,
    /// Certificates by subject
    certificates: HashMap<String, Certificate>,
}

impl KeyManager {
    /// Create a new key manager
    pub fn new() -> Self {
        Self {
            seed: None,
            signing_keys: HashMap::new(),
            encryption_keys: HashMap::new(),
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

    /// Generate a user root key from the seed
    pub fn generate_user_root_key(&mut self) -> Result<&SigningKeyPair> {
        let seed = self.seed.ok_or_else(|| {
            KeyError::InvalidOperation("No seed available for key derivation".to_string())
        })?;

        let signing_keypair: SigningKeyPair = KeyDerivation::derive_user_root_key(&seed)?;

        self.signing_keys
            .insert("user_root".to_string(), signing_keypair);

        Ok(self.signing_keys.get("user_root").unwrap())
    }

    /// Generate a user profile key from the seed, creating and storing both a signing and an encryption key pair.
    pub fn generate_user_profile_key(&mut self, profile_index: u32) -> Result<Vec<u8>> {
        let seed = self.seed.ok_or_else(|| {
            KeyError::InvalidOperation("No seed available for key derivation".to_string())
        })?;

        // 1. Derive the signing key pair
        let signing_keypair = KeyDerivation::derive_user_profile_key(&seed, profile_index)?;

        // 2. Derive the corresponding encryption key pair from the signing key pair
        let encryption_keypair = EncryptionKeyPair::from_key_pair(&signing_keypair);

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

    /// Generate a network CA key from the seed
    pub fn generate_user_ca_key(&mut self, user_public_key: &[u8]) -> Result<Vec<u8>> {
        let seed = self.seed.ok_or_else(|| {
            KeyError::InvalidOperation("No seed available for key derivation".to_string())
        })?;

        let signing_keypair = KeyDerivation::derive_user_ca_key(&seed, user_public_key)?;

        let key_id = format!("user_ca_{}", hex::encode(user_public_key));
        self.signing_keys
            .insert(key_id.clone(), signing_keypair.clone());

        Ok(signing_keypair.public_key().to_vec())
    }

    /// Generate a node TLS key pair
    pub fn generate_node_tls_key(&mut self) -> Result<Vec<u8>> {
        let signing_keypair = SigningKeyPair::generate();
        let key_id = format!("node_tls_{}", hex::encode(signing_keypair.public_key()));
        self.signing_keys
            .insert(key_id.clone(), signing_keypair.clone());

        Ok(signing_keypair.public_key().to_vec())
    }

    /// Generate a node storage key pair
    pub fn generate_node_storage_key(&mut self, node_pk: &[u8]) -> Result<&EncryptionKeyPair> {
        let encryption_keypair = EncryptionKeyPair::generate();

        let key_id = format!("node_storage_{}", hex::encode(node_pk));
        self.encryption_keys
            .insert(key_id.clone(), encryption_keypair);

        Ok(self.encryption_keys.get(&key_id).unwrap())
    }

    /// Generate a network data key pair
    pub fn generate_network_data_key(&mut self) -> Result<Vec<u8>> {
        let encryption_keypair = EncryptionKeyPair::generate();

        let key_id = format!(
            "network_data_{}",
            hex::encode(encryption_keypair.public_key())
        );

        self.encryption_keys
            .insert(key_id.clone(), encryption_keypair.clone());

        Ok(encryption_keypair.public_key().as_bytes().to_vec())
    }

    // TODO how to secure this method so it only is available in the mobile build -
    // maybe as a feature flag
    pub fn get_network_private_key(&self, network_public_key: &[u8]) -> Result<Vec<u8>> {
        let key_id = format!("network_data_{}", hex::encode(network_public_key));
        let encryption_keypair = self.encryption_keys.get(&key_id).ok_or_else(|| {
            KeyError::KeyNotFound(format!("Encryption key not found: {}", key_id))
        })?;

        Ok(encryption_keypair.secret_key_bytes().to_vec())
    }

    /// Add a signing key pair
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

    /// Sign a Certificate Signing Request (CSR)
    pub fn sign_csr(&mut self, csr_bytes: &[u8], ca_key_id: &str) -> Result<Certificate> {
        // Get CA key
        let signing_key_pair = self
            .get_signing_key(ca_key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("CA key not found: {}", ca_key_id)))?;

        // Sign CSR
        let certificate = signing_key_pair.sign_csr(csr_bytes)?;

        // Store certificate
        self.add_certificate(certificate.clone());

        Ok(certificate)
    }

    //TODO verify if this is correct.. the verificatio of the certificate
    /// Create a certificate signing request (CSR)
    pub fn create_csr(&self, subject: &str, key_id: &str) -> Result<Vec<u8>> {
        let signing_key = self
            .signing_keys
            .get(key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Signing key not found: {}", key_id)))?;

        Certificate::create_csr(subject, &signing_key.public_key())
    }

    /// Add a certificate
    pub fn add_certificate(&mut self, certificate: Certificate) {
        self.certificates
            .insert(certificate.subject.clone(), certificate);
    }

    /// Get a certificate by subject
    pub fn get_certificate(&self, subject: &str) -> Option<&Certificate> {
        self.certificates.get(subject)
    }

    /// Verify a certificate's signature
    pub fn verify_certificate(&self, certificate: &Certificate) -> Result<()> {
        // Verify certificate signature
        match certificate.verify(certificate.data.as_bytes(), &certificate.signature)? {
            true => Ok(()),
            false => Err(KeyError::SignatureError(
                "Certificate signature verification failed".to_string(),
            )),
        }
    }
}
