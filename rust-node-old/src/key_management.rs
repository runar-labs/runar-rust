use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Keypair, Signature, Signer};
use hkdf::Hkdf;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

/// The type of key used in the Runar network
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// Network identity key used for P2P connections
    Network,
    /// Node identity key used for signing data
    Node,
    /// User identity key for authentication
    User,
    /// Temporary key for ephemeral operations
    Temporary,
}

/// A keypair with additional metadata for the Runar network
#[derive(Debug)]
pub struct RunarKeypair {
    /// The underlying keypair
    keypair: Keypair,
    /// The type of key
    key_type: KeyType,
    /// Creation timestamp
    _created_at: Instant,
    /// Optional expiration for temporary keys
    expires_at: Option<Instant>,
}

impl RunarKeypair {
    /// Create a new keypair of the specified type
    pub fn new(key_type: KeyType, expiration: Option<Duration>) -> Result<Self> {
        // For now, use a non-cryptographic RNG during testing
        // In production, we should use a proper cryptographic RNG
        let mut seed = [0u8; 32];
        rand::thread_rng().fill(&mut seed);

        let secret = ed25519_dalek::SecretKey::from_bytes(&seed)
            .map_err(|e| anyhow!("Failed to create secret key: {}", e))?;
        let public = ed25519_dalek::PublicKey::from(&secret);

        let keypair = Keypair { secret, public };

        Ok(Self {
            keypair,
            key_type,
            _created_at: Instant::now(),
            expires_at: expiration.map(|d| Instant::now() + d),
        })
    }

    /// Create a keypair from existing key bytes
    pub fn from_bytes(
        key_type: KeyType,
        bytes: &[u8],
        expiration: Option<Duration>,
    ) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(anyhow!("Invalid keypair length: {}", bytes.len()));
        }

        let keypair =
            Keypair::from_bytes(bytes).map_err(|e| anyhow!("Failed to create keypair: {}", e))?;

        Ok(Self {
            keypair,
            key_type,
            _created_at: Instant::now(),
            expires_at: expiration.map(|d| Instant::now() + d),
        })
    }

    /// Check if the key has expired
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(instant) => instant <= Instant::now(),
            None => false,
        }
    }

    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        self.keypair.public.as_bytes()
    }

    /// Get the keypair bytes
    pub fn keypair_bytes(&self) -> [u8; 64] {
        self.keypair.to_bytes()
    }

    /// Sign a message using the private key
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.sign(message)
    }

    /// Verify a signature using the public key
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.keypair.verify(message, signature).is_ok()
    }

    /// Encrypt data using ChaCha20Poly1305
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Derive an encryption key from our keypair
        let salt = b"runar-encryption";
        let hkdf = Hkdf::<Sha256>::new(Some(salt), self.keypair.secret.as_bytes());
        let mut enc_key = [0u8; 32];
        hkdf.expand(b"chacha20poly1305-key", &mut enc_key)
            .map_err(|_| anyhow!("Failed to derive encryption key"))?;

        // Create the ChaCha20Poly1305 cipher
        let cipher = ChaCha20Poly1305::new_from_slice(&enc_key)
            .map_err(|_| anyhow!("Failed to create ChaCha20Poly1305 cipher"))?;

        // Generate a random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the plaintext
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| anyhow!("Encryption failed"))?;

        // Combine nonce and ciphertext
        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data using ChaCha20Poly1305
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(anyhow!("Ciphertext too short"));
        }

        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let actual_ciphertext = &ciphertext[12..];

        // Derive the encryption key
        let salt = b"runar-encryption";
        let hkdf = Hkdf::<Sha256>::new(Some(salt), self.keypair.secret.as_bytes());
        let mut enc_key = [0u8; 32];
        hkdf.expand(b"chacha20poly1305-key", &mut enc_key)
            .map_err(|_| anyhow!("Failed to derive encryption key"))?;

        // Create the ChaCha20Poly1305 cipher
        let cipher = ChaCha20Poly1305::new_from_slice(&enc_key)
            .map_err(|_| anyhow!("Failed to create ChaCha20Poly1305 cipher"))?;

        // Decrypt the ciphertext
        let plaintext = cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|_| anyhow!("Decryption failed"))?;

        Ok(plaintext)
    }
}

/// The KeyManager manages the lifecycle of keys
pub struct KeyManager {
    /// The keys managed by this instance
    keys: HashMap<KeyType, RunarKeypair>,
    /// The config directory where keys are stored
    config_dir: String,
}

impl KeyManager {
    /// Create a new key manager
    pub fn new(config_dir: &str) -> Result<Self> {
        // Ensure the config directory exists
        let path = Path::new(config_dir);
        if !path.exists() {
            fs::create_dir_all(path)?;
        }

        Ok(Self {
            keys: HashMap::new(),
            config_dir: config_dir.to_string(),
        })
    }

    /// Generate a new keypair
    pub fn generate_keypair() -> Result<Keypair> {
        // For now, use a non-cryptographic RNG during testing
        // In production, we should use a proper cryptographic RNG
        let mut seed = [0u8; 32];
        rand::thread_rng().fill(&mut seed);

        let secret = ed25519_dalek::SecretKey::from_bytes(&seed)
            .map_err(|e| anyhow!("Failed to create secret key: {}", e))?;
        let public = ed25519_dalek::PublicKey::from(&secret);

        Ok(Keypair { secret, public })
    }

    /// Load or create the node key
    pub fn load_or_create_node_key(&mut self) -> Result<&RunarKeypair> {
        if self.keys.contains_key(&KeyType::Node) {
            return Ok(&self.keys[&KeyType::Node]);
        }

        let key_path = Path::new(&self.config_dir).join("node_key");

        if key_path.exists() {
            // Load existing key
            let bytes = fs::read(&key_path)?;
            let keypair = RunarKeypair::from_bytes(KeyType::Node, &bytes, None)?;
            self.keys.insert(KeyType::Node, keypair);
        } else {
            // Create new key
            let keypair = RunarKeypair::new(KeyType::Node, None)?;
            fs::write(&key_path, &keypair.keypair_bytes())?;
            self.keys.insert(KeyType::Node, keypair);
        }

        Ok(&self.keys[&KeyType::Node])
    }

    /// Load or create the network key
    pub fn load_or_create_network_key(&mut self) -> Result<&RunarKeypair> {
        if self.keys.contains_key(&KeyType::Network) {
            return Ok(&self.keys[&KeyType::Network]);
        }

        let key_path = Path::new(&self.config_dir).join("network_key");

        if key_path.exists() {
            // Load existing key
            let bytes = fs::read(&key_path)?;
            let keypair = RunarKeypair::from_bytes(KeyType::Network, &bytes, None)?;
            self.keys.insert(KeyType::Network, keypair);
        } else {
            // Create new key
            let keypair = RunarKeypair::new(KeyType::Network, None)?;
            fs::write(&key_path, &keypair.keypair_bytes())?;
            self.keys.insert(KeyType::Network, keypair);
        }

        Ok(&self.keys[&KeyType::Network])
    }

    /// Add a temporary key with an expiration
    pub fn add_temporary_key(&mut self, duration: Duration) -> Result<&RunarKeypair> {
        let keypair = RunarKeypair::new(KeyType::Temporary, Some(duration))?;
        self.keys.insert(KeyType::Temporary, keypair);
        Ok(&self.keys[&KeyType::Temporary])
    }

    /// Get a key by type
    pub fn get_key(&self, key_type: KeyType) -> Option<&RunarKeypair> {
        self.keys.get(&key_type)
    }

    /// Cleanup expired keys
    pub fn cleanup_expired_keys(&mut self) {
        let expired_keys: Vec<KeyType> = self
            .keys
            .iter()
            .filter(|(_, keypair)| keypair.is_expired())
            .map(|(key_type, _)| *key_type)
            .collect();

        for key_type in expired_keys {
            self.keys.remove(&key_type);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use tempfile::tempdir;

    #[test]
    fn test_keypair_generation() {
        // Test keypair generation and basic properties
        let keypair = RunarKeypair::new(KeyType::Node, None).unwrap();

        // Check key type
        assert_eq!(keypair.key_type(), KeyType::Node);

        // Check key lengths
        assert_eq!(keypair.public_key_bytes().len(), 32);
        assert_eq!(keypair.keypair_bytes().len(), 64);

        // Check expiration
        assert_eq!(keypair.is_expired(), false);
    }

    #[test]
    fn test_signing_and_verification() {
        // Generate a keypair
        let keypair = RunarKeypair::new(KeyType::Node, None).unwrap();

        // Sign a message
        let message = b"Hello, Runar!";
        let signature = keypair.sign(message);

        // Verify the signature
        assert!(keypair.verify(message, &signature));

        // Verify that a modified message fails
        let modified_message = b"Hello, Runar?";
        assert!(!keypair.verify(modified_message, &signature));

        // Verify that a modified signature fails
        let mut signature_bytes = signature.to_bytes();
        signature_bytes[0] = signature_bytes[0].wrapping_add(1);
        let modified_signature = Signature::from_bytes(&signature_bytes).unwrap();
        assert!(!keypair.verify(message, &modified_signature));
    }

    #[test]
    fn test_encryption_and_decryption() {
        // Generate a keypair
        let keypair = RunarKeypair::new(KeyType::Node, None).unwrap();

        // Encrypt a message
        let plaintext = b"Secret Runar message";
        let ciphertext = keypair.encrypt(plaintext).unwrap();

        // Decrypt the message
        let decrypted = keypair.decrypt(&ciphertext).unwrap();

        // Check that the decrypted text matches the original
        assert_eq!(decrypted, plaintext);

        // Check that decryption fails with modified ciphertext
        let mut modified_ciphertext = ciphertext.clone();
        if modified_ciphertext.len() > 20 {
            modified_ciphertext[20] = modified_ciphertext[20].wrapping_add(1);
            assert!(keypair.decrypt(&modified_ciphertext).is_err());
        }
    }

    #[test]
    fn test_temporary_key_expiration() {
        // Create a temporary key that expires in 10ms
        let keypair =
            RunarKeypair::new(KeyType::Temporary, Some(Duration::from_millis(10))).unwrap();

        // Initially, the key should not be expired
        assert_eq!(keypair.is_expired(), false);

        // Wait for the key to expire
        sleep(Duration::from_millis(20));

        // Now the key should be expired
        assert_eq!(keypair.is_expired(), true);
    }

    #[test]
    fn test_key_manager() {
        // Create a temporary directory for the test
        let temp_dir = tempdir().unwrap();
        let config_dir = temp_dir.path().to_str().unwrap();

        // Create a new key manager
        let mut key_manager = KeyManager::new(config_dir).unwrap();

        // Load or create the node key
        let node_key = key_manager.load_or_create_node_key().unwrap();
        assert_eq!(node_key.key_type(), KeyType::Node);

        // Check that the key file exists
        let node_key_path = temp_dir.path().join("node_key");
        assert!(node_key_path.exists());

        // Add a temporary key
        let temp_key = key_manager
            .add_temporary_key(Duration::from_millis(10))
            .unwrap();
        assert_eq!(temp_key.key_type(), KeyType::Temporary);

        // Wait for the temporary key to expire
        sleep(Duration::from_millis(20));

        // Clean up expired keys
        key_manager.cleanup_expired_keys();

        // The temporary key should be gone
        assert!(key_manager.get_key(KeyType::Temporary).is_none());

        // The node key should still be there
        assert!(key_manager.get_key(KeyType::Node).is_some());
    }

    #[test]
    fn test_keypair_from_bytes() {
        // Create a keypair
        let original_keypair = RunarKeypair::new(KeyType::Node, None).unwrap();
        let keypair_bytes = original_keypair.keypair_bytes();

        // Create a new keypair from the bytes
        let new_keypair = RunarKeypair::from_bytes(KeyType::Node, &keypair_bytes, None).unwrap();

        // The public keys should match
        assert_eq!(
            original_keypair.public_key_bytes(),
            new_keypair.public_key_bytes()
        );

        // Check that signing with both keypairs produces verifiable signatures
        let message = b"Hello, Runar!";
        let signature1 = original_keypair.sign(message);
        let signature2 = new_keypair.sign(message);

        assert!(original_keypair.verify(message, &signature2));
        assert!(new_keypair.verify(message, &signature1));
    }
}
