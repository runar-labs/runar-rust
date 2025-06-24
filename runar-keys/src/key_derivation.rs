use crate::crypto::SigningKeyPair;
use crate::error::Result;
use ed25519_dalek::SigningKey;

use rand::RngCore;
use sha2::{Digest, Sha256};

/// Key derivation using SLIP-0010
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive a key pair from a seed using SLIP-0010
    pub fn derive_from_seed(seed: &[u8], path: &str) -> Result<SigningKeyPair> {
        // Derive the key using SLIP-0010
        let (private_key, _chain_code) = ed25519_hd_key::derive_from_path(path, seed);

        // Convert to SigningKeyPair
        // Convert private_key (32 bytes) to a 64-byte array for SigningKeyPair
        let mut keypair_bytes = [0u8; 64];
        keypair_bytes[..32].copy_from_slice(&private_key);
        // Derive public key and store in second half
        let signing_key = SigningKey::from_bytes(&private_key.try_into().unwrap());
        keypair_bytes[32..].copy_from_slice(&signing_key.verifying_key().to_bytes());

        SigningKeyPair::from_bytes(&keypair_bytes)
    }

    /// Generate a random seed
    pub fn generate_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut seed);
        seed
    }

    /// Derive a user root key from a seed (path m/0')
    pub fn derive_user_root_key(seed: &[u8]) -> Result<SigningKeyPair> {
        Self::derive_from_seed(seed, "m/0'")
    }

    /// Derive a user profile key from a seed (path m/44'/1'/profile_index')
    pub fn derive_user_profile_key(seed: &[u8], profile_index: u32) -> Result<SigningKeyPair> {
        let path = format!("m/44'/1'/{}'", profile_index);
        Self::derive_from_seed(seed, &path)
    }

    /// Derive a user CA key from a seed and user public key
    pub fn derive_user_ca_key(seed: &[u8], user_public_key: &[u8]) -> Result<SigningKeyPair> {
        // Hash the user public key to get a deterministic index
        let mut hasher = Sha256::new();
        hasher.update(user_public_key);
        let hash = hasher.finalize();

        // Use the first 4 bytes of the hash as the index
        let index = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) & 0x7FFFFFFF;

        let path = format!("m/44'/2'/{}'", index);
        Self::derive_from_seed(seed, &path)
    }
}
