use crate::crypto::SigningKeyPair;
use crate::error::Result;
// SigningKey is imported via the SigningKeyPair struct

use rand::RngCore;
use hkdf::Hkdf;
use sha2::Sha256;

/// Key derivation using SLIP-0010
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive a key pair from a seed using SLIP-0010
    pub fn derive_from_seed(seed: &[u8], path: &str) -> Result<SigningKeyPair> {
        // Derive the key using SLIP-0010
        let (private_key, _chain_code) = ed25519_hd_key::derive_from_path(path, seed);

        Ok(SigningKeyPair::from_secret(&private_key))
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

    /// Derive a user CA key from the user's root key using HKDF.
    pub fn derive_user_ca_key(user_root_key: &SigningKeyPair) -> Result<SigningKeyPair> {
        const INFO_PERSON: &[u8] = b"runar-network-ca-key";

        let ikm = user_root_key.secret_key_bytes();
        let salt = [0u8; 32]; // A fixed salt is acceptable for this use case

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 32]; // Output key material
        hkdf.expand(INFO_PERSON, &mut okm)?;

        Ok(SigningKeyPair::from_secret(&okm))
    }
}
