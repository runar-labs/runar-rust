use crate::crypto::{Certificate, SigningKeyPair};
use crate::envelope::Envelope;
use crate::error::{KeyError, Result};
use crate::manager::KeyManager;
use crate::node::SetupToken;

/// Mobile key manager
pub struct MobileKeyManager {
    /// The underlying key manager
    key_manager: KeyManager,

    user_public_key: Option<Vec<u8>>,
    /// User profile index counter
    profile_counter: u32,
}

impl MobileKeyManager {
    /// Create a new mobile key manager
    pub fn new() -> Self {
        Self {
            key_manager: KeyManager::new(),
            user_public_key: None,
            profile_counter: 0,
        }
    }

    /// Generate a new seed
    pub fn generate_seed(&mut self) -> &[u8; 32] {
        self.key_manager.generate_seed()
    }

    /// Set an existing seed
    pub fn set_seed(&mut self, seed: [u8; 32]) {
        self.key_manager.set_seed(seed);
    }

    /// Generate the user root key
    pub fn generate_user_root_key(&mut self) -> Result<&SigningKeyPair> {
        let key_pair = self.key_manager.generate_user_root_key()?;
        self.user_public_key = Some(key_pair.public_key().to_vec());
        Ok(key_pair)
    }

    /// Generate a user CA key
    pub fn generate_user_ca_key(&mut self, user_public_key: &[u8]) -> Result<Vec<u8>> {
        self.key_manager.generate_user_ca_key(user_public_key)
    }

    /// Generate a user profile key
    pub fn generate_user_profile_key(&mut self) -> Result<(Vec<u8>, u32)> {
        let profile_index = self.profile_counter;
        self.profile_counter += 1;

        let public_key = self.key_manager.generate_user_profile_key(profile_index)?;
        Ok((public_key, profile_index))
    }

    /// Process a node setup token
    pub fn process_setup_token(&mut self, token: &SetupToken) -> Result<Certificate> {
        // Get the User CA key
        let ca_key_id = format!(
            "user_ca_{}",
            hex::encode(
                self.user_public_key
                    .as_ref()
                    .expect("User public key not found")
            )
        );
        let ca_key = self
            .key_manager
            .get_signing_key(&ca_key_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!("User CA key not found: {}", ca_key_id))
            })?;

        // Parse CSR from setup token
        let csr_bytes = &token.tls_csr;

        // Sign CSR with CA key
        let certificate = ca_key.sign_csr(csr_bytes)?;

        // Store the certificate
        self.key_manager.add_certificate(certificate.clone());

        Ok(certificate)
    }

    /// Generate a network data key
    pub fn generate_network_data_key(&mut self) -> Result<Vec<u8>> {
        self.key_manager.generate_network_data_key()
    }

    pub fn get_network_private_key(&self, network_public_key: &[u8]) -> Result<Vec<u8>> {
        self.key_manager.get_network_private_key(network_public_key)
    }

    // TODO change thios to receive the profile public key instead of the index..
    // the Key manager will maintain a map of profile public keys to indexes
    /// Encrypt data for a network and user profile
    pub fn encrypt_for_network_and_profile(
        &self,
        data: &[u8],
        network_public_key: &[u8],
        profile_index: u32,
    ) -> Result<Envelope> {
        // Get the network data key
        let network_key_id = format!("network_data_{}", hex::encode(network_public_key));
        let network_key = self
            .key_manager
            .get_encryption_key(&network_key_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!("Network key not found: {}", network_key_id))
            })?;

        // Get the user profile encryption key, which is now stored correctly in the manager
        let profile_encryption_key_id = format!("user_profile_encryption_{}", profile_index);
        let profile_encryption_key = self
            .key_manager
            .get_encryption_key(&profile_encryption_key_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!(
                    "Profile encryption key not found: {}",
                    profile_encryption_key_id
                ))
            })?;

        let recipients = vec![network_key, profile_encryption_key];

        Envelope::new(data, &recipients)
    }

    /// Decrypt data using a user profile key
    pub fn decrypt_with_profile_key(
        &self,
        envelope: &Envelope,
        profile_index: u32,
    ) -> Result<Vec<u8>> {
        // Get the user profile encryption key, which is now stored correctly in the manager
        let profile_encryption_key_id = format!("user_profile_encryption_{}", profile_index);
        let profile_encryption_key = self
            .key_manager
            .get_encryption_key(&profile_encryption_key_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!(
                    "Profile encryption key not found: {}",
                    profile_encryption_key_id
                ))
            })?;

        // Decrypt the envelope
        envelope.decrypt(profile_encryption_key)
    }

    /// Get the underlying key manager
    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }

    /// Get the underlying key manager mutably
    pub fn key_manager_mut(&mut self) -> &mut KeyManager {
        &mut self.key_manager
    }
}
