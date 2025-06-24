use crate::crypto::{Certificate, EncryptionKeyPair, SigningKeyPair};
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
    pub fn generate_user_profile_key(&mut self) -> Result<(&SigningKeyPair, u32)> {
        let profile_index = self.profile_counter;
        self.profile_counter += 1;

        let key = self.key_manager.generate_user_profile_key(profile_index)?;
        Ok((key, profile_index))
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
    pub fn generate_network_data_key(&mut self, network_id: &str) -> Result<Vec<u8>> {
        self.key_manager.generate_network_data_key(network_id)
    }

    pub fn get_network_private_key(&self, network_id: &str) -> Result<Vec<u8>> {
        self.key_manager.get_network_private_key(network_id)
    }

    /// Encrypt data for a network and user profile
    pub fn encrypt_for_network_and_profile(
        &self,
        data: &[u8],
        network_id: &str,
        profile_index: u32,
    ) -> Result<Envelope> {
        // Get the network data key
        let network_key_id = format!("network_data_{}", network_id);
        let network_key = self
            .key_manager
            .get_encryption_key(&network_key_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!("Network key not found: {}", network_key_id))
            })?;

        // Get the user profile key
        let profile_key_id = format!("user_profile_{}", profile_index);
        let profile_key = self
            .key_manager
            .get_signing_key(&profile_key_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!("Profile key not found: {}", profile_key_id))
            })?;

        // For simplicity, we're using the signing key as an encryption key
        // In a real implementation, we would derive an encryption key from the profile key
        let profile_encryption_key =
            EncryptionKeyPair::from_secret(&profile_key.secret_key_bytes())?;

        // Create the envelope with consistent recipient IDs
        // IMPORTANT: The network_id recipient must match exactly what's used in decrypt_with_network_key
        let recipients = vec![
            // Use the exact network_id as the recipient ID for the node to decrypt
            (network_id.to_string(), network_key),
            // Use a profile-specific ID for the profile key
            (
                format!("profile:{}", profile_index),
                &profile_encryption_key,
            ),
        ];

        Envelope::new(data, &recipients)
    }

    /// Decrypt data using a user profile key
    pub fn decrypt_with_profile_key(
        &self,
        envelope: &Envelope,
        profile_index: u32,
    ) -> Result<Vec<u8>> {
        // Get the user profile key
        let profile_key_id = format!("user_profile_{}", profile_index);
        let profile_key = self
            .key_manager
            .get_signing_key(&profile_key_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!("Profile key not found: {}", profile_key_id))
            })?;

        // For simplicity, we're using the signing key as an encryption key
        // In a real implementation, we would derive an encryption key from the profile key
        let profile_encryption_key =
            EncryptionKeyPair::from_secret(&profile_key.secret_key_bytes())?;

        // Decrypt the envelope
        envelope.decrypt(
            &format!("profile:{}", profile_index),
            &profile_encryption_key,
        )
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
