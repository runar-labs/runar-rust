use crate::crypto::{Certificate, EncryptionKeyPair, NodeMessage, PublicKey};
use crate::envelope::Envelope;
use crate::error::{KeyError, Result};
use crate::key_derivation::KeyDerivation;
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

    /// Generate the user root key and return only the public key
    /// The private key remains securely stored in the key manager
    pub fn generate_user_root_key(&mut self) -> Result<PublicKey> {
        let public_key = self.key_manager.generate_user_root_key()?;
        self.user_public_key = Some(public_key.bytes().to_vec());
        Ok(public_key)
    }

    /// Generate a user CA key derived from the user's root key.
    /// Returns only the public key while storing the private key securely in the key manager.
    pub fn generate_user_ca_key(&mut self) -> Result<PublicKey> {
        let seed = self.key_manager.get_seed().ok_or_else(|| {
            KeyError::InvalidOperation("Cannot generate user CA key without a seed".to_string())
        })?;

        let user_root_key = KeyDerivation::derive_user_root_key(seed)?;
        let ca_key = KeyDerivation::derive_user_ca_key(&user_root_key)?;

        // Store the CA key in the key manager
        self.key_manager
            .add_signing_key("user_ca_key", ca_key.clone());

        // Return only the public key
        Ok(PublicKey::new(*ca_key.public_key()))
    }

    /// Generate a user profile key
    pub fn generate_user_profile_key(&mut self) -> Result<(Vec<u8>, u32)> {
        let profile_index = self.profile_counter;
        self.profile_counter += 1;

        let public_key = self.key_manager.generate_user_profile_key(profile_index)?;
        Ok((public_key, profile_index))
    }

    /// Process a node setup token by signing the CSR with the User CA key.
    /// 
    /// This method also stores the node's encryption public key for secure communication.
    pub fn process_setup_token(&mut self, token: &SetupToken) -> Result<Certificate> {
        // Store the node's encryption public key for future secure communication
        let node_id = hex::encode(&token.node_public_key);
        let key_id = format!("node_encryption_{}", node_id);
        
        // Store the encryption key in the key manager
        // We're only storing the public key since we only need it for encryption
        let encryption_key = EncryptionKeyPair::from_public_key(&token.node_encryption_public_key)?;
        self.key_manager.store_encryption_key(&key_id, encryption_key);
        
        // Sign the CSR from the token with the User CA key
        self.key_manager.sign_csr(&token.tls_csr, "user_ca_key")
    }

    /// Encrypt a message containing certificate and CA public key for secure transmission to a node
    /// 
    /// This creates an envelope that can only be decrypted by the node with the given node_id.
    /// The node_id should be the hex-encoded node public key from the setup token.
    pub fn encrypt_message_for_node(&self, certificate: &Certificate, node_id: &str) -> Result<Envelope> {
        // Get the CA key to include its public key in the message
        let ca_key = self.key_manager.get_signing_key("user_ca_key")
            .ok_or_else(|| KeyError::KeyNotFound("User CA key not found".to_string()))?;
        
        // Create a NodeMessage containing both the certificate and CA public key
        let node_message = NodeMessage {
            certificate: certificate.clone(),
            ca_public_key: ca_key.public_key().to_vec(),
        };
        
        // Get the node's encryption key from storage
        let key_id = format!("node_encryption_{}", node_id);
        let encryption_key = self.key_manager.get_encryption_key(&key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Node encryption key not found for {}", node_id)))?;
        
        // Serialize the message to bytes using bincode for binary serialization
        let message_bytes = bincode::serialize(&node_message)
            .map_err(|e| KeyError::SerializationError(e.to_string()))?;
        
        // Create an envelope with the message as payload, encrypted for the node
        let envelope = Envelope::new(&message_bytes, &[encryption_key])
            .map_err(|e| KeyError::EncryptionError(e.to_string()))?;
            
        Ok(envelope)
    }
    
    /// Encrypt a certificate for secure transmission to a node (deprecated)
    /// 
    /// This method is kept for backward compatibility. Use encrypt_message_for_node instead.
    pub fn encrypt_certificate_for_node(&self, certificate: &Certificate, node_id: &str) -> Result<Envelope> {
        self.encrypt_message_for_node(certificate, node_id)
    }

    /// Generate a network data key
    pub fn generate_network_data_key(&mut self) -> Result<Vec<u8>> {
        self.key_manager.generate_network_data_key()
    }

    /// Create an encrypted network keys message for secure transmission to a node
    /// 
    /// This creates an envelope containing network keys that can only be decrypted by the node with the given node_id.
    /// The node_id should be the hex-encoded node public key from the setup token.
    pub fn create_network_keys_message(&self, network_public_key: &[u8], network_name: &str, node_id: &str) -> Result<Envelope> {
        // Create a NetworkKeyMessage using the key manager
        let network_key_message = self.key_manager.create_network_key_message(network_public_key, network_name)?;
        
        // Get the node's encryption key from storage
        let key_id = format!("node_encryption_{}", node_id);
        let encryption_key = self.key_manager.get_encryption_key(&key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Node encryption key not found for {}", node_id)))?;
        
        // Serialize the message to bytes using bincode for binary serialization
        let message_bytes = bincode::serialize(&network_key_message)
            .map_err(|e| KeyError::SerializationError(e.to_string()))?;
        
        // Create an envelope with the message as payload, encrypted for the node
        let envelope = Envelope::new(&message_bytes, &[encryption_key])
            .map_err(|e| KeyError::EncryptionError(e.to_string()))?;
            
        Ok(envelope)
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
