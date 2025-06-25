use crate::crypto::{Certificate, EncryptionKeyPair, NetworkKeyMessage, NodeMessage};
use crate::envelope::Envelope;
use crate::error::{KeyError, Result};
use crate::manager::{KeyManager, KeyManagerData};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

/// Represents a setup token for node initialization
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SetupToken {
    pub token_id: String,
    /// Node identifier (TLS public key)
    pub node_public_key: Vec<u8>,
    /// Node encryption public key for secure communication
    pub node_encryption_public_key: Vec<u8>,
    /// TLS certificate signing request
    pub tls_csr: Vec<u8>,
    /// Time to live in seconds
    pub ttl: u64,
}

/// Data structure for serializing node key manager state
#[derive(Serialize, Deserialize)]
pub struct NodeKeyManagerData {
    /// Key manager data
    pub key_manager_data: KeyManagerData,
}

/// Node key manager
pub struct NodeKeyManager {
    /// The underlying key manager
    key_manager: KeyManager,
    /// Node identifier
    node_public_key: Vec<u8>,
    //TODO review and remove this... node can participate in a multiple networiks not just one
    // Network identifier (if part of a network)
    //network_id: Option<String>,
}

impl Default for NodeKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeKeyManager {
    /// Create a new node key manager
    pub fn new() -> Self {
        let mut key_manager = KeyManager::new();
        let node_public_key = key_manager
            .generate_node_tls_key()
            .expect("Failed to generate node TLS key");

        // Generate an encryption key pair for the node
        key_manager
            .generate_encryption_key("node_encryption")
            .expect("Failed to generate node encryption key");

        // Generate a symmetric key for local file/data encryption
        key_manager
            .generate_symmetric_key("node_storage")
            .expect("Failed to generate node storage key");

        Self {
            key_manager,
            node_public_key,
        }
    }

    /// Get the node's encryption public key for secure communication
    pub fn get_encryption_public_key(&self) -> Result<Vec<u8>> {
        let encryption_key = self
            .key_manager
            .get_encryption_key("node_encryption")
            .ok_or_else(|| KeyError::KeyNotFound("Node encryption key not found".to_string()))?;

        Ok(encryption_key.public_key().to_vec())
    }

    /// Get the node ID
    pub fn node_public_key(&self) -> &Vec<u8> {
        &self.node_public_key
    }

    /// Generate a setup token using the existing node TLS key
    pub fn generate_setup_token(&mut self) -> Result<SetupToken> {
        // Use the existing node public key that was generated during initialization
        let node_public_key = self.node_public_key.clone();
        let subject = format!("node:{}", hex::encode(&node_public_key));

        // Create CSR for the node TLS key
        let tls_key_id = format!("node_tls_{}", hex::encode(&node_public_key));
        let tls_csr = self.key_manager.create_csr(&subject, &tls_key_id)?;

        // Ensure node has an encryption key pair for secure communication
        let node_encryption_public_key =
            if let Some(key) = self.key_manager.get_encryption_key("node_encryption") {
                key.public_key().to_vec()
            } else {
                // Generate a new encryption key pair if one doesn't exist
                self.key_manager
                    .generate_encryption_key("node_encryption")?
            };

        // Create a setup token
        let token = SetupToken {
            token_id: uuid::Uuid::new_v4().to_string(),
            node_public_key,
            node_encryption_public_key,
            tls_csr,
            ttl: 3600, // 1 hour
        };

        Ok(token)
    }

    /// Decrypt an encrypted envelope containing a NodeMessage
    ///
    /// This method decrypts a NodeMessage that was encrypted specifically for this node.
    /// The NodeMessage contains both the certificate and the CA public key needed to verify it.
    pub fn decrypt_node_message(&self, envelope: &Envelope) -> Result<NodeMessage> {
        // Get the node's encryption key pair
        let node_encryption_key = self
            .key_manager
            .get_encryption_key("node_encryption")
            .ok_or_else(|| KeyError::KeyNotFound("Node encryption key not found".to_string()))?;

        // Decrypt the envelope
        let decrypted_bytes = envelope.decrypt(node_encryption_key)?;

        // Deserialize the NodeMessage using bincode for binary deserialization
        let node_message: NodeMessage = bincode::deserialize(&decrypted_bytes)
            .map_err(|e| KeyError::SerializationError(e.to_string()))?;

        Ok(node_message)
    }

    /// Process an encrypted envelope containing a NodeMessage from mobile
    ///
    /// This method decrypts the envelope, extracts the NodeMessage (containing certificate and CA public key),
    /// Validates the certificate using the provided CA public key, and stores it if valid.
    pub fn process_mobile_message(&mut self, envelope: &Envelope) -> Result<()> {
        // Try to decrypt as a NodeMessage first (preferred approach)
        let node_message = self.decrypt_node_message(envelope)?;

        // Extract certificate and CA public key from the NodeMessage
        let certificate = node_message.certificate;
        let ca_public_key = node_message.ca_public_key;

        // Create a VerifyingKey from the CA public key for validation
        // Convert Vec<u8> to [u8; 32] for ed25519_dalek::VerifyingKey::from_bytes
        let ca_public_key_array: [u8; 32] = ca_public_key
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::CryptoError("Invalid CA public key length".to_string()))?;

        // Create the verifying key directly from the bytes
        let ca_verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&ca_public_key_array)
            .map_err(|e| KeyError::CryptoError(e.to_string()))?;

        // Validate the certificate using the provided CA public key
        certificate.validate(&ca_verifying_key)?;

        // Store the certificate directly in the key manager
        // We've already validated it with the CA public key, so we can just store it
        self.key_manager.store_validated_certificate(certificate)?;

        Ok(())
    }

    /// Process a network keys message from a mobile device
    ///
    /// This decrypts the envelope containing the network keys and stores them securely
    pub fn process_network_keys_message(&mut self, envelope: &Envelope) -> Result<()> {
        // Get the node's encryption key for decryption
        let node_encryption_key = self
            .key_manager
            .get_encryption_key("node_encryption")
            .ok_or_else(|| KeyError::KeyNotFound("Node encryption key not found".to_string()))?;

        // Decrypt the envelope to get the network key message
        let decrypted_bytes = envelope.decrypt(node_encryption_key)?;

        // Deserialize the network key message
        let network_key_message: NetworkKeyMessage = bincode::deserialize(&decrypted_bytes)
            .map_err(|e| KeyError::SerializationError(e.to_string()))?;

        // Store the network private key
        let network_private_key = network_key_message.private_key.clone();

        // Also store the network key as an encryption key for future use
        let _network_encryption_key_id = format!(
            "network_encryption_{}",
            hex::encode(&network_key_message.public_key)
        );
        // Create an encryption key pair from the network key (if needed)
        // This is commented out for now as we're using the existing store_network_key method
        // let encryption_key_pair = EncryptionKeyPair::from_bytes(&network_private_key)?;
        // self.key_manager.add_encryption_key(&network_encryption_key_id, encryption_key_pair);

        // Store the network key using the existing method
        self.store_network_key(&network_key_message.public_key, network_private_key)?;

        // Store the network name
        // For now, we'll just log it (implementation depends on requirements)
        println!(
            "Received network name: {}",
            network_key_message.network_name
        );

        Ok(())
    }

    /// Export the node key manager state for persistence
    pub fn export_state(&self) -> NodeKeyManagerData {
        NodeKeyManagerData {
            key_manager_data: self.key_manager.export_keys(),
        }
    }

    /// Import the node key manager state from persistence
    pub fn import_state(&mut self, data: NodeKeyManagerData) {
        self.key_manager.import_keys(data.key_manager_data);
    }

    /// Store a network key
    pub fn store_network_key(
        &mut self,
        network_public_key: &[u8],
        network_private_key: Vec<u8>,
    ) -> Result<()> {
        let key_id = format!("network_data_{}", hex::encode(network_public_key));
        let mut private_key_array = [0u8; 32];
        if network_private_key.len() == 32 {
            private_key_array.copy_from_slice(&network_private_key);

            let network_key_pair = EncryptionKeyPair::from_secret(&private_key_array);

            self.key_manager
                .add_encryption_key(&key_id, network_key_pair);

            Ok(())
        } else {
            Err(KeyError::KeyNotFound(
                "Network private key is not 32 bytes long".to_string(),
            ))
        }
    }

    /// Decrypt data using the network key
    pub fn decrypt_with_network_key(
        &self,
        network_public_key: &[u8],
        envelope: &Envelope,
    ) -> Result<Vec<u8>> {
        let network_key_id = format!("network_data_{}", hex::encode(network_public_key));
        let network_encryption_key = self
            .key_manager
            .get_encryption_key(&network_key_id)
            .ok_or_else(|| {
                KeyError::KeyNotFound(format!("Network key not found: {}", network_key_id))
            })?;

        // The recipient ID must match exactly what was used in encrypt_for_network_and_profile
        envelope.decrypt(network_encryption_key)
    }

    /// Get the underlying key manager
    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }

    /// Get the underlying key manager mutably
    pub fn key_manager_mut(&mut self) -> &mut KeyManager {
        &mut self.key_manager
    }

    /// Get the node's certificate
    pub fn get_node_certificate(&self) -> Result<&Certificate> {
        let node_pk_str = hex::encode(self.node_public_key());
        let subject = format!("node:{}", node_pk_str);
        self.key_manager
            .get_certificate(&subject)
            .ok_or_else(|| KeyError::KeyNotFound("Node certificate not found".to_string()))
    }

    /// Encrypt data using the node's symmetric storage key.
    pub fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.key_manager
            .encrypt_with_symmetric_key("node_storage", data)
    }

    /// Decrypt data using the node's symmetric storage key.
    pub fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        self.key_manager
            .decrypt_with_symmetric_key("node_storage", encrypted_data)
    }
}
