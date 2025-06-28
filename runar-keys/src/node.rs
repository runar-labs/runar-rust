use hex;

use crate::crypto::{
    Certificate, EncryptionKeyPair, NetworkKeyMessage, NodeMessage, SigningKeyPair,
};
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
#[derive(Debug)]
pub struct NodeKeyManager {
    /// The underlying key manager
    key_manager: KeyManager,
    /// Node identifier
    node_public_key: Vec<u8>,
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

        // Generate a key pair for the node (certificate will be added later via CSR)
        let keypair = SigningKeyPair::new();
        let node_public_key = keypair.public_key().to_vec();

        // Store the key pair
        key_manager.add_signing_key("node_tls", keypair);

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

    pub fn new_with_state(state: NodeKeyManagerData) -> Self {
        let key_manager = KeyManager::new_with_state(state.key_manager_data);
        let node_public_key = key_manager
            .get_node_public_key()
            .expect("Failed to get node Public key");
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

        Ok(encryption_key.public_key_bytes().to_vec())
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
        let tls_key_id = "node_tls".to_string();
        let tls_csr = self.key_manager.create_csr(&subject, &tls_key_id)?;

        // Get the node encryption public key - it must exist at this point
        let encryption_key = self
            .key_manager
            .get_encryption_key("node_encryption")
            .ok_or_else(|| KeyError::KeyNotFound("Node encryption key not found".to_string()))?;

        let node_encryption_public_key = encryption_key.public_key_bytes().to_vec();

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

        // Store the User CA public key for future certificate chain operations
        let ca_key_pair = SigningKeyPair::from_public_key(&ca_public_key_array)?;
        self.key_manager.add_signing_key("user_ca", ca_key_pair);

        // Update the certificate subject and issuer to match our expected format
        let mut cert = certificate;
        cert.subject = format!("node:{}", hex::encode(&self.node_public_key));
        cert.issuer = format!("ca:{}", hex::encode(&ca_public_key));

        // Store the certificate - store_validated_certificate will handle the QUIC key mapping
        self.key_manager.store_validated_certificate(cert)?;

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

        // Store the network name with the network key for future reference
        let network_metadata_key = format!(
            "network_metadata_{}",
            hex::encode(&network_key_message.public_key)
        );

        // Store network metadata in the key manager using proper encrypted storage
        self.key_manager_mut()
            .store_network_metadata(&network_metadata_key, &network_key_message.network_name)?;

        Ok(())
    }

    /// Export the node key manager state for persistence
    pub fn export_state(&self) -> NodeKeyManagerData {
        NodeKeyManagerData {
            key_manager_data: self.key_manager.export_keys(),
        }
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

    /// Get the underlying key manager mutably
    pub fn key_manager_mut(&mut self) -> &mut KeyManager {
        &mut self.key_manager
    }

    /// Get the node's certificate
    pub fn get_node_certificate(&self) -> Result<&Certificate> {
        self.key_manager
            .get_certificate("node_tls_cert")
            .ok_or_else(|| KeyError::KeyNotFound("Node certificate not found".to_string()))
    }

    /// Get QUIC-compatible certificates, private key, and verifier for this node
    pub fn get_quic_certs(
        &self,
    ) -> Result<(
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls_pki_types::PrivateKeyDer<'static>,
        std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier>,
    )> {
        self.key_manager.get_quic_certs()
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

    /// Ensure a symmetric key exists and return it (create one if it doesn't exist)
    pub fn ensure_symetric_key(&mut self, key_name: &str) -> Result<Vec<u8>> {
        let key = self.key_manager.ensure_symmetric_key(key_name)?;
        Ok(key.to_bytes())
    }

    pub fn save_credentials(&self) -> Result<()> {
        let state = self.export_state();
        let serialized_state = bincode::serialize(&state)?;
        let serialized_state_hex = hex::encode(serialized_state);
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USERNAME)?;
        entry.set_password(&serialized_state_hex)?;
        Ok(())
    }

    pub fn load_credentials() -> Result<NodeKeyManager> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USERNAME)?;
        let serialized_state_hex = entry.get_password()?;
        let serialized_state = hex::decode(serialized_state_hex)?;
        let state: NodeKeyManagerData = bincode::deserialize(&serialized_state)?;
        let manager = NodeKeyManager::new_with_state(state);
        Ok(manager)
    }
}

const KEYRING_SERVICE: &str = "runar_node";
const KEYRING_USERNAME: &str = "credentials";

#[cfg(test)]
mod credentials_tests {
    use super::*;
    use keyring::Entry;
    use std::sync::Mutex;

    // A mutex to ensure that tests that interact with the system keyring run serially.
    static KEYRING_MUTEX: Mutex<()> = Mutex::new(());

    fn delete_test_credentials() -> Result<()> {
        let entry = Entry::new(KEYRING_SERVICE, KEYRING_USERNAME)?;
        match entry.delete_password() {
            Ok(_) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // It's ok if it's already gone
            Err(e) => Err(KeyError::KeyringError(format!(
                "Failed to delete test credentials: {}",
                e
            ))),
        }
    }

    #[test]
    fn test_save_and_load_credentials() {
        let _guard = KEYRING_MUTEX.lock().unwrap();

        // Setup: Create a new manager
        let original_manager = NodeKeyManager::new();
        let original_pub_key = original_manager.node_public_key().to_vec();

        // Action: Save the credentials
        original_manager
            .save_credentials()
            .expect("Failed to save credentials");

        // Action: Load the credentials
        let loaded_manager =
            NodeKeyManager::load_credentials().expect("Failed to load credentials");

        // Assert: The loaded manager should have the same public key
        assert_eq!(
            original_pub_key.as_slice(),
            loaded_manager.node_public_key()
        );

        // Cleanup
        delete_test_credentials().expect("Failed to delete test credentials");
    }

    #[test]
    fn test_load_credentials_not_found() {
        let _guard = KEYRING_MUTEX.lock().unwrap();

        // Setup: Ensure no credentials exist
        delete_test_credentials().expect("Failed to delete test credentials before test");

        // Action: Attempt to load credentials
        let result = NodeKeyManager::load_credentials();

        // Assert: The result should be an error indicating no entry
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert!(matches!(error, KeyError::KeyNotFound(_)));
        assert!(error.to_string().contains("No credentials found"));
    }
}
