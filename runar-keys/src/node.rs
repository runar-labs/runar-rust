use crate::crypto::{Certificate, EncryptionKeyPair};
use crate::envelope::Envelope;
use crate::error::{KeyError, Result};
use crate::manager::KeyManager;
use serde::{Deserialize, Serialize};

/// Represents a setup token for node initialization
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SetupToken {
    pub token_id: String,
    /// Node identifier
    pub node_public_key: Vec<u8>,
    /// TLS certificate signing request
    pub tls_csr: Vec<u8>,
    //ttl
    pub ttl: u64,
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

impl NodeKeyManager {
    /// Create a new node key manager
    pub fn new() -> Self {
        let mut key_manager = KeyManager::new();
        let node_public_key = key_manager
            .generate_node_tls_key()
            .expect("Failed to generate node TLS key");
        Self {
            key_manager: key_manager,
            node_public_key: node_public_key,

        }
    }

    pub fn new_with_key_manager(mut key_manager: KeyManager) -> Self {
        let node_public_key = key_manager
            .generate_node_tls_key()
            .expect("Failed to generate node TLS key");
        Self {
            key_manager: key_manager,
            node_public_key: node_public_key,

        }
    }

    /// Get the node ID
    pub fn node_public_key(&self) -> &Vec<u8> {
        &self.node_public_key
    }

    /// Generate node TLS and storage keys and create a setup token
    pub fn generate_setup_token(&mut self) -> Result<SetupToken> {
        // Generate TLS key
        let tls_key_public_key = self.key_manager.generate_node_tls_key()?;
        let node_pk_str = hex::encode(&tls_key_public_key);
        let tls_key_id = format!("node_tls_{}", node_pk_str);

        // Create CSR for TLS key
        let subject = format!("node:{}", node_pk_str);
        let tls_csr = self.key_manager.create_csr(&subject, &tls_key_id)?;

        let _storage_key = self
            .key_manager
            .generate_node_storage_key(&tls_key_public_key)?;

        //generate random UUID
        let token_id = uuid::Uuid::new_v4();

        // Create setup token
        let token = SetupToken {
            token_id: token_id.to_string(),
            node_public_key: tls_key_public_key,
            tls_csr,
            ttl: 120, //120 seconds
        };

        //store token to be used for TTL validation when receivig the token again

        Ok(token)
    }

    /// Process a signed certificate from mobile
    pub fn process_signed_certificate(&mut self, certificate: Certificate) -> Result<()> {
        // Store the certificate
        self.key_manager.add_certificate(certificate);

        Ok(())
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
            Err(KeyError::KeyNotFound(format!(
                "Network private key is not 32 bytes long"
            )))
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
}
