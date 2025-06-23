use crate::crypto::{SigningKeyPair, EncryptionKeyPair, Certificate};
use crate::manager::KeyManager;
use crate::envelope::Envelope;
use crate::error::{KeyError, Result};
use serde::{Serialize, Deserialize};

/// Represents a setup token for node initialization
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SetupToken {
    /// Node identifier
    pub node_id: String,
    /// TLS certificate signing request
    pub tls_csr: Vec<u8>,
    /// Storage key public key
    pub storage_public_key: Vec<u8>,
}

/// Node key manager
pub struct NodeKeyManager {
    /// The underlying key manager
    key_manager: KeyManager,
    /// Node identifier
    node_id: String,
    /// Network identifier (if part of a network)
    network_id: Option<String>,
}

impl NodeKeyManager {
    /// Create a new node key manager
    pub fn new(node_id: &str) -> Self {
        Self {
            key_manager: KeyManager::new(),
            node_id: node_id.to_string(),
            network_id: None,
        }
    }

    /// Get the node ID
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Set the network ID
    pub fn set_network_id(&mut self, network_id: &str) {
        self.network_id = Some(network_id.to_string());
    }

    /// Get the network ID
    pub fn network_id(&self) -> Option<&str> {
        self.network_id.as_deref()
    }

    /// Generate node TLS and storage keys and create a setup token
    pub fn generate_setup_token(&mut self) -> Result<SetupToken> {
        // Generate TLS key
        let tls_key_id = format!("node_tls_{}", self.node_id);
        let _tls_key = self.key_manager.generate_node_tls_key(&self.node_id)?;
        
        // Generate storage key
        let _storage_key_id = format!("node_storage_{}", self.node_id);
        
        // Create CSR for TLS key
        let subject = format!("node:{}", self.node_id);
        let tls_csr = self.key_manager.create_csr(&subject, &tls_key_id)?;
        
        // Generate storage key after CSR creation to avoid borrow conflict
        let storage_key = self.key_manager.generate_node_storage_key(&self.node_id)?;
        
        // Create setup token
        let token = SetupToken {
            node_id: self.node_id.clone(),
            tls_csr,
            storage_public_key: storage_key.public_key_bytes().to_vec(),
        };
        
        Ok(token)
    }

    /// Process a signed certificate from mobile
    pub fn process_signed_certificate(&mut self, certificate: Certificate) -> Result<()> {
        // Store the certificate
        self.key_manager.add_certificate(certificate);
        
        Ok(())
    }

    /// Store a network key
    pub fn store_network_key(&mut self, network_id: &str, network_key: EncryptionKeyPair) -> Result<()> {
        let key_id = format!("network_data_{}", network_id);
        self.key_manager.add_encryption_key(&key_id, network_key);
        self.network_id = Some(network_id.to_string());
        
        Ok(())
    }

    /// Decrypt data using the network key
    pub fn decrypt_with_network_key(&self, envelope: &Envelope) -> Result<Vec<u8>> {
        let network_id = self.network_id.as_ref().ok_or_else(|| {
            KeyError::InvalidOperation("Node is not part of a network".to_string())
        })?;
        
        let key_id = format!("network_data_{}", network_id);
        let network_key = self.key_manager.get_encryption_key(&key_id)
            .ok_or_else(|| KeyError::KeyNotFound(format!("Network key not found: {}", key_id)))?;
        
        // The recipient ID must match exactly what was used in encrypt_for_network_and_profile
        envelope.decrypt(network_id, network_key)
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
