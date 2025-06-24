use serde::{Serialize, Deserialize};
use crate::crypto::EncryptionKeyPair;


/// Represents a network configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NetworkConfig {
    /// Network identifier
    pub network_id: String,
    /// Network name
    pub name: String,
    /// Network description
    pub description: String,
}

/// Network data key
pub struct NetworkDataKey {
    /// Network identifier
    pub network_id: String,
    /// Network data encryption key pair
    pub key_pair: EncryptionKeyPair,
}

impl NetworkDataKey {
    /// Create a new network data key
    pub fn new(network_id: &str, key_pair: EncryptionKeyPair) -> Self {
        Self {
            network_id: network_id.to_string(),
            key_pair,
        }
    }

    /// Get the network ID
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Get the key pair
    pub fn key_pair(&self) -> &EncryptionKeyPair {
        &self.key_pair
    }
}

/// Network membership certificate
pub struct NetworkMembership {
    /// Network identifier
    pub network_id: String,
    /// Node identifier
    pub node_id: String,
    /// Membership status
    pub is_active: bool,
}

impl NetworkMembership {
    /// Create a new network membership
    pub fn new(network_id: &str, node_id: &str) -> Self {
        Self {
            network_id: network_id.to_string(),
            node_id: node_id.to_string(),
            is_active: true,
        }
    }

    /// Revoke the membership
    pub fn revoke(&mut self) {
        self.is_active = false;
    }

    /// Check if the membership is active
    pub fn is_active(&self) -> bool {
        self.is_active
    }
}
