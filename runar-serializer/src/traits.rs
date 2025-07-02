use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Re-export common keystore traits & structs from runar-keys so downstream
// code can simply `use runar_serializer::traits::*;`.
pub use runar_keys::keystore::{EncryptedEnvelope, EncryptedKey, KeyStore};

/// Label-to-PublicKey mapping configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyMappingConfig {
    /// Maps abstract labels to actual public key identifiers
    pub label_mappings: HashMap<String, Vec<u8>>, // label -> public_key_bytes
}

/// Label resolver interface for mapping labels to public keys
pub trait LabelResolver: Send + Sync {
    /// Resolve a label to public key bytes
    fn resolve_label(&self, label: &str) -> Result<Option<Vec<u8>>>;

    /// Get available labels in current context
    fn available_labels(&self) -> Vec<String>;

    /// Check if a label can be resolved
    fn can_resolve(&self, label: &str) -> bool;
}

/// Configurable label resolver implementation
pub struct ConfigurableLabelResolver {
    /// The mapping configuration
    config: KeyMappingConfig,
}

impl ConfigurableLabelResolver {
    pub fn new(config: KeyMappingConfig) -> Self {
        Self { config }
    }
}

impl LabelResolver for ConfigurableLabelResolver {
    fn resolve_label(&self, label: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.config.label_mappings.get(label).cloned())
    }

    fn available_labels(&self) -> Vec<String> {
        self.config.label_mappings.keys().cloned().collect()
    }

    fn can_resolve(&self, label: &str) -> bool {
        self.config.label_mappings.contains_key(label)
    }
}

/// Marker trait for detecting encryption capability at runtime
pub trait RunarEncryptable {}

/// Trait for encrypting structs with selective field encryption
pub trait RunarEncrypt: RunarEncryptable {
    type Encrypted: RunarDecrypt<Decrypted = Self>;

    fn encrypt_with_keystore(
        &self,
        keystore: &dyn KeyStore,
        resolver: &dyn LabelResolver,
    ) -> Result<Self::Encrypted>;
}

/// Trait for decrypting encrypted structs
pub trait RunarDecrypt {
    type Decrypted: RunarEncrypt<Encrypted = Self>;

    fn decrypt_with_keystore(&self, keystore: &dyn KeyStore) -> Result<Self::Decrypted>;
}
