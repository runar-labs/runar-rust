use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Re-exports from runar-keys for envelope encryption integration
// ---------------------------------------------------------------------------
pub use runar_keys::mobile::EnvelopeEncryptedData;
pub use runar_keys::EnvelopeCrypto;

// Trait-object alias so existing code that expects `&dyn KeyStore` continues to
// compile while delegating to the real `EnvelopeCrypto` implementation.
// This avoids another custom abstraction layer.
pub type KeyStore = dyn EnvelopeCrypto;

// ---------------------------------------------------------------------------
// Key-scope modelling
// ---------------------------------------------------------------------------

/// Determines how an envelope key should be encrypted for a given label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyScope {
    /// Encrypt with the network key so all nodes in the network can decrypt.
    Network,
    /// Encrypt with one or more user-profile keys so only specific profiles can decrypt.
    Profile,
}

/// Information required to perform envelope encryption for a label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelKeyInfo {
    /// The public key bytes used for envelope key encryption.
    pub public_key: Vec<u8>,
    /// The key-encryption scope.
    pub scope: KeyScope,
}

// ---------------------------------------------------------------------------
// Label-to-PublicKey mapping utilities
// ---------------------------------------------------------------------------

/// Label-to-PublicKey mapping configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyMappingConfig {
    /// Maps labels to public-key & scope information.
    pub label_mappings: HashMap<String, LabelKeyInfo>,
}

/// Label resolver interface for mapping labels to public keys
pub trait LabelResolver: Send + Sync {
    /// Resolve a label to key-info (public key + scope).
    fn resolve_label_info(&self, label: &str) -> Result<Option<LabelKeyInfo>>;

    /// Legacy helper: resolve just the public key bytes.
    fn resolve_label(&self, label: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.resolve_label_info(label)?.map(|info| info.public_key))
    }

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
    fn resolve_label_info(&self, label: &str) -> Result<Option<LabelKeyInfo>> {
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
        keystore: &KeyStore,
        resolver: &dyn LabelResolver,
    ) -> Result<Self::Encrypted>;
}

/// Trait for decrypting encrypted structs
pub trait RunarDecrypt {
    type Decrypted: RunarEncrypt<Encrypted = Self>;

    fn decrypt_with_keystore(&self, keystore: &KeyStore) -> Result<Self::Decrypted>;
}

pub trait CustomFromBytes: Sized + 'static + Clone + Debug + Send + Sync {
    fn from_plain_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self>
    where
        Self: Sized;
    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self>;
    fn to_binary(
        &self,
        keystore: Option<&Arc<KeyStore>>,
        resolver: Option<&dyn LabelResolver>,
    ) -> Result<Vec<u8>>;
}
