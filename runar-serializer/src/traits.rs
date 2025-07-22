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
// #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
// pub enum KeyScope {
//     /// Encrypt with the network key so all nodes in the network can decrypt.
//     Network,
//     /// Encrypt with one or more user-profile keys so only specific profiles can decrypt.
//     Profile,
// }
/// Information required to perform envelope encryption for a label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelKeyInfo {
    pub profile_public_keys: Vec<Vec<u8>>,
    pub network_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Label-to-PublicKey mapping utilities
// ---------------------------------------------------------------------------

/// Label-to-PublicKey mapping configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyMappingConfig {
    /// Maps labels to public-key information.
    pub label_mappings: HashMap<String, LabelKeyInfo>,
}

/// Label resolver interface for mapping labels to public keys
pub trait LabelResolver: Send + Sync {
    /// Resolve a label to key-info (public key + scope).
    fn resolve_label_info(&self, label: &str) -> Result<Option<LabelKeyInfo>>;

    /// Get available labels in current context
    fn available_labels(&self) -> Vec<String>;

    /// Check if a label can be resolved
    fn can_resolve(&self, label: &str) -> bool;

    /// Clone this trait object
    fn clone_box(&self) -> Box<dyn LabelResolver>;
}

// Implement LabelResolver for Box<dyn LabelResolver> to allow cloning
impl LabelResolver for Box<dyn LabelResolver> {
    fn resolve_label_info(&self, label: &str) -> Result<Option<LabelKeyInfo>> {
        self.as_ref().resolve_label_info(label)
    }

    fn available_labels(&self) -> Vec<String> {
        self.as_ref().available_labels()
    }

    fn can_resolve(&self, label: &str) -> bool {
        self.as_ref().can_resolve(label)
    }

    fn clone_box(&self) -> Box<dyn LabelResolver> {
        self.as_ref().clone_box()
    }
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

    fn clone_box(&self) -> Box<dyn LabelResolver> {
        Box::new(ConfigurableLabelResolver {
            config: self.config.clone(),
        })
    }
}

/// Marker trait for detecting encryption capability at runtime
pub trait RunarEncryptable {}

/// Trait for encrypting structs with selective field encryption
pub trait RunarEncrypt: RunarEncryptable {
    type Encrypted: RunarDecrypt<Decrypted = Self> + Serialize;

    fn encrypt_with_keystore(
        &self,
        keystore: &Arc<KeyStore>,
        resolver: &dyn LabelResolver,
    ) -> Result<Self::Encrypted>;
}

/// Trait for decrypting encrypted structs
pub trait RunarDecrypt {
    type Decrypted: RunarEncrypt<Encrypted = Self>;

    fn decrypt_with_keystore(&self, keystore: &Arc<KeyStore>) -> Result<Self::Decrypted>;
}

// (identity RunarEncrypt/RunarDecrypt impls for primitives are no longer
// required – primitives never hit the decrypt registry path because they
// succeed in the direct `serde_cbor` deserialisation fast-path.)
// ---------------------------------------------------------------------------
// Serialization Context for consolidated parameters
// ---------------------------------------------------------------------------

/// Consolidated context for serialization operations containing all encryption-related parameters
#[derive(Clone)]
pub struct SerializationContext {
    pub keystore: Arc<KeyStore>,
    pub resolver: Arc<dyn LabelResolver>,
    pub network_id: String,
    pub profile_id: String,
}

impl SerializationContext {
    /// Create a new serialization context
    pub fn new(
        keystore: Arc<KeyStore>,
        resolver: Arc<dyn LabelResolver>,
        network_id: String,
        profile_id: String,
    ) -> Self {
        Self {
            keystore,
            resolver,
            network_id,
            profile_id,
        }
    }
}
