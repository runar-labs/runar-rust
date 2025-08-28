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
    pub network_public_key: Option<Vec<u8>>, // ← PRE-RESOLVED NETWORK PUBLIC KEY
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
    /// Concurrent mapping used heavily on read path
    mapping: dashmap::DashMap<String, LabelKeyInfo>,
}

impl ConfigurableLabelResolver {
    pub fn new(config: KeyMappingConfig) -> Self {
        let dm = dashmap::DashMap::new();
        for (k, v) in config.label_mappings {
            dm.insert(k, v);
        }
        Self { mapping: dm }
    }

    pub fn from_map(map: std::collections::HashMap<String, LabelKeyInfo>) -> Self {
        let dm = dashmap::DashMap::new();
        for (k, v) in map {
            dm.insert(k, v);
        }
        Self { mapping: dm }
    }
}

impl LabelResolver for ConfigurableLabelResolver {
    fn resolve_label_info(&self, label: &str) -> Result<Option<LabelKeyInfo>> {
        Ok(self.mapping.get(label).map(|v| v.clone()))
    }

    fn available_labels(&self) -> Vec<String> {
        self.mapping.iter().map(|kv| kv.key().clone()).collect()
    }

    fn can_resolve(&self, label: &str) -> bool {
        self.mapping.contains_key(label)
    }

    fn clone_box(&self) -> Box<dyn LabelResolver> {
        let dm = dashmap::DashMap::new();
        for e in self.mapping.iter() {
            dm.insert(e.key().clone(), e.value().clone());
        }
        Box::new(ConfigurableLabelResolver { mapping: dm })
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
    pub network_public_key: Vec<u8>, // ← PRE-RESOLVED PUBLIC KEY
    pub profile_public_keys: Vec<Vec<u8>>, // ← MULTIPLE PROFILE KEYS
}
