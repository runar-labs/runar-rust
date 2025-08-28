use anyhow::{anyhow, Result};
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

/// Configuration for label resolver system labels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelResolverConfig {
    /// Static label mappings for system labels
    /// These are config-driven and known at startup
    /// Supports both direct network public keys and dynamic keywords
    pub label_mappings: HashMap<String, LabelValue>,
}

/// Value specification for a label
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelValue {
    /// Optional network public key for this label
    /// If None, will use empty key for user-only labels
    pub network_public_key: Option<Vec<u8>>,
    /// Optional user key specification for this label
    pub user_key_spec: Option<LabelKeyword>,
}

/// Keywords for dynamic label resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LabelKeyword {
    /// Maps to current user's profile public keys from request context
    CurrentUser,
    /// Reserved for future custom resolution functions
    Custom(String), // Function name for custom resolution
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

    /// Creates a label resolver for a specific context
    /// REQUIRES: Every label must have an explicit network_public_key - no defaults allowed
    pub fn create_context_label_resolver(
        system_config: &LabelResolverConfig,
        user_profile_keys: &Vec<Vec<u8>>, // From request context - empty vec means no profile keys
    ) -> Result<Arc<dyn LabelResolver>> {
        let mut mappings = HashMap::new();

        // Process system label mappings
        for (label, label_value) in &system_config.label_mappings {
            let mut profile_public_keys = Vec::new();

            // Get network key if specified, or use empty for user-only labels
            let network_public_key = label_value.network_public_key.clone()
                .unwrap_or_else(|| vec![]); // Empty key for user-only labels

            // Process user key specification
            match &label_value.user_key_spec {
                Some(LabelKeyword::CurrentUser) => {
                    // Always extend with user profile keys (empty vec is fine)
                    profile_public_keys.extend_from_slice(user_profile_keys);
                },
                Some(LabelKeyword::Custom(_custom_name)) => {
                    // Future: Call custom resolution function
                    // For now, profile_public_keys remains empty
                    // Custom resolver would populate profile_public_keys here
                },
                None => {
                    // No user keys - profile_public_keys remains empty
                },
            }

            // Validation: Label must have either network key OR user keys OR both
            // Empty network key + empty profile keys = invalid label
            if network_public_key.is_empty() && profile_public_keys.is_empty() {
                return Err(anyhow::anyhow!("Label '{}' must specify either network_public_key or user_key_spec (or both)", label));
            }

            mappings.insert(label.clone(), LabelKeyInfo {
                network_public_key: Some(network_public_key),
                profile_public_keys,
            });
        }

        Ok(Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
            label_mappings: mappings,
        })))
    }

    /// Validate label resolver configuration
    pub fn validate_label_config(config: &LabelResolverConfig) -> Result<()> {
        // Ensure config has required label mappings
        if config.label_mappings.is_empty() {
            return Err(anyhow::anyhow!("LabelResolverConfig must contain at least one label mapping"));
        }

        // Validate each label mapping
        for (label, label_value) in &config.label_mappings {
            // Check that label has either network key OR user key spec OR both
            let has_network_key = label_value.network_public_key.is_some();
            let has_user_spec = label_value.user_key_spec.is_some();

            if !has_network_key && !has_user_spec {
                return Err(anyhow::anyhow!("Label '{}' must specify either network_public_key or user_key_spec (or both)", label));
            }

            // If network key is provided, validate it's not empty
            if let Some(network_key) = &label_value.network_public_key {
                if network_key.is_empty() {
                    return Err(anyhow::anyhow!("Label '{}' has empty network_public_key - use None for user-only labels", label));
                }
            }

            // Validate user key spec if provided
            if let Some(user_spec) = &label_value.user_key_spec {
                match user_spec {
                    LabelKeyword::CurrentUser => {
                        // CurrentUser is always valid
                    },
                    LabelKeyword::Custom(resolver_name) => {
                        if resolver_name.is_empty() {
                            return Err(anyhow::anyhow!("Label '{}' has empty custom resolver name", label));
                        }
                        // Future: Could validate that custom resolver exists
                    }
                }
            }
        }

        Ok(())
    }
}

/// Creates a label resolver for a specific context
/// REQUIRES: Every label must have an explicit network_public_key - no defaults allowed
pub fn create_context_label_resolver(
    system_config: &LabelResolverConfig,
    user_profile_keys: &Vec<Vec<u8>>, // From request context - empty vec means no profile keys
) -> Result<Arc<dyn LabelResolver>> {
    ConfigurableLabelResolver::create_context_label_resolver(system_config, user_profile_keys)
}

impl ConfigurableLabelResolver {
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
