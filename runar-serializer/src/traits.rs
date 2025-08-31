use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use std::time::{Duration, Instant};

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

// /// Simple trait for LabelResolver to maintain macro compatibility
// /// This delegates to the concrete LabelResolver struct
// pub trait LabelResolver: Send + Sync {
//     /// Resolve a label to key-info (public key + scope).
//     fn resolve_label_info(&self, label: &str) -> Result<Option<LabelKeyInfo>>;

//     /// Get available labels in current context
//     fn available_labels(&self) -> Vec<String>;

//     /// Check if a label can be resolved
//     fn can_resolve(&self, label: &str) -> bool;
// }

// impl LabelResolver for LabelResolver {
//     fn resolve_label_info(&self, label: &str) -> Result<Option<LabelKeyInfo>> {
//         self.resolve_label_info(label)
//     }

//     fn available_labels(&self) -> Vec<String> {
//         self.available_labels()
//     }

//     fn can_resolve(&self, label: &str) -> bool {
//         self.can_resolve(label)
//     }
// }

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

/// Label resolver implementation
pub struct LabelResolver {
    /// Concurrent mapping used heavily on read path
    mapping: DashMap<String, LabelKeyInfo>,
}

impl LabelResolver {
    pub fn new(config: KeyMappingConfig) -> Self {
        let dm = DashMap::new();
        for (k, v) in config.label_mappings {
            dm.insert(k, v);
        }
        Self { mapping: dm }
    }

    /// Resolve a label to key-info (public key + scope).
    pub fn resolve_label_info(&self, label: &str) -> Result<Option<LabelKeyInfo>> {
        Ok(self.mapping.get(label).map(|v| v.clone()))
    }

    /// Get available labels in current context
    pub fn available_labels(&self) -> Vec<String> {
        self.mapping.iter().map(|kv| kv.key().clone()).collect()
    }

    /// Check if a label can be resolved
    pub fn can_resolve(&self, label: &str) -> bool {
        self.mapping.contains_key(label)
    }

    /// Creates a label resolver for a specific context
    /// REQUIRES: Every label must have an explicit network_public_key - no defaults allowed
    pub fn create_context_label_resolver(
        system_config: &LabelResolverConfig,
        user_profile_keys: &[Vec<u8>], // From request context - empty vec means no profile keys
    ) -> Result<Arc<LabelResolver>> {
        let mut mappings = HashMap::new();

        // Process system label mappings
        for (label, label_value) in &system_config.label_mappings {
            let mut profile_public_keys = Vec::new();

            // Get network key if specified, or use empty for user-only labels
            let network_public_key = label_value
                .network_public_key
                .clone()
                .unwrap_or_else(Vec::new); // Empty key for user-only labels

            // Process user key specification
            match &label_value.user_key_spec {
                Some(LabelKeyword::CurrentUser) => {
                    // Always extend with user profile keys (empty vec is fine)
                    profile_public_keys.extend_from_slice(user_profile_keys);
                }
                Some(LabelKeyword::Custom(_custom_name)) => {
                    // Future: Call custom resolution function
                    // For now, profile_public_keys remains empty
                    // Custom resolver would populate profile_public_keys here
                }
                None => {
                    // No user keys - profile_public_keys remains empty
                }
            }

            // Validation: Label must have either network key OR user keys OR both
            // Empty network key + empty profile keys = invalid label
            if network_public_key.is_empty() && profile_public_keys.is_empty() {
                return Err(anyhow::anyhow!(
                    "Label '{}' must specify either network_public_key or user_key_spec (or both)",
                    label
                ));
            }

            mappings.insert(
                label.clone(),
                LabelKeyInfo {
                    network_public_key: Some(network_public_key),
                    profile_public_keys,
                },
            );
        }

        Ok(Arc::new(LabelResolver::new(KeyMappingConfig {
            label_mappings: mappings,
        })))
    }

    /// Validate label resolver configuration
    pub fn validate_label_config(config: &LabelResolverConfig) -> Result<()> {
        // Ensure config has required label mappings
        if config.label_mappings.is_empty() {
            return Err(anyhow::anyhow!(
                "LabelResolverConfig must contain at least one label mapping"
            ));
        }

        // Validate each label mapping
        for (label, label_value) in &config.label_mappings {
            // Check that label has either network key OR user key spec OR both
            let has_network_key = label_value.network_public_key.is_some();
            let has_user_spec = label_value.user_key_spec.is_some();

            if !has_network_key && !has_user_spec {
                return Err(anyhow::anyhow!(
                    "Label '{}' must specify either network_public_key or user_key_spec (or both)",
                    label
                ));
            }

            // If network key is provided, validate it's not empty
            if let Some(network_key) = &label_value.network_public_key {
                if network_key.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Label '{}' has empty network_public_key - use None for user-only labels",
                        label
                    ));
                }
            }

            // Validate user key spec if provided
            if let Some(user_spec) = &label_value.user_key_spec {
                match user_spec {
                    LabelKeyword::CurrentUser => {
                        // CurrentUser is always valid
                    }
                    LabelKeyword::Custom(resolver_name) => {
                        if resolver_name.is_empty() {
                            return Err(anyhow::anyhow!(
                                "Label '{}' has empty custom resolver name",
                                label
                            ));
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
    user_profile_keys: &[Vec<u8>], // From request context - empty vec means no profile keys
) -> Result<Arc<LabelResolver>> {
    LabelResolver::create_context_label_resolver(system_config, user_profile_keys)
}

/// Marker trait for detecting encryption capability at runtime
pub trait RunarEncryptable {}

/// Trait for encrypting structs with selective field encryption
pub trait RunarEncrypt: RunarEncryptable {
    type Encrypted: RunarDecrypt<Decrypted = Self> + Serialize;

    fn encrypt_with_keystore(
        &self,
        keystore: &Arc<KeyStore>,
        resolver: &LabelResolver,
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
    pub resolver: Arc<LabelResolver>,
    pub network_public_key: Vec<u8>, // ← PRE-RESOLVED PUBLIC KEY
    pub profile_public_keys: Vec<Vec<u8>>, // ← MULTIPLE PROFILE KEYS
}

// ---------------------------------------------------------------------------
// Resolver Cache Implementation - Simplified Design
// ---------------------------------------------------------------------------

/// Cache entry for a label resolver with metadata
struct CacheEntry {
    resolver: Arc<LabelResolver>,
    created_at: Instant,
    last_accessed: AtomicU64, // Unix timestamp
}

impl CacheEntry {
    fn new(resolver: Arc<LabelResolver>) -> Self {
        let now = Instant::now();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            resolver,
            created_at: now,
            last_accessed: AtomicU64::new(timestamp),
        }
    }

    fn access(&self) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_accessed.store(timestamp, Ordering::Relaxed);
    }

    fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    fn last_accessed(&self) -> u64 {
        self.last_accessed.load(Ordering::Relaxed)
    }
}

/// Cache for label resolvers to improve performance
/// Uses simplified cache key strategy: only user_profile_keys (config changes are rare)
pub struct ResolverCache {
    cache: DashMap<String, CacheEntry>,
    max_size: usize,
    ttl: Duration,
}

impl ResolverCache {
    /// Create a new resolver cache with the specified configuration
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            max_size,
            ttl,
        }
    }

    /// Create a new resolver cache with default settings
    pub fn new_default() -> Self {
        Self::new(1000, Duration::from_secs(300)) // 1000 entries, 5 minutes TTL
    }

    /// Get or create a label resolver, using cache if available
    /// Simplified cache key: only user_profile_keys since config changes are rare
    pub fn get_or_create(
        &self,
        config: &LabelResolverConfig,
        user_profile_keys: &[Vec<u8>],
    ) -> Result<Arc<LabelResolver>> {
        let cache_key = self.generate_cache_key(user_profile_keys);

        // Try to get from cache first
        let should_remove_expired = if let Some(entry) = self.cache.get(&cache_key) {
            // Check if entry is still valid
            if entry.age() < self.ttl {
                entry.access();
                return Ok(entry.resolver.clone());
            } else {
                true // Mark for removal
            }
        } else {
            false
        };

        // Remove expired entry if needed (outside of the get() scope to avoid deadlock)
        if should_remove_expired {
            self.cache.remove(&cache_key);
        }

        // Cache miss - create new resolver
        let resolver = create_context_label_resolver(config, user_profile_keys)?;

        // Create cache entry
        let entry = CacheEntry::new(resolver.clone());

        // Insert into cache, handling size limits
        self.insert_with_size_limit(cache_key, entry);

        Ok(resolver)
    }

    /// Generate a cache key for user profile keys only
    /// Simplified approach: config changes are rare, so only hash user keys
    fn generate_cache_key(&self, user_profile_keys: &[Vec<u8>]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        // Only hash the user profile keys (sorted for consistent hashing)
        // Config is not included since it rarely changes and cache invalidation handles it
        let mut sorted_keys: Vec<_> = user_profile_keys.iter().collect();
        sorted_keys.sort();
        for key in sorted_keys {
            key.hash(&mut hasher);
        }

        format!("{:x}", hasher.finish())
    }

    /// Insert a cache entry, handling size limits
    fn insert_with_size_limit(&self, key: String, entry: CacheEntry) {
        // If cache is full, remove least recently used entries
        if self.cache.len() >= self.max_size {
            self.evict_lru_entries();
        }

        self.cache.insert(key, entry);
    }

    /// Evict least recently used entries to make room
    fn evict_lru_entries(&self) {
        // When cache is full, we need to make room for at least one new entry
        let target_evictions = std::cmp::max(1, self.max_size / 4); // Evict at least 1, or 25% of entries

        // Collect entries with their access info for sorting
        let mut entries: Vec<_> = self
            .cache
            .iter()
            .map(|entry| {
                let key = entry.key().clone();
                let last_accessed = entry.last_accessed();
                (key, last_accessed)
            })
            .collect();

        // Sort by last accessed time (oldest first)
        entries.sort_by_key(|(_, last_accessed)| *last_accessed);

        // Remove the oldest entries
        for (key, _) in entries.iter().take(target_evictions) {
            self.cache.remove(key);
        }
    }

    /// Clear expired entries from the cache
    pub fn cleanup_expired(&self) -> usize {
        let mut removed_count = 0;

        let expired_keys: Vec<_> = self
            .cache
            .iter()
            .filter(|entry| entry.age() >= self.ttl)
            .map(|entry| entry.key().clone())
            .collect();

        for key in expired_keys {
            if self.cache.remove(&key).is_some() {
                removed_count += 1;
            }
        }

        removed_count
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            total_entries: self.cache.len(),
            max_size: self.max_size,
            ttl_seconds: self.ttl.as_secs(),
        }
    }

    /// Clear the entire cache
    pub fn clear(&self) {
        self.cache.clear();
    }
}

/// Statistics for the resolver cache
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub max_size: usize,
    pub ttl_seconds: u64,
}
