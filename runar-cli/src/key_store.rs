//! OS Key Store Integration
//!
//! This module provides secure storage for node keys using the operating system's
//! key store (Keychain on macOS, Credential Manager on Windows, Secret Service on Linux).

use anyhow::{Context, Result};
use base64::Engine;
use keyring::Entry;
use runar_common::logging::Logger;
use std::sync::Arc;

/// OS Key Store for secure key storage
pub struct OsKeyStore {
    logger: Arc<Logger>,
}

impl OsKeyStore {
    /// Create a new OS Key Store instance
    pub fn new(logger: Arc<Logger>) -> Self {
        Self { logger }
    }

    /// Store serialized node state in OS key store
    ///
    /// # Arguments
    /// * `keys_name` - Unique identifier for the keys (format: runar_{uuid})
    /// * `serialized_state` - Serialized NodeKeyManagerState bytes
    pub fn store_node_keys(&self, keys_name: &str, serialized_state: &[u8]) -> Result<()> {
        let entry =
            Entry::new("runar-node", keys_name).context("Failed to create keyring entry")?;

        entry
            .set_password(&base64::engine::general_purpose::STANDARD.encode(serialized_state))
            .with_context(|| format!("Failed to store keys in OS key store: {keys_name}"))?;

        self.logger.info(format!(
            "Node keys stored securely in OS key store: {keys_name}"
        ));

        Ok(())
    }

    /// Retrieve serialized node state from OS key store
    ///
    /// # Arguments
    /// * `keys_name` - Unique identifier for the keys (format: runar_{uuid})
    ///
    /// # Returns
    /// * Serialized NodeKeyManagerState bytes
    pub fn retrieve_node_keys(&self, keys_name: &str) -> Result<Vec<u8>> {
        let entry =
            Entry::new("runar-node", keys_name).context("Failed to create keyring entry")?;

        let encoded_state = entry
            .get_password()
            .with_context(|| format!("Failed to retrieve keys from OS key store: {keys_name}"))?;

        let serialized_state = base64::engine::general_purpose::STANDARD
            .decode(&encoded_state)
            .with_context(|| format!("Failed to decode keys from OS key store: {keys_name}"))?;

        self.logger.info(format!(
            "Node keys retrieved from OS key store: {keys_name}"
        ));

        Ok(serialized_state)
    }

    /// Check if keys exist in OS key store
    ///
    /// # Arguments
    /// * `keys_name` - Unique identifier for the keys (format: runar_{uuid})
    ///
    /// # Returns
    /// * `true` if keys exist, `false` otherwise
    pub fn keys_exist(&self, keys_name: &str) -> bool {
        let entry = match Entry::new("runar-node", keys_name) {
            Ok(entry) => entry,
            Err(_) => return false,
        };

        entry.get_password().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runar_common::logging::Component;

    #[test]
    fn test_key_store_operations() {
        let logger = Arc::new(Logger::new_root(Component::CLI, "test"));
        let key_store = OsKeyStore::new(logger);

        let test_keys_name = "test_keys_123";
        let test_data = b"test serialized node state data";

        // Test storing keys - handle case where OS key store is not available
        match key_store.store_node_keys(test_keys_name, test_data) {
            Ok(_) => {
                // OS key store is available, run full test
                println!("OS key store available, running full test");

                // Test checking if keys exist
                assert!(key_store.keys_exist(test_keys_name));

                // Test retrieving keys
                let retrieved_data = key_store.retrieve_node_keys(test_keys_name).unwrap();
                assert_eq!(retrieved_data, test_data);

                println!("All key store operations completed successfully");
            }
            Err(e) => {
                // OS key store is not available (common in CI environments)
                println!("OS key store not available, skipping test: {e}");
                println!(
                    "This is expected in CI environments where keyring services are not available"
                );

                // Test that keys_exist returns false when key store is not available
                assert!(!key_store.keys_exist(test_keys_name));

                println!("Test completed gracefully with unavailable key store");
            }
        }
    }
}
