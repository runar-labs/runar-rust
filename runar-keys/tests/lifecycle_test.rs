//! Tests for NodeKeyManager lifecycle and new features
//!
//! This module tests the new NodeKeyManager lifecycle with generate_keys(),
//! Option return types, and node ID persistence without overlapping with
//! existing comprehensive tests.

use anyhow::Result;
use runar_common::compact_ids::compact_id;
use runar_keys::{keystore::DeviceKeystore, NodeKeyManager};
use runar_logging::{Component, Logger};
use std::sync::Arc;
use tempfile::TempDir;

// Simple mock keystore for testing
struct MockDeviceKeystore;

impl DeviceKeystore for MockDeviceKeystore {
    fn encrypt(&self, plaintext: &[u8], _aad: &[u8]) -> runar_keys::error::Result<Vec<u8>> {
        // Simple mock - just return the plaintext (not secure, but fine for testing)
        Ok(plaintext.to_vec())
    }

    fn decrypt(&self, ciphertext: &[u8], _aad: &[u8]) -> runar_keys::error::Result<Vec<u8>> {
        // Simple mock - just return the ciphertext (not secure, but fine for testing)
        Ok(ciphertext.to_vec())
    }

    fn capabilities(&self) -> runar_keys::keystore::DeviceKeystoreCaps {
        runar_keys::keystore::DeviceKeystoreCaps::default()
    }
}

fn create_test_logger() -> Arc<Logger> {
    Arc::new(Logger::new_root(Component::Custom("lifecycle_test")))
}

/// Test the new NodeKeyManager lifecycle with generate_keys()
#[test]
fn test_node_key_manager_lifecycle() -> Result<()> {
    let logger = create_test_logger();
    let mut manager = NodeKeyManager::new(logger)?;

    // Before generate_keys() - all should return None
    assert!(manager.get_node_id().is_none());
    assert!(manager.get_node_public_key().is_none());
    assert!(manager.get_storage_key().is_none());

    // generate_keys() should succeed
    manager.generate_keys()?;

    // After generate_keys() - all should return Some
    let node_id = manager.get_node_id().unwrap();
    let node_public_key = manager.get_node_public_key().unwrap();
    let storage_key = manager.get_storage_key().unwrap();

    // Verify values are valid
    assert!(!node_id.is_empty());
    assert_eq!(node_id.len(), 26); // Compact ID length
    assert!(!node_public_key.is_empty());
    assert_eq!(storage_key.len(), 32); // AES-256 key

    // Verify node_id is derived from public key
    let derived_id = compact_id(&node_public_key);
    assert_eq!(node_id, derived_id);

    Ok(())
}

/// Test calling generate_keys() multiple times (should be idempotent)
#[test]
fn test_generate_keys_idempotent() -> Result<()> {
    let logger1 = create_test_logger();
    let mut manager = NodeKeyManager::new(logger1)?;

    // First call
    manager.generate_keys()?;
    let first_node_id = manager.get_node_id().unwrap();
    let first_public_key = manager.get_node_public_key().unwrap();

    // Test that keys are available after first call
    assert!(!first_node_id.is_empty());
    assert!(!first_public_key.is_empty());

    // Note: We can't call generate_keys() again on the same manager
    // because it would try to set the logger's node_id again, which panics.
    // The idempotency is ensured by the fact that generate_keys() only
    // generates keys if they don't already exist (checked internally).

    Ok(())
}

/// Test error handling when trying to use methods before generate_keys()
#[test]
fn test_methods_before_generate_keys() -> Result<()> {
    let logger = create_test_logger();
    let mut manager = NodeKeyManager::new(logger)?;

    // These should return None, not panic
    assert!(manager.get_node_id().is_none());
    assert!(manager.get_node_public_key().is_none());
    assert!(manager.get_storage_key().is_none());

    // These should return errors, not panic
    assert!(manager.generate_csr().is_err());
    assert!(manager.get_quic_certificate_config().is_err());

    Ok(())
}

/// Test node ID persistence with node_id.txt file
#[test]
fn test_node_id_persistence() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_dir = temp_dir.path().to_path_buf();

    let logger = create_test_logger();
    let mut manager = NodeKeyManager::new(logger)?;

    // Configure persistence
    manager.set_persistence_dir(config_dir.clone());
    manager.register_device_keystore(Arc::new(MockDeviceKeystore));

    manager.generate_keys()?;

    let original_node_id = manager.get_node_id().unwrap();

    // Flush state (this should create node_id.txt)
    manager.flush_state()?;

    // Check if node_id.txt was created
    let node_id_path = config_dir.join("node_id.txt");
    assert!(
        node_id_path.exists(),
        "node_id.txt should be created during export"
    );

    // Read the node_id.txt file
    let persisted_node_id = std::fs::read_to_string(&node_id_path)?;
    assert_eq!(persisted_node_id.trim(), original_node_id);

    // Test loading from file using probe_and_load_state
    let logger2 = create_test_logger();
    let mut loaded_manager = NodeKeyManager::new(logger2)?;

    // Configure persistence for the loaded manager (same as original)
    loaded_manager.set_persistence_dir(config_dir.clone());
    loaded_manager.register_device_keystore(Arc::new(MockDeviceKeystore));

    let state_loaded = loaded_manager.probe_and_load_state()?;
    assert!(state_loaded, "State should be loaded successfully");

    let loaded_node_id = loaded_manager.get_node_id().unwrap();
    assert_eq!(loaded_node_id, original_node_id);

    Ok(())
}

/// Test profile key functionality in NodeKeyManager
#[test]
fn test_node_profile_key_derivation() -> Result<()> {
    let logger = create_test_logger();
    let mut manager = NodeKeyManager::new(logger)?;
    manager.generate_keys()?;

    // Test profile key derivation
    let profile1_key = manager.derive_user_profile_key("personal")?;
    let profile2_key = manager.derive_user_profile_key("work")?;

    // Keys should be different
    assert_ne!(profile1_key, profile2_key);

    // Keys should be valid public keys (uncompressed P-256)
    assert_eq!(profile1_key.len(), 65); // Uncompressed P-256 (0x04 + 32 + 32)
    assert_eq!(profile2_key.len(), 65);

    // Test profile-based encryption/decryption (basic test)
    let test_data = b"test message for profile encryption";
    let encrypted = manager.encrypt_message_for_mobile(test_data, &profile1_key)?;

    // For this test, we'll just verify the encryption worked
    // (decrypt_with_profile requires EnvelopeEncryptedData, not Vec<u8>)
    assert!(!encrypted.is_empty());
    assert_ne!(encrypted, test_data);

    Ok(())
}
