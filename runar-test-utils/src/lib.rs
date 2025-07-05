// Test utilities for Runar crates
//
// This crate provides test-specific functionality that should not be available
// in production builds. All functions in this crate are for testing only.

use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_keys::compact_ids;
use runar_keys::{mobile::MobileKeyManager, node::NodeKeyManager};
use runar_node::{
    network::{network_config::NetworkConfig, QuicTransportOptions},
    NodeConfig,
};
use std::sync::Arc;

/// Create a test configuration with certificates, user root keys, network and node keys installed.
///
/// ⚠️  WARNING: This is for TESTING ONLY. Do not use in production.
/// Use the proper node setup flow for production use.
pub fn create_test_mobile_keys() -> Result<(MobileKeyManager, String)> {
    let logger = Arc::new(Logger::new_root(Component::Keys, "mobile_keys_test"));

    let mut mobile_keys_manager = MobileKeyManager::new(logger.clone())?;
    let _ = mobile_keys_manager
        .initialize_user_root_key()
        .expect("Failed to generate user root key");
    let default_network_id = mobile_keys_manager
        .generate_network_data_key()
        .expect("Failed to generate network data key");
    Ok((mobile_keys_manager, default_network_id))
}

/// Create a test configuration with certificates, user root keys, network and node keys installed.
///
/// ⚠️  WARNING: This is for TESTING ONLY. Do not use in production.
/// Use the proper node setup flow for production use.
pub fn create_test_node_keys(
    mobile_keys_manager: &mut MobileKeyManager,
    default_network_id: &str,
) -> Result<(NodeKeyManager, String)> {
    let logger = Arc::new(Logger::new_root(Component::Keys, "mobile_keys_test"));

    let mut node_keys_manager = NodeKeyManager::new(logger.clone())?;
    let node_public_key = node_keys_manager.get_node_public_key();
    let node_id = compact_ids::compact_node_id(&node_public_key);

    let setup_token = node_keys_manager
        .generate_csr()
        .expect("Failed to generate setup token");

    let cert_message = mobile_keys_manager
        .process_setup_token(&setup_token)
        .expect("Failed to process setup token");

    let network_key_message = mobile_keys_manager
        .create_network_key_message(default_network_id, &node_public_key)
        .expect("Failed to create network key message");

    node_keys_manager
        .install_certificate(cert_message)
        .expect("could not install certificate");

    node_keys_manager
        .install_network_key(network_key_message)
        .expect("Failed to install network key");

    Ok((node_keys_manager, node_id))
}

/// Create a test configuration with certificates, user root keys, network and node keys installed.
///
/// ⚠️  WARNING: This is for TESTING ONLY. Do not use in production.
/// Use the proper node setup flow for production use.
pub fn create_node_test_config() -> Result<NodeConfig> {
    // Create test credentials

    let (mut mobile_keys_manager, default_network_id) = create_test_mobile_keys()?;

    let (node_keys_manager, node_id) =
        create_test_node_keys(&mut mobile_keys_manager, &default_network_id)?;

    let key_state = node_keys_manager.export_state();
    let key_state_bytes = bincode::serialize(&key_state)?;

    Ok(NodeConfig::new(node_id, default_network_id).with_key_manager_state(key_state_bytes))
}

/// Create a test configuration with certificates, user root keys, network and node keys installed.
///
/// ⚠️  WARNING: This is for TESTING ONLY. Do not use in production.
/// Use the proper node setup flow for production use.
pub fn create_networked_node_test_config(total: u32) -> Result<Vec<NodeConfig>> {
    // Create test credentials
    let (mut mobile_keys_manager, default_network_id) = create_test_mobile_keys()?;

    // Get the CA certificate to use as root certificate for validation
    let ca_certificate = mobile_keys_manager
        .get_ca_certificate()
        .to_rustls_certificate();

    let mut configs = Vec::new();
    for _ in 0..total {
        let (node_keys_manager, node_id) =
            create_test_node_keys(&mut mobile_keys_manager, &default_network_id)?;

        let node_cert_config = node_keys_manager
            .get_quic_certificate_config()
            .expect("Failed to get QUIC certificates for node1");

        let key_state = node_keys_manager.export_state();
        let key_state_bytes = bincode::serialize(&key_state)?;

        let transport_options = QuicTransportOptions::new()
            .with_certificates(node_cert_config.certificate_chain)
            .with_private_key(node_cert_config.private_key)
            .with_root_certificates(vec![ca_certificate.clone()]);

        let config = NodeConfig::new(node_id, default_network_id.clone())
            .with_key_manager_state(key_state_bytes)
            .with_network_config(
                NetworkConfig::with_quic(transport_options).with_multicast_discovery(),
            );

        configs.push(config);
    }

    Ok(configs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Set up logging once for all tests in this module
    fn setup_logging() {
        let logging_config = runar_node::config::LoggingConfig::new()
            .with_default_level(runar_node::config::LogLevel::Error);
        logging_config.apply();
    }

    // This runs once when the test module is loaded
    static INIT: std::sync::Once = std::sync::Once::new();

    fn init() {
        INIT.call_once(|| {
            setup_logging();
        });
    }

    #[test]
    fn test_create_test_mobile_keys() {
        init();
        let (_mobile_keys_manager, network_id) = create_test_mobile_keys().unwrap();

        // Verify mobile keys manager was created and network_id is valid
        assert!(!network_id.is_empty());

        // Verify network ID format (should be a compact ID)
        assert!(network_id.len() > 20); // Compact IDs are typically long
        assert!(!network_id.contains(' ')); // Should not contain spaces
    }

    #[test]
    fn test_create_test_node_keys() {
        init();
        let (mut mobile_keys_manager, network_id) = create_test_mobile_keys().unwrap();

        let (node_keys_manager, node_id) =
            create_test_node_keys(&mut mobile_keys_manager, &network_id).unwrap();

        // Verify node keys manager was created with proper state
        assert!(!node_id.is_empty());
        assert!(!node_keys_manager.get_node_public_key().is_empty());

        // Verify node ID format (should be a compact ID)
        assert!(node_id.len() > 20); // Compact IDs are typically long
        assert!(!node_id.contains(' ')); // Should not contain spaces

        // Verify we can export the state (which validates the internal state)
        let exported_state = node_keys_manager.export_state();
        let logger = Arc::new(Logger::new_root(Component::Keys, "test_import"));

        let imported_manager = NodeKeyManager::from_state(exported_state, logger).unwrap();

        // Verify the imported manager has the same node ID
        assert_eq!(imported_manager.get_node_id(), node_id);
    }

    #[test]
    fn test_create_node_test_config() {
        init();
        let config = create_node_test_config().unwrap();

        // Verify basic config properties
        assert!(!config.node_id.is_empty());
        assert!(!config.default_network_id.is_empty());
        assert_eq!(config.request_timeout_ms, 30000);

        // Test that we can create a Node from this config (which validates the key manager state)
        let rt = tokio::runtime::Runtime::new().unwrap();
        let node_result = rt.block_on(async { runar_node::Node::new(config).await });
        assert!(
            node_result.is_ok(),
            "Failed to create Node from test config: {:?}",
            node_result.err()
        );
    }

    #[test]
    fn test_create_multiple_node_test_config() {
        init();
        let total_nodes = 3;
        let configs = create_networked_node_test_config(total_nodes).unwrap();

        // Verify correct number of configs
        assert_eq!(configs.len(), total_nodes as usize);

        // Verify each config is valid
        for (i, config) in configs.iter().enumerate() {
            assert!(!config.node_id.is_empty(), "Node {i} has empty node_id");
            assert!(
                !config.default_network_id.is_empty(),
                "Node {i} has empty network_id"
            );
            assert_eq!(
                config.request_timeout_ms, 30000,
                "Node {i} has wrong timeout"
            );
        }

        // Verify all nodes have the same network ID (they should be in the same network)
        let first_network_id = &configs[0].default_network_id;
        for (i, config) in configs.iter().enumerate() {
            assert_eq!(
                &config.default_network_id, first_network_id,
                "Node {i} has different network_id"
            );
        }

        // Verify all nodes have unique node IDs
        let mut node_ids = std::collections::HashSet::new();
        for config in &configs {
            assert!(
                node_ids.insert(config.node_id.clone()),
                "Duplicate node_id found: {}",
                config.node_id
            );
        }
    }

    #[test]
    fn test_error_handling() {
        init();
        // Test with invalid parameters
        let result = create_networked_node_test_config(0);
        assert!(result.is_ok()); // Should handle 0 nodes gracefully

        let configs = result.unwrap();
        assert_eq!(configs.len(), 0);
    }
}
