// Test utilities for Runar crates
//
// This crate provides test-specific functionality that should not be available
// in production builds. All functions in this crate are for testing only.

use anyhow::Result;
use runar_common::compact_ids;
use runar_common::logging::{Component, Logger};
use runar_keys::{mobile::MobileKeyManager, node::NodeKeyManager};
use runar_node::NodeConfig;
use runar_serializer::traits::{
    create_context_label_resolver, LabelKeyword, LabelResolver, LabelResolverConfig, LabelValue,
};
use runar_transporter::{
    discovery::DiscoveryOptions,
    network_config::{DiscoveryProviderConfig, NetworkConfig},
    transport::QuicTransportOptions,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Create a test label resolver configuration with common test labels
pub fn create_test_label_resolver_config(network_public_key: Vec<u8>) -> LabelResolverConfig {
    LabelResolverConfig {
        label_mappings: HashMap::from([
            // System label - network key only
            (
                "system".to_string(),
                LabelValue {
                    network_public_key: Some(network_public_key.clone()),
                    user_key_spec: None,
                },
            ),
            // User label - network key + current user
            (
                "user".to_string(),
                LabelValue {
                    network_public_key: Some(network_public_key.clone()),
                    user_key_spec: Some(LabelKeyword::CurrentUser),
                },
            ),
            // Admin label - network key only
            (
                "admin".to_string(),
                LabelValue {
                    network_public_key: Some(network_public_key.clone()),
                    user_key_spec: None,
                },
            ),
            // User-only label - no network key, only user keys
            (
                "private".to_string(),
                LabelValue {
                    network_public_key: Some(network_public_key.clone()),
                    user_key_spec: Some(LabelKeyword::CurrentUser),
                },
            ),
            // Search label - network key only
            (
                "search".to_string(),
                LabelValue {
                    network_public_key: Some(network_public_key.clone()),
                    user_key_spec: None,
                },
            ),
            // System-only label - network key only
            (
                "system_only".to_string(),
                LabelValue {
                    network_public_key: Some(network_public_key.clone()),
                    user_key_spec: None,
                },
            ),
        ]),
    }
}

/// Create a test label resolver for a specific context
pub fn create_test_label_resolver(
    network_public_key: Vec<u8>,
    user_profile_keys: Option<Vec<Vec<u8>>>,
) -> Result<Arc<dyn LabelResolver>> {
    let config = create_test_label_resolver_config(network_public_key);
    let profile_keys = user_profile_keys.unwrap_or_default();
    create_context_label_resolver(&config, &profile_keys)
}

/// Create a test SerializationContext with dynamic resolver
pub fn create_test_serialization_context(
    keystore: Arc<dyn runar_serializer::traits::EnvelopeCrypto>,
    network_public_key: Vec<u8>,
    user_profile_keys: Option<Vec<Vec<u8>>>,
) -> Result<runar_serializer::traits::SerializationContext> {
    let resolver =
        create_test_label_resolver(network_public_key.clone(), user_profile_keys.clone())?;

    Ok(runar_serializer::traits::SerializationContext {
        keystore,
        resolver,
        network_public_key,
        profile_public_keys: user_profile_keys.unwrap_or_default(),
    })
}

/// Create a test configuration with certificates, user root keys, network and node keys installed.
///
/// ⚠️  WARNING: This is for TESTING ONLY. Do not use in production.
/// Use the proper node setup flow for production use.
pub fn create_test_mobile_keys() -> Result<(MobileKeyManager, String)> {
    let logger = Arc::new(Logger::new_root(Component::Keys));

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
    let logger = Arc::new(Logger::new_root(Component::Keys));

    let mut node_keys_manager = NodeKeyManager::new(logger.clone())?;
    let node_public_key = node_keys_manager.get_node_public_key();
    let node_id = compact_ids::compact_id(&node_public_key);
    logger.set_node_id(node_id.clone());
    let setup_token = node_keys_manager
        .generate_csr()
        .expect("Failed to generate setup token");

    let cert_message = mobile_keys_manager
        .process_setup_token(&setup_token)
        .expect("Failed to process setup token");

    let network_key_message = mobile_keys_manager
        .create_network_key_message(default_network_id, &setup_token.node_agreement_public_key)
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

    let (node_keys_manager, _node_id) =
        create_test_node_keys(&mut mobile_keys_manager, &default_network_id)?;

    // Create test label resolver config
    let network_public_key = node_keys_manager.get_network_public_key(&default_network_id)?;
    let label_config = create_test_label_resolver_config(network_public_key);

    let config = NodeConfig::new(default_network_id.clone())
        .with_key_manager(Arc::new(RwLock::new(node_keys_manager)))
        .with_label_resolver_config(label_config);

    Ok(config)
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
    // Assign a unique multicast port for this test instance to isolate from other tests
    let unique_port: u16 = 47000 + (rand::random::<u16>() % 1000);
    let unique_group = format!("239.255.42.98:{unique_port}");

    let mut configs = Vec::new();
    for _ in 0..total {
        let (node_keys_manager, _node_id) =
            create_test_node_keys(&mut mobile_keys_manager, &default_network_id)?;

        let node_cert_config = node_keys_manager
            .get_quic_certificate_config()
            .expect("Failed to get QUIC certificates for node1");

        let transport_options = QuicTransportOptions::new()
            .with_certificates(node_cert_config.certificate_chain)
            .with_private_key(node_cert_config.private_key)
            .with_root_certificates(vec![ca_certificate.clone()]);

        //transport_options.

        let discovery_options = DiscoveryOptions {
            multicast_group: unique_group.clone(),
            ..Default::default()
        };

        // Create test label resolver config
        let network_public_key = node_keys_manager.get_network_public_key(&default_network_id)?;
        let label_config = create_test_label_resolver_config(network_public_key);

        let config = NodeConfig::new(default_network_id.clone())
            .with_key_manager(Arc::new(RwLock::new(node_keys_manager)))
            .with_label_resolver_config(label_config)
            .with_network_config(
                NetworkConfig::with_quic(transport_options)
                    .with_discovery_options(discovery_options)
                    .with_discovery_provider(DiscoveryProviderConfig::default_multicast()),
            );

        configs.push(config);
    }

    Ok(configs)
}

// Mobile Simulator Utilities
// =========================

/// Represents a mobile device with its key manager and profile information
pub struct MobileDevice {
    /// The mobile key manager for this device
    pub key_manager: Arc<MobileKeyManager>,
    /// User profile keys derived from the root key
    pub profile_keys: HashMap<String, Vec<u8>>,
    /// Network IDs this mobile has access to
    pub network_ids: Vec<String>,
    /// Logger for this mobile device
    pub logger: Arc<Logger>,
}

/// Master mobile that sets up the network and can issue certificates
pub struct MasterMobile {
    /// The master mobile key manager
    pub key_manager: Arc<MobileKeyManager>,
    /// Network ID created by this master
    pub network_id: String,
    /// Network public key for sharing with other devices
    pub network_public_key: Vec<u8>,
    /// Logger for the master mobile
    pub logger: Arc<Logger>,
}

/// Complete mobile simulation environment
pub struct MobileSimulator {
    /// The master mobile that owns the network
    pub master: MasterMobile,
    /// Regular user mobile devices
    pub users: HashMap<String, MobileDevice>,
    /// Logger for the simulator
    pub logger: Arc<Logger>,
}

impl MobileSimulator {
    /// Create a new mobile simulator with a master mobile
    pub fn new(logger: Arc<Logger>) -> Result<Self> {
        logger.info("🚀 Creating Mobile Simulator...");

        // Create master mobile
        let master_logger = Arc::new(Logger::new_root(Component::System));
        let mut master_key_manager = MobileKeyManager::new(master_logger.clone())?;

        // Initialize master with user root key and network
        master_key_manager.initialize_user_root_key()?;
        let network_id = master_key_manager.generate_network_data_key()?;
        let network_public_key = master_key_manager.get_network_public_key(&network_id)?;

        let master = MasterMobile {
            key_manager: Arc::new(master_key_manager),
            network_id: network_id.clone(),
            network_public_key,
            logger: master_logger,
        };

        logger.info(format!(
            "✅ Master mobile created with network: {network_id}"
        ));

        Ok(Self {
            master,
            users: HashMap::new(),
            logger,
        })
    }

    /// Add a new user mobile device to the simulation
    pub fn add_user_mobile(&mut self, user_id: &str, profile_names: &[&str]) -> Result<()> {
        self.logger
            .info(format!("📱 Adding user mobile: {user_id}"));

        let user_logger = Arc::new(Logger::new_root(Component::System));
        let mut user_key_manager = MobileKeyManager::new(user_logger.clone())?;

        // Initialize user with root key
        user_key_manager.initialize_user_root_key()?;

        // Derive profile keys
        let mut profile_keys = HashMap::new();
        for profile_name in profile_names {
            let profile_key = user_key_manager.derive_user_profile_key(profile_name)?;
            profile_keys.insert(profile_name.to_string(), profile_key);
            self.logger
                .info(format!("   ✅ Created profile: {profile_name}"));
        }

        // Install network public key so user can encrypt for the network
        user_key_manager.install_network_public_key(&self.master.network_public_key)?;

        let user_device = MobileDevice {
            key_manager: Arc::new(user_key_manager),
            profile_keys,
            network_ids: vec![self.master.network_id.clone()],
            logger: user_logger,
        };

        self.users.insert(user_id.to_string(), user_device);
        self.logger.info(format!(
            "✅ User mobile {user_id} added with {} profiles",
            profile_names.len()
        ));

        Ok(())
    }

    /// Create a node configuration that can work with this mobile simulation
    pub fn create_node_config(&self) -> Result<NodeConfig> {
        self.logger.info("🖥️ Creating node configuration...");

        // Create node key manager
        let node_logger = Arc::new(Logger::new_root(Component::System));
        let mut node_key_manager = NodeKeyManager::new(node_logger)?;

        // Get node setup token and have master sign it
        let setup_token = node_key_manager.generate_csr()?;

        // Export the master key manager state and create a new instance with the same state
        let master_state = self.master.key_manager.export_state();
        let mut master_key_manager =
            MobileKeyManager::from_state(master_state, self.master.logger.clone())?;

        // Use the existing network ID from the master
        let cert_message = master_key_manager.process_setup_token(&setup_token)?;
        node_key_manager.install_certificate(cert_message)?;

        // Install network key from master using the existing network ID
        let network_key_message = master_key_manager.create_network_key_message(
            &self.master.network_id,
            &setup_token.node_agreement_public_key,
        )?;
        node_key_manager.install_network_key(network_key_message)?;

        // Get the CA certificate to use as root certificate for validation
        let ca_certificate = master_key_manager
            .get_ca_certificate()
            .to_rustls_certificate();

        // Get QUIC certificate configuration for this node
        let node_cert_config = node_key_manager
            .get_quic_certificate_config()
            .expect("Failed to get QUIC certificates for node");

        // Get node ID before moving node_key_manager
        let node_id = node_key_manager.get_node_id();

        // Create transport options with QUIC certificates
        let transport_options = QuicTransportOptions::new()
            .with_certificates(node_cert_config.certificate_chain)
            .with_private_key(node_cert_config.private_key)
            .with_root_certificates(vec![ca_certificate]);

        let discovery_options = DiscoveryOptions::default();

        // Create test label resolver config
        let network_public_key =
            node_key_manager.get_network_public_key(&self.master.network_id)?;
        let label_config = create_test_label_resolver_config(network_public_key);

        let config = NodeConfig::new(self.master.network_id.clone())
            .with_key_manager(Arc::new(RwLock::new(node_key_manager)))
            .with_label_resolver_config(label_config)
            .with_network_config(
                NetworkConfig::with_quic(transport_options)
                    .with_discovery_options(discovery_options)
                    .with_discovery_provider(DiscoveryProviderConfig::default_multicast()),
            );

        self.logger.info(format!(
            "✅ Node configuration created for node: {node_id} with network transport"
        ));

        Ok(config)
    }

    /// Create label resolvers for encryption/decryption scenarios
    pub fn create_label_resolvers(
        &self,
    ) -> Result<(Arc<dyn LabelResolver>, Arc<dyn LabelResolver>)> {
        self.logger.info("🔑 Creating label resolvers...");

        // Get profile keys from first user (or create default if none)
        let profile_keys = if let Some(first_user) = self.users.values().next() {
            first_user.profile_keys.clone()
        } else {
            // Create a default user if none exists
            let mut default_user = MobileKeyManager::new(self.logger.clone())?;
            default_user.initialize_user_root_key()?;
            let default_profile = default_user.derive_user_profile_key("default")?;
            HashMap::from([("default".to_string(), default_profile)])
        };

        // Create system label config
        let system_config =
            create_test_label_resolver_config(self.master.network_public_key.clone());

        // Create mobile resolver (with user context)
        let profile_keys_vec = profile_keys.values().cloned().collect::<Vec<_>>();
        let mobile_resolver = create_context_label_resolver(&system_config, &profile_keys_vec)?;

        // Create node resolver (system context only)
        let empty_profile_keys = vec![];
        let node_resolver = create_context_label_resolver(
            &system_config,
            &empty_profile_keys, // No user context
        )?;

        self.logger.info("✅ Label resolvers created");

        Ok((mobile_resolver, node_resolver))
    }

    /// Get a specific user mobile device
    pub fn get_user_mobile(&self, user_id: &str) -> Option<&MobileDevice> {
        self.users.get(user_id)
    }

    /// Get the master mobile
    pub fn get_master_mobile(&self) -> &MasterMobile {
        &self.master
    }

    /// Print simulation summary
    pub fn print_summary(&self) {
        self.logger.info("📊 Mobile Simulation Summary:");
        self.logger
            .info(format!("   Master Network ID: {}", self.master.network_id));
        self.logger
            .info(format!("   Total Users: {}", self.users.len()));

        for (user_id, user_device) in &self.users {
            self.logger.info(format!(
                "   User {user_id}: {} profiles",
                user_device.profile_keys.len()
            ));
            for profile_name in user_device.profile_keys.keys() {
                self.logger.info(format!("     - {profile_name}"));
            }
        }
    }
}

/// Convenience function to create a simple mobile simulation for testing
pub fn create_simple_mobile_simulation() -> Result<MobileSimulator> {
    let logger = Arc::new(Logger::new_root(Component::System));
    let mut simulator = MobileSimulator::new(logger)?;

    // Add a default user with common profiles
    simulator.add_user_mobile("alice", &["personal", "work", "family"])?;

    Ok(simulator)
}

/// Convenience function to create a complete test environment with mobile simulation and node config
pub fn create_test_environment() -> Result<(MobileSimulator, NodeConfig)> {
    let simulator = create_simple_mobile_simulation()?;
    let node_config = simulator.create_node_config()?;

    Ok((simulator, node_config))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Set up logging once for all tests in this module
    fn setup_logging() {
        let logging_config = runar_common::logging::LoggingConfig::new()
            .with_default_level(runar_node::config::LogLevel::Warn);
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
        let logger = Arc::new(Logger::new_root(Component::Keys));

        let imported_manager = NodeKeyManager::from_state(exported_state, logger).unwrap();

        // Verify the imported manager has the same node ID
        assert_eq!(imported_manager.get_node_id(), node_id);
    }

    #[test]
    fn test_create_node_test_config() {
        init();
        let config = create_node_test_config().unwrap();

        // Verify basic config properties
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

    // Mobile Simulator Tests
    // =====================

    #[test]
    fn test_mobile_simulator_creation() -> Result<()> {
        init();
        let simulator = create_simple_mobile_simulation()?;

        // Verify master mobile exists
        assert!(!simulator.master.network_id.is_empty());
        assert!(!simulator.master.network_public_key.is_empty());

        // Verify user mobile exists
        let alice = simulator
            .get_user_mobile("alice")
            .expect("Alice should exist");
        assert_eq!(alice.profile_keys.len(), 3);
        assert!(alice.profile_keys.contains_key("personal"));
        assert!(alice.profile_keys.contains_key("work"));
        assert!(alice.profile_keys.contains_key("family"));

        Ok(())
    }

    #[test]
    fn test_label_resolvers() -> Result<()> {
        init();
        let simulator = create_simple_mobile_simulation()?;
        let (_mobile_resolver, _node_resolver) = simulator.create_label_resolvers()?;

        // Verify resolvers were created (basic validation)
        // The actual encryption/decryption testing is done in the encryption_test.rs

        Ok(())
    }

    #[tokio::test]
    async fn test_mobile_simulator_network_discovery() -> Result<()> {
        use std::time::Duration;
        init();

        // Configure logging
        let logging_config = runar_common::logging::LoggingConfig::new()
            .with_default_level(runar_node::config::LogLevel::Warn);
        logging_config.apply();

        let logger = Arc::new(Logger::new_root(Component::Custom(
            "mobile_sim_network_test",
        )));

        // Create mobile simulator
        let simulator = create_simple_mobile_simulation()?;

        // Create two node configurations using the simulator
        let node1_config = simulator.create_node_config()?;
        let node2_config = simulator.create_node_config()?;

        // let node1_id = node1_config.node_id.clone();
        // let node2_id = node2_config.node_id.clone();

        // logger.info(format!("Node1 ID: {node1_id}"));
        // logger.info(format!("Node2 ID: {node2_id}"));
        logger.info(format!("Network ID: {}", simulator.master.network_id));

        // Create nodes
        let node1 = runar_node::Node::new(node1_config).await?;
        let node2 = runar_node::Node::new(node2_config).await?;

        // Start nodes
        node1.start().await?;
        logger.info("✅ Node 1 started");

        node2.start().await?;
        logger.info("✅ Node 2 started");

        // Wait for nodes to discover each other
        logger.info("⏳ Waiting for nodes to discover each other...");
        let _ = node2
            .on(
                format!(
                    "$registry/peer/{node1_id}/discovered",
                    node1_id = node1.node_id()
                ),
                Some(runar_node::services::OnOptions {
                    timeout: Duration::from_secs(3),
                    include_past: Some(Duration::from_secs(3)),
                }),
            )
            .await?;
        let _ = node1
            .on(
                format!(
                    "$registry/peer/{node2_id}/discovered",
                    node2_id = node2.node_id()
                ),
                Some(runar_node::services::OnOptions {
                    timeout: Duration::from_secs(3),
                    include_past: Some(Duration::from_secs(3)),
                }),
            )
            .await?;

        logger.info("✅ Nodes successfully discovered each other!");

        // Cleanup
        node2.stop().await?;
        node1.stop().await?;

        logger.info("✅ Mobile simulator network discovery test completed successfully!");

        Ok(())
    }
}
