//! Start command for running a Runar node
//!
//! This module handles starting a Runar node with the configuration and keys
//! that were created during initialization.

use anyhow::{Context, Result};
use runar_common::logging::{Component, Logger};
use runar_keys::NodeKeyManager;
use runar_node::{Node, NodeConfig as RunarNodeConfig};
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::NodeConfig;
use crate::key_store::OsKeyStore;

pub struct StartCommand {
    config_dir: PathBuf,
    logger: Arc<Logger>,
}

impl StartCommand {
    pub fn new(config_dir: PathBuf, logger: Arc<Logger>) -> Self {
        Self { config_dir, logger }
    }

    pub async fn run(&self, config_path: Option<PathBuf>) -> Result<()> {
        self.logger.info("Starting Runar node...");

        // Load configuration
        let config = self.load_configuration(config_path)?;
        self.logger
            .info(format!("Loaded configuration for node: {}", config.node_id));

        // Load node keys from OS key store
        let node_key_manager = self.load_node_keys(&config)?;
        self.logger
            .info("Node keys loaded successfully from OS key store");

        // Create Runar node configuration using production constructor
        let runar_config = self.create_runar_config(&config, &node_key_manager)?;

        // Create and start the node
        let mut node = Node::new(runar_config)
            .await
            .context("Failed to create Runar node")?;

        self.logger.info("Runar node created successfully");

        // Start the node
        node.start().await.context("Failed to start Runar node")?;

        self.logger.info("Runar node started successfully");
        println!("🚀 Runar node is now running!");
        println!("📋 Node Information:");
        println!("   • Node ID: {}", config.node_id);
        println!("   • Default Network: {}", config.default_network_id);
        println!("   • Keys Name: {}", config.keys_name);
        println!();
        println!("📱 The node is ready to accept connections from mobile devices");
        println!("🛑 Press Ctrl+C to stop the node");

        // Wait for shutdown signal
        self.wait_for_shutdown(&mut node).await?;

        Ok(())
    }

    fn load_configuration(&self, config_path: Option<PathBuf>) -> Result<NodeConfig> {
        let config_dir = config_path
            .map(|p| p.parent().unwrap_or(&self.config_dir).to_path_buf())
            .unwrap_or(self.config_dir.clone());

        NodeConfig::load(&config_dir)
            .with_context(|| format!("Failed to load configuration from {config_dir:?}"))
    }

    fn load_node_keys(&self, config: &NodeConfig) -> Result<NodeKeyManager> {
        // Load the serialized node state from OS key store
        let key_store = OsKeyStore::new(self.logger.clone());

        if !key_store.keys_exist(&config.keys_name) {
            return Err(anyhow::anyhow!(
                "Node keys not found in OS key store: {}",
                config.keys_name
            ));
        }

        let serialized_state = key_store
            .retrieve_node_keys(&config.keys_name)
            .with_context(|| {
                format!(
                    "Failed to retrieve node keys from OS key store: {}",
                    config.keys_name
                )
            })?;

        // Deserialize the node state
        let node_state =
            bincode::deserialize(&serialized_state).context("Failed to deserialize node state")?;

        // Create logger for the key manager
        let key_logger = Arc::new(Logger::new_root(Component::Keys, &config.node_id));

        // Create node key manager from state
        let node_key_manager = NodeKeyManager::from_state(node_state, key_logger)
            .context("Failed to create node key manager from state")?;

        self.logger.info(format!(
            "Node keys loaded from OS key store: {}",
            config.keys_name
        ));

        Ok(node_key_manager)
    }

    fn create_runar_config(
        &self,
        config: &NodeConfig,
        node_key_manager: &NodeKeyManager,
    ) -> Result<RunarNodeConfig> {
        // Export the current state for the Runar node
        let node_state = node_key_manager.export_state();
        let serialized_state = bincode::serialize(&node_state)
            .context("Failed to serialize node state for Runar config")?;

        // Create Runar node configuration using production constructor
        let mut runar_config =
            RunarNodeConfig::new(config.node_id.clone(), config.default_network_id.clone());
        runar_config = runar_config
            .with_additional_networks(config.network_ids.clone())
            .with_request_timeout(config.request_timeout_ms)
            .with_key_manager_state(serialized_state);

        Ok(runar_config)
    }

    async fn wait_for_shutdown(&self, node: &mut Node) -> Result<()> {
        // Set up signal handling for graceful shutdown (cross-platform)
        let ctrl_c = tokio::signal::ctrl_c();
        ctrl_c
            .await
            .context("Failed to create shutdown signal handler")?;

        self.logger
            .info("Shutdown signal received - stopping node...");

        // Stop the node gracefully
        node.stop().await.context("Failed to stop Runar node")?;

        self.logger.info("Runar node stopped successfully");
        println!("🛑 Runar node stopped");

        Ok(())
    }
}
