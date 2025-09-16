//! Start command for Runar CLI
//!
//! This module handles starting a Runar node with the configuration and keys
//! created during the initialization process.

use anyhow::{Context, Result};
use runar_keys::node::NodeKeyManager;
use runar_logging::log_info;
use runar_logging::{Component, Logger};
use runar_node::{Node, NodeConfig};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::signal::ctrl_c;

use crate::config::NodeConfig as CliNodeConfig;
use crate::device_keystore::create_device_keystore_for_platform;

pub struct StartCommand {
    config_dir: PathBuf,
    logger: Arc<Logger>,
}

impl StartCommand {
    pub fn new(config_dir: PathBuf, logger: Arc<Logger>) -> Self {
        Self { config_dir, logger }
    }

    pub async fn run(&self, config_path: Option<PathBuf>) -> Result<()> {
        log_info!(self.logger, "Starting Runar node...");

        // Load configuration
        let config = self.load_configuration(config_path)?;
        log_info!(
            self.logger,
            "Loaded configuration for node: {}",
            config.node_id
        );

        // Load node keys using new state management
        let node_key_manager = self.load_node_keys(&config)?;
        log_info!(
            self.logger,
            "Node keys loaded successfully from device keystore"
        );

        // Create Runar node configuration using production constructor
        let runar_config = self.create_runar_config(&config, node_key_manager)?;

        // Create and start the node
        let node = Node::new(runar_config)
            .await
            .context("Failed to create Runar node")?;

        log_info!(self.logger, "Runar node created successfully");

        // Start the node
        node.start().await.context("Failed to start Runar node")?;

        log_info!(self.logger, "Runar node started successfully");
        println!("🚀 Runar node is now running!");
        println!("📋 Node Information:");
        println!("   • Node ID: {}", config.node_id);
        println!("   • Default Network: {}", config.default_network_id);
        println!("   • Persistence Dir: {:?}", config.persistence_dir);
        println!();
        println!("📱 The node is ready to accept connections from mobile devices");
        println!("🛑 Press Ctrl+C to stop the node");

        // Wait for shutdown signal
        self.wait_for_shutdown(&node).await?;

        Ok(())
    }

    fn load_configuration(&self, config_path: Option<PathBuf>) -> Result<CliNodeConfig> {
        let config_dir = config_path
            .map(|p| p.parent().unwrap_or(&self.config_dir).to_path_buf())
            .unwrap_or(self.config_dir.clone());

        CliNodeConfig::load(&config_dir)
            .with_context(|| format!("Failed to load configuration from {config_dir:?}"))
    }

    fn load_node_keys(&self, config: &CliNodeConfig) -> Result<NodeKeyManager> {
        // Create NodeKeyManager with new approach
        let logger = Arc::new(Logger::new_root(Component::Keys));
        let mut node_key_manager = NodeKeyManager::new(logger)?;

        // Configure persistence directory
        node_key_manager.set_persistence_dir(config.persistence_dir.clone());

        // Register device keystore (OS integration)
        let device_keystore = create_device_keystore_for_platform()
            .context("Failed to create device keystore for platform")?;
        node_key_manager.register_device_keystore(device_keystore);

        // Try to load existing state using new API
        let state_loaded = node_key_manager
            .probe_and_load_state()
            .context("Failed to probe and load state")?;

        if state_loaded {
            log_info!(
                self.logger,
                "Loaded existing node keys from device keystore"
            );
            Ok(node_key_manager)
        } else {
            Err(anyhow::anyhow!(
                "Node not initialized - run 'runar init' first"
            ))
        }
    }

    fn create_runar_config(
        &self,
        config: &CliNodeConfig,
        node_key_manager: NodeKeyManager,
    ) -> Result<NodeConfig> {
        // Create Runar node configuration using the new approach
        let mut runar_config = NodeConfig::new(config.default_network_id.clone());
        runar_config = runar_config
            .with_additional_networks(config.network_ids.clone())
            .with_request_timeout(config.request_timeout_ms)
            .with_key_manager(Arc::new(RwLock::new(node_key_manager)));

        Ok(runar_config)
    }

    async fn wait_for_shutdown(&self, node: &Node) -> Result<()> {
        // Set up signal handling for graceful shutdown (cross-platform)
        let ctrl_c = ctrl_c();
        ctrl_c
            .await
            .context("Failed to create shutdown signal handler")?;

        log_info!(self.logger, "Shutdown signal received - stopping node...");

        // Stop the node gracefully
        node.stop().await.context("Failed to stop Runar node")?;

        log_info!(self.logger, "Runar node stopped successfully");
        println!("🛑 Runar node stopped");

        Ok(())
    }
}
