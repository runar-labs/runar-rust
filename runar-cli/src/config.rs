//! Configuration management for Runar CLI
//!
//! This module handles loading, saving, and managing node configuration files.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string_pretty};
use std::path::Path;
use uuid::Uuid;

/// Node configuration stored in the config file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Unique identifier for this node
    pub node_id: String,

    /// Default network ID this node belongs to
    pub default_network_id: String,

    /// Additional network IDs this node participates in
    pub network_ids: Vec<String>,

    /// Keys name for OS key store (format: runar_{uuid})
    pub keys_name: String,

    /// Node public key (for reference)
    pub node_public_key: String,

    /// Setup server configuration
    pub setup_server: SetupServerConfig,

    /// Request timeout in milliseconds
    pub request_timeout_ms: u64,
}

/// Setup server configuration for QR code generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupServerConfig {
    /// IP address for setup server
    pub ip: String,

    /// Port for setup server
    pub port: u16,
}

impl Default for SetupServerConfig {
    fn default() -> Self {
        Self {
            ip: "127.0.0.1".to_string(),
            port: 8080,
        }
    }
}

impl NodeConfig {
    /// Create a new node configuration
    pub fn new(
        node_id: String,
        default_network_id: String,
        node_public_key: String,
        setup_server: SetupServerConfig,
    ) -> Self {
        let keys_name = format!("runar_{}", Uuid::new_v4());

        Self {
            node_id,
            default_network_id,
            network_ids: Vec::new(),
            keys_name,
            node_public_key,
            setup_server,
            request_timeout_ms: 30000, // 30 seconds
        }
    }

    /// Load configuration from file
    pub fn load(config_dir: &Path) -> Result<Self> {
        let config_file = config_dir.join("config.json");

        if !config_file.exists() {
            return Err(anyhow::anyhow!(
                "Configuration file not found: {:?}",
                config_file
            ));
        }

        let config_content = std::fs::read_to_string(&config_file)
            .with_context(|| format!("Failed to read config file: {config_file:?}"))?;

        let config: NodeConfig = from_str(&config_content)
            .with_context(|| format!("Failed to parse config file: {config_file:?}"))?;

        Ok(config)
    }

    /// Save configuration to file
    pub fn save(&self, config_dir: &Path) -> Result<()> {
        let config_file = config_dir.join("config.json");

        let config_content = to_string_pretty(self).context("Failed to serialize config")?;

        std::fs::write(&config_file, config_content)
            .with_context(|| format!("Failed to write config file: {config_file:?}"))?;

        Ok(())
    }

    /// Check if configuration exists
    pub fn exists(config_dir: &Path) -> bool {
        config_dir.join("config.json").exists()
    }
}
