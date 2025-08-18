//! Basic tests for the Runar CLI

use runar_cli::{InitCommand, NodeConfig, StartCommand};
use runar_common::logging::{Component, Logger};

use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test]
async fn test_config_creation() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_dir = temp_dir.path().to_path_buf();

    let config = NodeConfig::new(
        "test_node".to_string(),
        "test_network".to_string(),
        "test_public_key".to_string(),
        runar_cli::config::SetupServerConfig::default(),
    );

    // Test saving and loading config
    config.save(&config_dir).expect("Failed to save config");
    let loaded_config = NodeConfig::load(&config_dir).expect("Failed to load config");

    assert_eq!(config.node_id, loaded_config.node_id);
    assert_eq!(config.default_network_id, loaded_config.default_network_id);
    assert_eq!(config.node_public_key, loaded_config.node_public_key);
}

#[tokio::test]
async fn test_init_command_creation() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_dir = temp_dir.path().to_path_buf();
    let logger = Arc::new(Logger::new_root(Component::CLI));

    let _init_cmd = InitCommand::new(config_dir, logger);

    // Just test that the command can be created
}

#[tokio::test]
async fn test_start_command_creation() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_dir = temp_dir.path().to_path_buf();
    let logger = Arc::new(Logger::new_root(Component::CLI));

    let _start_cmd = StartCommand::new(config_dir, logger);

    // Just test that the command can be created
}

#[test]
fn test_config_exists_check() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let config_dir = temp_dir.path().to_path_buf();

    // Should not exist initially
    assert!(!NodeConfig::exists(&config_dir));

    // Create a config
    let config = NodeConfig::new(
        "test_node".to_string(),
        "test_network".to_string(),
        "test_public_key".to_string(),
        runar_cli::config::SetupServerConfig::default(),
    );
    config.save(&config_dir).expect("Failed to save config");

    // Should exist now
    assert!(NodeConfig::exists(&config_dir));
}
