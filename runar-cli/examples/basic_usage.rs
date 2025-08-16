//! Basic usage example for the Runar CLI
//!
//! This example demonstrates how to use the CLI programmatically.

use anyhow::Result;
use runar_cli::{InitCommand, NodeConfig, StartCommand};
use runar_common::logging::{Component, Logger};
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    // Create a temporary directory for this example
    let temp_dir = TempDir::new()?;
    let config_dir = temp_dir.path().to_path_buf();

    println!("📁 Using temporary config directory: {config_dir:?}");

    // Create logger
    let logger = Arc::new(Logger::new_root(Component::CLI));

    // Example 1: Create a configuration manually
    println!("\n🔧 Example 1: Creating configuration manually");

    let config = NodeConfig::new(
        "example_node".to_string(),
        "example_network".to_string(),
        "example_public_key_123".to_string(),
        runar_cli::config::SetupServerConfig::default(),
    );

    config.save(&config_dir)?;
    println!("✅ Configuration saved");

    // Example 2: Load configuration
    println!("\n📖 Example 2: Loading configuration");

    let loaded_config = NodeConfig::load(&config_dir)?;
    println!("✅ Configuration loaded:");
    println!("   Node ID: {}", loaded_config.node_id);
    println!("   Network: {}", loaded_config.default_network_id);
    println!("   Keys Name: {}", loaded_config.keys_name);

    // Example 3: Check if configuration exists
    println!("\n🔍 Example 3: Checking configuration existence");

    if NodeConfig::exists(&config_dir) {
        println!("✅ Configuration exists");
    } else {
        println!("❌ Configuration does not exist");
    }

    // Example 4: Create command instances
    println!("\n🚀 Example 4: Creating command instances");

    let _init_cmd = InitCommand::new(config_dir.clone(), logger.clone());
    let _start_cmd = StartCommand::new(config_dir, logger);

    println!("✅ InitCommand and StartCommand created successfully");

    println!("\n🎉 Basic CLI usage example completed!");
    println!("📝 Note: This example only demonstrates the API - actual node initialization");
    println!("   would require a mobile device to complete the certificate exchange.");

    Ok(())
}
