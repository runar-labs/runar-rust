// Configuration Module
//
// This module provides configuration options for the Runar system, including
// logging configuration and network settings.
//
// ## Components
//
// - **Logging Configuration**: Configurable log levels, formats, and destinations
// - **Network Configuration**: Network transport and discovery settings
// - **Node Configuration**: Node-specific settings and behavior
//
// ## Examples
//
// ```rust
// use runar_node::config::{LoggingConfig, LogLevel};
//
// // Configure logging
// let logging = LoggingConfig::new()
//     .with_level(LogLevel::Debug)
//     .with_timestamp(true);
//
// // Use in node configuration
// let config = NodeConfig::new("my-node", "my-network")
//     .with_logging_config(logging);
// ```

// Re-export configuration types from runar_common::logging
pub use runar_common::logging::{ComponentKey, LogLevel, LoggingConfig};
