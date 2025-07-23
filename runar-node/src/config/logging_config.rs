// Logging Configuration
//
// This module provides configuration options for logging in the Runar system.

use runar_common::logging::Component;
use std::collections::HashMap;

/// Logging configuration options
#[derive(Clone, Debug)]
pub struct LoggingConfig {
    /// Default log level for all components
    pub default_level: LogLevel,
    /// Component-specific log levels
    pub component_levels: HashMap<ComponentKey, LogLevel>,
}

/// Component key for logging configuration
/// This provides Hash and Eq implementations for identifying components
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ComponentKey {
    Node,
    Registry,
    Service,
    Database,
    Network,
    System,
    Custom(String),
}

impl From<Component> for ComponentKey {
    fn from(component: Component) -> Self {
        match component {
            Component::Node => ComponentKey::Node,
            Component::Registry => ComponentKey::Registry,
            Component::Service => ComponentKey::Service,
            Component::Database => ComponentKey::Database,
            Component::Transporter => ComponentKey::Network,
            Component::System => ComponentKey::System,
            Component::NetworkDiscovery => ComponentKey::Network,
            Component::Custom(name) => ComponentKey::Custom(name.to_string()),
            Component::CLI => ComponentKey::Custom("CLI".to_string()),
            Component::Keys => ComponentKey::Custom("Keys".to_string()),
        }
    }
}

/// Log levels matching standard Rust log crate levels
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
    Off,
}

impl LogLevel {
    /// Convert to log::LevelFilter
    pub fn to_level_filter(&self) -> log::LevelFilter {
        match self {
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Trace => log::LevelFilter::Trace,
            LogLevel::Off => log::LevelFilter::Off,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl LoggingConfig {
    /// Create a new logging configuration with default settings
    pub fn new() -> Self {
        Self {
            default_level: LogLevel::Info,
            component_levels: HashMap::new(),
        }
    }

    /// Create a default logging configuration with Info level for all components
    pub fn default_info() -> Self {
        Self::new()
    }

    /// Set the default log level
    pub fn with_default_level(mut self, level: LogLevel) -> Self {
        self.default_level = level;
        self
    }

    /// Set a log level for a specific component
    pub fn with_component_level(mut self, component: Component, level: LogLevel) -> Self {
        self.component_levels.insert(component.into(), level);
        self
    }

    /// Apply this logging configuration
    ///
    /// INTENTION: Configure the global logger solely based on the settings in this
    /// LoggingConfig object. Ignore all environment variables.
    ///
    /// Note: If the logger is already initialized, this method will silently return
    /// without doing anything to avoid panics in test environments where multiple
    /// tests might try to initialize the logger.
    pub fn apply(&self) {
        // Create a new env_logger builder
        let mut builder = env_logger::Builder::new();

        // Disable reading from environment variables
        builder.parse_default_env();

        // Set the default level
        builder.filter_level(self.default_level.to_level_filter());

        // Apply component-specific levels
        for (component, level) in &self.component_levels {
            let target = match component {
                ComponentKey::Node => "runar_node",
                ComponentKey::Registry => "runar_node::services::registry",
                ComponentKey::Service => "runar_node::services",
                ComponentKey::Database => "runar_node::database",
                ComponentKey::Network => "runar_node::network",
                ComponentKey::System => "runar_node::system",
                ComponentKey::Custom(name) => name,
            };

            builder.filter(Some(target), level.to_level_filter());
        }

        // Try to initialize the global logger, but don't panic if it's already initialized
        // This is especially important for tests where multiple tests might try to initialize the logger
        let _ = builder.try_init();
    }
}
