// Logging Configuration
//
// This module provides configuration options for logging in the Runar system.

use env_logger::{Builder, TimestampPrecision};
use log::LevelFilter;

/// Logging configuration options
#[derive(Clone, Debug)]
pub struct LoggingConfig {
    /// Default log level for all runar modules
    pub default_level: LogLevel,
}

// Components are only used for adding context to log messages, not for filtering

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
    /// Convert to LevelFilter
    pub fn to_level_filter(&self) -> LevelFilter {
        match self {
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
            LogLevel::Off => LevelFilter::Off,
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
            default_level: LogLevel::Error,
        }
    }

    /// Create a default logging configuration with Info level for all runar modules
    pub fn default_info() -> Self {
        Self {
            default_level: LogLevel::Info,
        }
    }

    /// Set the default log level for all runar modules
    pub fn with_default_level(mut self, level: LogLevel) -> Self {
        self.default_level = level;
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
        let mut builder = Builder::new();

        // Disable reading from environment variables
        builder.parse_default_env();

        // Customize the log format to remove module path and simplify output
        builder.format_module_path(false);
        builder.format_target(false);
        builder.format_timestamp(Some(TimestampPrecision::Millis));

        // Set the default level to Error to suppress external libraries
        builder.filter_level(LogLevel::Error.to_level_filter());

        // Component-specific levels are not used for filtering
        // Components are only for adding context to log messages

        // Always allow our runar modules to use the specified default level
        // This ensures that when default_level is set, it applies to all runar_* modules
        if self.default_level != LogLevel::Error {
            builder.filter(Some("runar_"), self.default_level.to_level_filter());
            builder.filter(Some("runar_node"), self.default_level.to_level_filter());
            builder.filter(Some("runar_keys"), self.default_level.to_level_filter());
            builder.filter(
                Some("runar_transporter"),
                self.default_level.to_level_filter(),
            );
            builder.filter(
                Some("runar_serializer"),
                self.default_level.to_level_filter(),
            );
            builder.filter(Some("runar_common"), self.default_level.to_level_filter());
            builder.filter(Some("runar_ffi"), self.default_level.to_level_filter());
            builder.filter(Some("runar_logging"), self.default_level.to_level_filter());
            builder.filter(Some("runar_macros"), self.default_level.to_level_filter());
            builder.filter(Some("runar_schemas"), self.default_level.to_level_filter());
            builder.filter(Some("runar_services"), self.default_level.to_level_filter());
            builder.filter(Some("runar_gateway"), self.default_level.to_level_filter());
        }

        // Keep external libraries at Info level to avoid verbose logs
        builder.filter(Some("quinn"), LogLevel::Info.to_level_filter());
        builder.filter(Some("quinn::"), LogLevel::Info.to_level_filter());
        builder.filter(Some("quinn_proto"), LogLevel::Info.to_level_filter());
        builder.filter(Some("quinn_udp"), LogLevel::Info.to_level_filter());
        builder.filter(Some("rustls"), LogLevel::Info.to_level_filter());
        builder.filter(Some("rustls::"), LogLevel::Info.to_level_filter());
        builder.filter(Some("tokio"), LogLevel::Info.to_level_filter());
        builder.filter(Some("tokio::"), LogLevel::Info.to_level_filter());
        builder.filter(Some("hyper"), LogLevel::Info.to_level_filter());
        builder.filter(Some("hyper::"), LogLevel::Info.to_level_filter());

        // Try to initialize the global logger, but don't panic if it's already initialized
        // This is especially important for tests where multiple tests might try to initialize the logger
        let _ = builder.try_init();
    }
}
