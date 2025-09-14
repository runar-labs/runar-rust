// Logging utilities for the Runar system
//
// This module provides a comprehensive logging system with:
// - Compile-time efficient macros
// - Component-based structured logging
// - Context-aware logging for services
// - Node ID tracking through logger inheritance
// - Support for action and event path tracing

use log::{debug, error, info, warn, Level};
use once_cell::sync::OnceCell;
use std::fmt::Arguments;

/// Predefined components for logging categorization
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Component {
    Node,
    Registry,
    Service,
    Event,
    Action,
    Database,
    Transporter,
    NetworkDiscovery,
    System,
    CLI,
    Keys,
    Custom(&'static str),
}

impl Component {
    /// Get the string representation of the component
    pub fn as_str(&self) -> &str {
        match self {
            Component::Node => "Node",
            Component::Registry => "Registry",
            Component::Service => "Service",
            Component::Event => "Event",
            Component::Action => "Action",
            Component::Database => "DB",
            Component::Transporter => "Network",
            Component::NetworkDiscovery => "NetworkDiscovery",
            Component::System => "System",
            Component::CLI => "CLI",
            Component::Keys => "Keys",
            Component::Custom(name) => name,
        }
    }
}

/// A helper for creating component-specific loggers with node ID tracking
#[derive(Clone)]
pub struct Logger {
    /// Component this logger is for
    component: Component,
    /// context for the logger
    context: OnceCell<String>,
    /// Parent context for hierarchical logging (if any)
    parent_context: Option<String>,
    //pre computed prefixes for performance
    full_component_prefix: String,
}

impl Logger {
    /// Create a new root logger for a specific component
    /// This should only be called by the Node root component
    pub fn new_root(component: Component) -> Self {
        Self {
            component,
            context: OnceCell::new(),
            parent_context: None,
            full_component_prefix: component.as_str().to_string(),
        }
    }

    pub fn set_context(&self, context: String) {
        let full_context_prefix: String;
        if let Some(parent_context) = self.parent_context.clone() {
            full_context_prefix = format!("{} {}", parent_context, context)
        } else {
            full_context_prefix = context
        }
        if self.context.set(full_context_prefix).is_err() {
            // This should never happen in normal usage
            warn!(
                "The context value of {context} was already set for this logger",
                context = self.context.get().map(|s| s.as_str()).unwrap_or("")
            );
        }
    }

    /// Create a child logger with the same node ID but different component
    /// This is the preferred way to create loggers in services and other components
    pub fn with_component(&self, component: Component) -> Self {
        Self {
            component,
            context: OnceCell::new(),
            parent_context: self.context.get().cloned(),
            full_component_prefix: format!("{} {}", self.component.as_str(), component.as_str()),
        }
    }

    fn full_context_prefix(&self) -> Option<String> {
        if let Some(context) = self.context.get() {
            Some(context.clone())
        } else if let Some(parent_context) = self.parent_context.clone() {
            Some(parent_context)
        } else {
            None
        }
    }

    /// Log a debug message
    pub fn debug(&self, message: impl Into<String>) {
        if log::log_enabled!(Level::Debug) {
            let component_prefix = &self.full_component_prefix;
            let context_prefix = self.full_context_prefix();
            if let Some(context_prefix) = context_prefix {
                debug!(
                    "[{} {}] {}",
                    component_prefix,
                    context_prefix,
                    message.into()
                );
            } else {
                debug!("[{}] {}", component_prefix, message.into());
            }
        }
    }

    /// Log a debug message using fmt::Arguments (avoids allocating message String)
    pub fn debug_args(&self, args: Arguments) {
        if log::log_enabled!(Level::Debug) {
            let component_prefix = &self.full_component_prefix;
            let context_prefix = self.full_context_prefix();
            if let Some(context_prefix) = context_prefix {
                debug!("[{} {}] {}", component_prefix, context_prefix, args);
            } else {
                debug!("[{}] {}", component_prefix, args);
            }
        }
    }

    /// Log an info message
    pub fn info(&self, message: impl Into<String>) {
        if log::log_enabled!(Level::Info) {
            let component_prefix = &self.full_component_prefix;
            let context_prefix = self.full_context_prefix();
            if let Some(context_prefix) = context_prefix {
                info!(
                    "[{} {}] {}",
                    component_prefix,
                    context_prefix,
                    message.into()
                );
            } else {
                info!("[{}] {}", component_prefix, message.into());
            }
        }
    }

    /// Log an info message using fmt::Arguments (avoids allocating message String)
    pub fn info_args(&self, args: Arguments) {
        if log::log_enabled!(Level::Info) {
            let component_prefix = &self.full_component_prefix;
            let context_prefix = self.full_context_prefix();
            if let Some(context_prefix) = context_prefix {
                info!("[{} {}] {}", component_prefix, context_prefix, args);
            } else {
                info!("[{}] {}", component_prefix, args);
            }
        }
    }

    /// Log a static info message without allocation
    pub fn info_static(&self, msg: &'static str) {
        if log::log_enabled!(Level::Info) {
            let component_prefix = &self.full_component_prefix;
            let context_prefix = self.full_context_prefix();
            if let Some(context_prefix) = context_prefix {
                info!("[{} {}] {}", component_prefix, context_prefix, msg);
            } else {
                info!("[{}] {}", component_prefix, msg);
            }
        }
    }

    /// Log a warning message
    pub fn warn(&self, message: impl Into<String>) {
        if log::log_enabled!(Level::Warn) {
            let component_prefix = &self.full_component_prefix;
            let context_prefix = self.full_context_prefix();
            if let Some(context_prefix) = context_prefix {
                warn!(
                    "[{} {}] {}",
                    component_prefix,
                    context_prefix,
                    message.into()
                );
            } else {
                warn!("[{}] {}", component_prefix, message.into());
            }
        }
    }

    /// Log a warning using fmt::Arguments
    pub fn warn_args(&self, args: Arguments) {
        if log::log_enabled!(Level::Warn) {
            let component_prefix = &self.full_component_prefix;
            let context_prefix = self.full_context_prefix();
            if let Some(context_prefix) = context_prefix {
                warn!("[{} {}] {}", component_prefix, context_prefix, args);
            } else {
                warn!("[{}] {}", component_prefix, args);
            }
        }
    }

    /// Log an error message
    pub fn error(&self, message: impl Into<String>) {
        if log::log_enabled!(Level::Error) {
            let component_prefix = &self.full_component_prefix;
            let context_prefix = self.full_context_prefix();
            if let Some(context_prefix) = context_prefix {
                error!(
                    "[{} {}] {}",
                    component_prefix,
                    context_prefix,
                    message.into()
                );
            } else {
                error!("[{}] {}", component_prefix, message.into());
            }
        }
    }

    /// Log an error using fmt::Arguments
    pub fn error_args(&self, args: Arguments) {
        if log::log_enabled!(Level::Error) {
            let component_prefix = &self.full_component_prefix;
            let context_prefix = self.full_context_prefix();
            if let Some(context_prefix) = context_prefix {
                error!("[{} {}] {}", component_prefix, context_prefix, args);
            } else {
                error!("[{}] {}", component_prefix, args);
            }
        }
    }
}

// Re-export logging configuration
pub mod config;
pub use config::{ComponentKey, LogLevel, LoggingConfig};
