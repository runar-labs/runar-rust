// Logging utilities for the Runar system
//
// This module provides a comprehensive logging system with:
// - Compile-time efficient macros
// - Component-based structured logging
// - Context-aware logging for services
// - Node ID tracking through logger inheritance
// - Support for action and event path tracing

use log::{debug, error, info, warn};
use std::fmt::{self, Arguments, Display, Formatter};

/// Predefined components for logging categorization
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Component {
    Node,
    Registry,
    Service,
    Database,
    Transporter,
    NetworkDiscovery,
    System,
    CLI,
    Keys,
    Custom(&'static str),
}

// Lightweight Display helpers to avoid prefix String allocations
struct ComponentPrefixDisplay {
    parent: Option<Component>,
    component: Component,
}
impl Display for ComponentPrefixDisplay {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.parent {
            Some(parent) if parent != Component::Node => {
                write!(f, "{}.{}", parent.as_str(), self.component.as_str())
            }
            _ => write!(f, "{}", self.component.as_str()),
        }
    }
}

struct MaybeActionDisplay<'a>(Option<&'a str>);
impl Display for MaybeActionDisplay<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(path) = self.0 {
            write!(f, "|action={path}")
        } else {
            Ok(())
        }
    }
}

struct MaybeEventDisplay<'a>(Option<&'a str>);
impl Display for MaybeEventDisplay<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(path) = self.0 {
            write!(f, "|event={path}")
        } else {
            Ok(())
        }
    }
}

impl Component {
    /// Get the string representation of the component
    pub fn as_str(&self) -> &str {
        match self {
            Component::Node => "Node",
            Component::Registry => "Registry",
            Component::Service => "Service",
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
    /// Node ID for distributed tracing
    node_id: String,
    /// Parent component for hierarchical logging (if any)
    parent_component: Option<Component>,
    /// Action path for request/action tracing
    action_path: Option<String>,
    /// Event path for event subscription tracing
    event_path: Option<String>,
}

impl Logger {
    /// Create a new root logger for a specific component and node ID
    /// This should only be called by the Node root component
    pub fn new_root(component: Component, node_id: &str) -> Self {
        Self {
            component,
            node_id: node_id.to_string(),
            parent_component: None,
            action_path: None,
            event_path: None,
        }
    }

    /// Create a child logger with the same node ID but different component
    /// This is the preferred way to create loggers in services and other components
    pub fn with_component(&self, component: Component) -> Self {
        Self {
            component,
            node_id: self.node_id.clone(),
            parent_component: Some(self.component),
            action_path: self.action_path.clone(),
            event_path: self.event_path.clone(),
        }
    }

    /// Create a logger with an action path
    /// This is used to track action requests through the system
    pub fn with_action_path(&self, path: impl Into<String>) -> Self {
        Self {
            component: self.component,
            node_id: self.node_id.clone(),
            parent_component: self.parent_component,
            action_path: Some(path.into()),
            event_path: self.event_path.clone(),
        }
    }

    /// Create a logger with an event path
    /// This is used to track event publications and subscriptions
    pub fn with_event_path(&self, path: impl Into<String>) -> Self {
        Self {
            component: self.component,
            node_id: self.node_id.clone(),
            parent_component: self.parent_component,
            action_path: self.action_path.clone(),
            event_path: Some(path.into()),
        }
    }

    /// Clone this logger with the same settings
    /// This is useful when you need to pass a logger to a component that might modify it
    pub fn clone_logger(&self) -> Self {
        self.clone()
    }

    /// Get a reference to the node ID
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Get a reference to the action path if available
    pub fn action_path(&self) -> Option<&str> {
        self.action_path.as_deref()
    }

    /// Get a reference to the event path if available
    pub fn event_path(&self) -> Option<&str> {
        self.event_path.as_deref()
    }

    /// Get the component prefix for logging, including parent if available
    fn component_prefix(&self) -> String {
        match self.parent_component {
            Some(parent) if parent != Component::Node => {
                format!("{}.{}", parent.as_str(), self.component.as_str())
            }
            _ => self.component.as_str().to_string(),
        }
    }

    /// Get the full prefix including component, action path, and event path
    fn full_prefix(&self) -> String {
        let mut parts = Vec::new();

        // Add component prefix
        parts.push(self.component_prefix());

        // Add action path if available
        if let Some(path) = &self.action_path {
            parts.push(format!("action={path}"));
        }

        // Add event path if available
        if let Some(path) = &self.event_path {
            parts.push(format!("event={path}"));
        }

        parts.join("|")
    }

    /// Log a debug message
    pub fn debug(&self, message: impl Into<String>) {
        if log::log_enabled!(log::Level::Debug) {
            // Skip displaying the component if it's Node to avoid redundancy
            if self.component == Component::Node && self.parent_component.is_none() {
                debug!("[{}] {}", self.node_id, message.into());
            } else {
                debug!(
                    "[{}][{}] {}",
                    self.node_id,
                    self.full_prefix(),
                    message.into()
                );
            }
        }
    }

    /// Log a debug message using fmt::Arguments (avoids allocating message String)
    pub fn debug_args(&self, args: Arguments) {
        if log::log_enabled!(log::Level::Debug) {
            if self.component == Component::Node && self.parent_component.is_none() {
                debug!("[{}] {}", self.node_id, args);
            } else {
                debug!(
                    "[{}][{}{}{}] {}",
                    self.node_id,
                    ComponentPrefixDisplay {
                        parent: self.parent_component,
                        component: self.component
                    },
                    MaybeActionDisplay(self.action_path()),
                    MaybeEventDisplay(self.event_path()),
                    args
                );
            }
        }
    }

    /// Log an info message
    pub fn info(&self, message: impl Into<String>) {
        if log::log_enabled!(log::Level::Info) {
            // Skip displaying the component if it's Node to avoid redundancy
            if self.component == Component::Node && self.parent_component.is_none() {
                info!("[{}] {}", self.node_id, message.into());
            } else {
                info!(
                    "[{}][{}] {}",
                    self.node_id,
                    self.full_prefix(),
                    message.into()
                );
            }
        }
    }

    /// Log an info message using fmt::Arguments (avoids allocating message String)
    pub fn info_args(&self, args: Arguments) {
        if log::log_enabled!(log::Level::Info) {
            if self.component == Component::Node && self.parent_component.is_none() {
                info!("[{}] {}", self.node_id, args);
            } else {
                info!(
                    "[{}][{}{}{}] {}",
                    self.node_id,
                    ComponentPrefixDisplay {
                        parent: self.parent_component,
                        component: self.component
                    },
                    MaybeActionDisplay(self.action_path()),
                    MaybeEventDisplay(self.event_path()),
                    args
                );
            }
        }
    }

    /// Log a static info message without allocation
    pub fn info_static(&self, msg: &'static str) {
        if log::log_enabled!(log::Level::Info) {
            if self.component == Component::Node && self.parent_component.is_none() {
                info!("[{}] {}", self.node_id, msg);
            } else {
                info!(
                    "[{}][{}{}{}] {}",
                    self.node_id,
                    ComponentPrefixDisplay {
                        parent: self.parent_component,
                        component: self.component
                    },
                    MaybeActionDisplay(self.action_path()),
                    MaybeEventDisplay(self.event_path()),
                    msg
                );
            }
        }
    }

    /// Log a warning message
    pub fn warn(&self, message: impl Into<String>) {
        if log::log_enabled!(log::Level::Warn) {
            // Skip displaying the component if it's Node to avoid redundancy
            if self.component == Component::Node && self.parent_component.is_none() {
                warn!("[{}] {}", self.node_id, message.into());
            } else {
                warn!(
                    "[{}][{}] {}",
                    self.node_id,
                    self.full_prefix(),
                    message.into()
                );
            }
        }
    }

    /// Log a warning using fmt::Arguments
    pub fn warn_args(&self, args: Arguments) {
        if log::log_enabled!(log::Level::Warn) {
            if self.component == Component::Node && self.parent_component.is_none() {
                warn!("[{}] {}", self.node_id, args);
            } else {
                warn!(
                    "[{}][{}{}{}] {}",
                    self.node_id,
                    ComponentPrefixDisplay {
                        parent: self.parent_component,
                        component: self.component
                    },
                    MaybeActionDisplay(self.action_path()),
                    MaybeEventDisplay(self.event_path()),
                    args
                );
            }
        }
    }

    /// Log an error message
    pub fn error(&self, message: impl Into<String>) {
        if log::log_enabled!(log::Level::Error) {
            // Skip displaying the component if it's Node to avoid redundancy
            if self.component == Component::Node && self.parent_component.is_none() {
                error!("[{}] {}", self.node_id, message.into());
            } else {
                error!(
                    "[{}][{}] {}",
                    self.node_id,
                    self.full_prefix(),
                    message.into()
                );
            }
        }
    }

    /// Log an error using fmt::Arguments
    pub fn error_args(&self, args: Arguments) {
        if log::log_enabled!(log::Level::Error) {
            if self.component == Component::Node && self.parent_component.is_none() {
                error!("[{}] {}", self.node_id, args);
            } else {
                error!(
                    "[{}][{}{}{}] {}",
                    self.node_id,
                    ComponentPrefixDisplay {
                        parent: self.parent_component,
                        component: self.component
                    },
                    MaybeActionDisplay(self.action_path()),
                    MaybeEventDisplay(self.event_path()),
                    args
                );
            }
        }
    }
}

/// Logging context for structured logging with additional context
pub trait LoggingContext {
    /// Get the component
    fn component(&self) -> Component;

    /// Get the service path or identifier
    fn service_path(&self) -> Option<&str>;

    /// Get the action path if available
    fn action_path(&self) -> Option<&str> {
        None
    }

    /// Get the event path if available
    fn event_path(&self) -> Option<&str> {
        None
    }

    /// Get the logger
    fn logger(&self) -> &Logger;

    /// Log at debug level
    fn log_debug(&self, message: String) {
        if log::log_enabled!(log::Level::Debug) {
            let prefix = self.log_prefix();
            let logger = self.logger();

            // Skip displaying the component if it's Node to avoid redundancy
            if self.component() == Component::Node && prefix == "Node" {
                debug!("[{}] {}", logger.node_id(), message);
            } else {
                debug!("[{}][{}] {}", logger.node_id(), prefix, message);
            }
        }
    }

    /// Log at info level
    fn log_info(&self, message: String) {
        if log::log_enabled!(log::Level::Info) {
            let prefix = self.log_prefix();
            let logger = self.logger();

            // Skip displaying the component if it's Node to avoid redundancy
            if self.component() == Component::Node && prefix == "Node" {
                info!("[{}] {}", logger.node_id(), message);
            } else {
                info!("[{}][{}] {}", logger.node_id(), prefix, message);
            }
        }
    }

    /// Log at warning level
    fn log_warn(&self, message: String) {
        if log::log_enabled!(log::Level::Warn) {
            let prefix = self.log_prefix();
            let logger = self.logger();

            // Skip displaying the component if it's Node to avoid redundancy
            if self.component() == Component::Node && prefix == "Node" {
                warn!("[{}] {}", logger.node_id(), message);
            } else {
                warn!("[{}][{}] {}", logger.node_id(), prefix, message);
            }
        }
    }

    /// Log at error level
    fn log_error(&self, message: String) {
        if log::log_enabled!(log::Level::Error) {
            let prefix = self.log_prefix();
            let logger = self.logger();

            // Skip displaying the component if it's Node to avoid redundancy
            if self.component() == Component::Node && prefix == "Node" {
                error!("[{}] {}", logger.node_id(), message);
            } else {
                error!("[{}][{}] {}", logger.node_id(), prefix, message);
            }
        }
    }

    /// Get the logging prefix
    fn log_prefix(&self) -> String {
        let mut parts = Vec::new();

        // Add component and service path
        match self.service_path() {
            Some(path) => parts.push(format!("{}:{}", self.component().as_str(), path)),
            None => parts.push(self.component().as_str().to_string()),
        }

        // Add action path if available
        if let Some(path) = self.action_path() {
            parts.push(format!("action={path}"));
        }

        // Add event path if available
        if let Some(path) = self.event_path() {
            parts.push(format!("event={path}"));
        }

        parts.join("|")
    }
}
