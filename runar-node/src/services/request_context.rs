// RequestContext Module
//
// INTENTION:
// This module provides the implementation of RequestContext, which encapsulates
// all contextual information needed to process service requests, including
// network identity, service path, and metadata.
//
// ARCHITECTURAL PRINCIPLE:
// Each request should have its own isolated context that moves with the
// request through the entire processing pipeline, ensuring proper tracing
// and consistent handling. The context avoids data duplication by
// deriving values from the TopicPath when needed.

use crate::node::Node; // Added for concrete type
use crate::routing::TopicPath;
use crate::services::NodeDelegate;
use anyhow::Result;
use runar_common::{
    logging::{Component, Logger, LoggingContext},
    types::ArcValue,   // Added ValueCategory for AsArcValue for S
    types::AsArcValue, // Moved from this file
};
use std::fmt::Debug;

// AsArcValue trait and implementations moved to runar_common::types
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------

use std::{collections::HashMap, fmt, sync::Arc};

/// Context for handling service requests
///
/// INTENTION: Encapsulate all contextual information needed to process
/// a service request, including network identity, service path, and metadata.
/// This ensures consistent request processing and proper logging.
///
/// The RequestContext is immutable and is passed with each request to provide:
/// - Network isolation (via network_id derived from topic_path)
/// - Service targeting (via service_path derived from topic_path)
/// - Request metadata and contextual information
/// - Logging capabilities with consistent context
///
/// ARCHITECTURAL PRINCIPLE:
/// Each request should have its own isolated context that moves with the
/// request through the entire processing pipeline, ensuring proper tracing
/// and consistent handling.
pub struct RequestContext {
    /// Complete topic path for this request (optional) - includes service path and action
    pub topic_path: TopicPath,
    /// Metadata for this request - additional contextual information
    pub metadata: Option<ArcValue>,
    /// Logger for this context - pre-configured with the appropriate component and path
    pub logger: Arc<Logger>,
    /// Path parameters extracted from template matching
    pub path_params: HashMap<String, String>,

    /// Node delegate for making requests or publishing events
    pub(crate) node_delegate: Arc<Node>,
}

// Manual implementation of Debug for RequestContext
impl fmt::Debug for RequestContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestContext")
            .field("network_id", &self.network_id())
            .field("service_path", &self.service_path())
            .field("topic_path", &self.topic_path)
            .field("metadata", &self.metadata)
            .field("logger", &"<Logger>") // Avoid trying to Debug the Logger
            .field("path_params", &self.path_params)
            .finish()
    }
}

// Manual implementation of Clone for RequestContext
impl Clone for RequestContext {
    fn clone(&self) -> Self {
        Self {
            topic_path: self.topic_path.clone(),
            metadata: self.metadata.clone(),
            logger: self.logger.clone(),
            path_params: self.path_params.clone(),
            node_delegate: self.node_delegate.clone(),
        }
    }
}

// Manual implementation of Default for RequestContext
impl Default for RequestContext {
    fn default() -> Self {
        panic!("RequestContext should not be created with default. Use new instead");
    }
}

/// Constructors follow the builder pattern principle:
/// - Prefer a single primary constructor with required parameters
/// - Use builder methods for optional parameters
/// - Avoid creating specialized constructors for every parameter combination
impl RequestContext {
    /// Create a new RequestContext with a TopicPath and logger
    ///
    /// This is the primary constructor that takes the minimum required parameters.
    pub fn new(topic_path: &TopicPath, node_delegate: Arc<Node>, logger: Arc<Logger>) -> Self {
        // Add action path to logger if available from topic_path
        let action_path = topic_path.action_path();
        let action_logger = if !action_path.is_empty() {
            // If there's an action path, add it to the logger
            Arc::new(logger.with_action_path(action_path))
        } else {
            logger
        };

        Self {
            topic_path: topic_path.clone(),
            metadata: None,
            logger: action_logger,
            node_delegate,
            path_params: HashMap::new(),
        }
    }

    /// Add metadata to a RequestContext
    ///
    /// Use builder-style methods instead of specialized constructors.
    pub fn with_metadata(mut self, metadata: ArcValue) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Get the network ID from the topic path
    pub fn network_id(&self) -> String {
        self.topic_path.network_id()
    }

    /// Get the service path from the topic path
    pub fn service_path(&self) -> String {
        self.topic_path.service_path()
    }

    /// Helper method to log debug level message
    ///
    /// INTENTION: Provide a convenient way to log debug messages with the
    /// context's logger, without having to access the logger directly.
    pub fn debug(&self, message: impl Into<String>) {
        self.logger.debug(message);
    }

    /// Helper method to log info level message
    ///
    /// INTENTION: Provide a convenient way to log info messages with the
    /// context's logger, without having to access the logger directly.
    pub fn info(&self, message: impl Into<String>) {
        self.logger.info(message);
    }

    /// Helper method to log warning level message
    ///
    /// INTENTION: Provide a convenient way to log warning messages with the
    /// context's logger, without having to access the logger directly.
    pub fn warn(&self, message: impl Into<String>) {
        self.logger.warn(message);
    }

    /// Helper method to log error level message
    ///
    /// INTENTION: Provide a convenient way to log error messages with the
    /// context's logger, without having to access the logger directly.
    pub fn error(&self, message: impl Into<String>) {
        self.logger.error(message);
    }

    /// Publish an event
    ///
    /// INTENTION: Allow event handlers to publish their own events.
    /// This method provides a convenient way to publish events from within
    /// an event handler.
    ///
    /// Handles different path formats:
    /// - Full path with network ID: "network:service/topic" (used as is)
    /// - Path with service: "service/topic" (network ID added)
    /// - Simple topic: "topic" (both service path and network ID added)
    pub async fn publish(&self, topic: impl Into<String>, data: Option<ArcValue>) -> Result<()> {
        let topic_string = topic.into();

        // Process the topic based on its format
        let full_topic = if topic_string.contains(':') {
            // Already has network ID, use as is
            topic_string
        } else if topic_string.contains('/') {
            // Has service/topic but no network ID
            format!("{}:{}", self.topic_path.network_id(), topic_string)
        } else {
            // Simple topic name - add service path and network ID
            format!(
                "{}:{}/{}",
                self.topic_path.network_id(),
                self.topic_path.service_path(),
                topic_string
            )
        };

        self.logger
            .debug(format!("Publishing to processed topic: {full_topic}"));
        self.node_delegate.publish(full_topic, data).await
    }

    /// Make a service request
    ///
    /// INTENTION: Allow event handlers to make requests to other services.
    /// This method provides a convenient way to call service actions from
    /// within an event handler.
    ///
    /// Handles different path formats:
    /// - Full path with network ID: "network:service/action" (used as is)
    /// - Path with service: "service/action" (network ID added)
    /// - Simple action: "action" (both service path and network ID added - calls own service)
    pub async fn request<P, T>(&self, path: impl Into<String>, payload: Option<P>) -> Result<T>
    where
        P: AsArcValue + Send + Sync,
        T: 'static + Send + Sync + Clone + Debug + for<'de> serde::Deserialize<'de>,
    {
        let path_string = path.into();

        // Process the path based on its format
        let full_path = if path_string.contains(':') {
            // Already has network ID, use as is
            path_string
        } else if path_string.contains('/') {
            // Has service/action but no network ID
            format!("{}:{}", self.topic_path.network_id(), path_string)
        } else {
            // Simple action name - add both service path and network ID
            format!(
                "{}:{}/{}",
                self.topic_path.network_id(),
                self.topic_path.service_path(),
                path_string
            )
        };

        self.logger
            .debug(format!("Making request to processed path: {full_path}"));

        // Call Node::request, specifying the generic types P and T.
        // Node::request itself will handle deserialization to T.
        self.node_delegate.request::<P, T>(full_path, payload).await
    }
}

impl LoggingContext for RequestContext {
    fn component(&self) -> Component {
        Component::Service
    }

    fn service_path(&self) -> Option<&str> {
        let path = self.topic_path.service_path();
        Some(Box::leak(path.into_boxed_str()))
    }

    fn action_path(&self) -> Option<&str> {
        let path = self.topic_path.action_path();
        Some(Box::leak(path.into_boxed_str()))
    }

    fn logger(&self) -> &Logger {
        &self.logger
    }
}
