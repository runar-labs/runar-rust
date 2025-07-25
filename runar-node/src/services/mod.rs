// Services Module
//
// INTENTION:
// This module defines the core service architecture components, interfaces, and types
// that form the foundation of the service-oriented architecture. It establishes
// the contracts between services, the node, and clients that use them.
//
// ARCHITECTURAL PRINCIPLES:
// 1. Service Isolation - Services are self-contained with clear boundaries
// 2. Request-Response Pattern - All service interactions follow a consistent
//    request-response pattern for predictability and simplicity
// 3. Contextual Logging - All operations include context for proper tracing
// 4. Network Isolation - Services operate within specific network boundaries
// 5. Event-Driven Communication - Services can publish and subscribe to events
//
// This module is the cornerstone of the system's service architecture, defining
// how services are structured, discovered, and interacted with.

// Module declarations
pub mod abstract_service;
pub mod event_context;
pub mod keys_service;
pub mod load_balancing;
pub mod registry_service;
pub mod remote_service;
pub mod request_context;
pub mod service_registry;

// Import necessary components
use crate::node::Node; // Added for concrete type Node
use crate::routing::TopicPath;
use anyhow::{anyhow, Result};
use runar_common::logging::{Component, Logger, LoggingContext};
use runar_schemas::{ActionMetadata, FieldSchema};
use runar_serializer::arc_value::AsArcValue;
use runar_serializer::ArcValue;
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

// Import types from submodules
use crate::services::abstract_service::ServiceState;
use crate::services::remote_service::RemoteService;
use runar_schemas::ServiceMetadata;

// Re-export the context types from their dedicated modules
pub use crate::services::event_context::EventContext;
pub use crate::services::request_context::RequestContext;

/// Handler for a service action
///
/// INTENTION: Define the signature for a function that handles a service action.
/// This provides a consistent interface for all action handlers and enables
/// them to be stored, passed around, and invoked uniformly.
pub type ActionHandler =
    Arc<dyn Fn(Option<ArcValue>, RequestContext) -> ServiceFuture + Send + Sync>;

/// Type for action registration function
pub type ActionRegistrar = Arc<
    dyn Fn(
            &TopicPath,
            ActionHandler,
            Option<ActionMetadata>,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

pub type EventCallback = Box<
    dyn Fn(Arc<EventContext>, Option<ArcValue>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

/// Context for service lifecycle management
///
/// INTENTION: Provide services with the context needed for lifecycle operations
/// such as initialization and shutdown. Includes access to the node for
/// registering action handlers, subscribing to events, and other operations.
#[derive(Clone)]
pub struct LifecycleContext {
    /// Network ID for the context
    pub network_id: String,
    /// Service path - identifies the service within the network
    pub service_path: String,
    /// Optional configuration data
    pub config: Option<ArcValue>,
    /// Logger instance with service context
    pub logger: Arc<Logger>,
    /// Node delegate for node operations
    node_delegate: Arc<Node>,
    // Removed serializer registry (no longer needed with redesigned serializer)
}

impl LifecycleContext {
    /// Create a new LifecycleContext with a topic path and logger
    ///
    /// This is the primary constructor that takes the minimum required parameters.
    pub fn new(topic_path: &TopicPath, node_delegate: Arc<Node>, logger: Arc<Logger>) -> Self {
        Self {
            network_id: topic_path.network_id(),
            service_path: topic_path.service_path(),
            config: None,
            logger,
            node_delegate,
            // Removed serializer registry (no longer needed with redesigned serializer)
        }
    }

    /// Add configuration to a LifecycleContext
    ///
    /// Use builder-style methods instead of specialized constructors.
    pub fn with_config(mut self, config: ArcValue) -> Self {
        self.config = Some(config);
        self
    }

    /// Helper method to log debug level message
    pub fn debug(&self, message: impl Into<String>) {
        self.logger.debug(message);
    }

    /// Helper method to log info level message
    pub fn info(&self, message: impl Into<String>) {
        self.logger.info(message);
    }

    /// Helper method to log warning level message
    pub fn warn(&self, message: impl Into<String>) {
        self.logger.warn(message);
    }

    /// Helper method to log error level message
    pub fn error(&self, message: impl Into<String>) {
        self.logger.error(message);
    }

    /// Make a service request from the lifecycle context.
    ///
    /// INTENTION: Allow services during their lifecycle (e.g., init, shutdown)
    /// to make requests to other services or their own actions.
    ///
    /// Handles different path formats:
    /// - Full path with network ID: "network:service/action" (used as is)
    /// - Path with service: "service/action" (current network ID added)
    /// - Simple action: "action" (current network ID and service path added - calls own service)
    pub async fn request<P>(&self, path: impl Into<String>, payload: Option<P>) -> Result<ArcValue>
    where
        P: AsArcValue + Send + Sync,
    {
        let path_string = path.into();
        let full_path = if path_string.contains(':') {
            path_string
        } else if path_string.contains('/') {
            format!("{0}:{1}", self.network_id, path_string)
        } else {
            format!(
                "{0}:{1}/{2}",
                self.network_id, self.service_path, path_string
            )
        };

        self.logger.debug(format!(
            "LifecycleContext making request to processed path: {full_path}"
        ));
        self.node_delegate.request::<P>(full_path, payload).await
    }

    /// Publish an event from the lifecycle context.
    ///
    /// INTENTION: Allow services during their lifecycle to publish events.
    ///
    /// Handles different topic formats:
    /// - Full topic with network ID: "network:service/topic" (used as is)
    /// - Topic with service: "service/topic" (current network ID added)
    /// - Simple topic: "topic" (current network ID and service path added)
    pub async fn publish(&self, topic: impl Into<String>, data: Option<ArcValue>) -> Result<()> {
        let topic_string = topic.into();
        let full_topic = if topic_string.contains(':') {
            topic_string
        } else if topic_string.contains('/') {
            format!("{0}:{1}", self.network_id, topic_string)
        } else {
            format!(
                "{0}:{1}/{2}",
                self.network_id, self.service_path, topic_string
            )
        };

        self.logger.debug(format!(
            "LifecycleContext publishing to processed topic: {full_topic}"
        ));
        self.node_delegate.publish(full_topic, data).await
    }

    /// Register an action handler
    ///
    /// INTENTION: Allow a service to register a handler function for a specific action.
    /// This is the main way for services to expose functionality to the Node.
    pub async fn register_action(
        &self,
        action_name: impl Into<String>,
        handler: ActionHandler,
    ) -> Result<()> {
        let delegate = &self.node_delegate;
        let action_name_string = action_name.into();

        // Create a topic path for this action
        let action_path = format!(
            "{service_path}/{action_name}",
            service_path = self.service_path,
            action_name = action_name_string
        );

        // Debug logs for action registration
        self.logger.debug(format!(
            "register_action name={}, service_path={}, action_path={}",
            action_name_string, self.service_path, action_path
        ));

        let topic_path: TopicPath = TopicPath::new(&action_path, &self.network_id)
            .map_err(|e| anyhow!("Invalid action path: {e}"))?;

        // More detailed debug after TopicPath creation
        self.logger
            .debug(format!("register_action: created TopicPath {topic_path}"));

        let metadata = ActionMetadata {
            name: action_name_string.clone(),
            description: format!(
                "Action {} for service {}",
                action_name_string, self.service_path
            ),
            input_schema: None,
            output_schema: None,
        };

        // Call the delegate to register the action handler
        delegate
            .register_action_handler(topic_path, handler, Some(metadata))
            .await
    }

    /// Register an action handler with metadata
    ///
    /// INTENTION: Allow a service to register a handler function for an action,
    /// along with descriptive metadata. This enables documentation and discovery
    /// of the action's purpose and parameters.
    pub async fn register_action_with_options(
        &self,
        action_name: impl Into<String>,
        handler: ActionHandler,
        options: ActionRegistrationOptions,
    ) -> Result<()> {
        let action_name_string = action_name.into();

        // Create action metadata from the options
        let metadata = ActionMetadata {
            name: action_name_string.clone(),
            description: options.description.unwrap_or_default(),
            input_schema: options.input_schema,
            output_schema: options.output_schema,
        };

        // Get the node delegate
        let delegate = &self.node_delegate;

        // Create a topic path for this action
        let action_path = format!(
            "{service_path}/{action_name}",
            service_path = self.service_path,
            action_name = action_name_string
        );
        let topic_path = TopicPath::new(&action_path, &self.network_id)
            .map_err(|e| anyhow!("Invalid action path: {e}"))?;

        // Register the action with the provided options
        delegate
            .register_action_handler(topic_path, handler, Some(metadata))
            .await
    }

    /// Subscribe to an event with specific registration options.
    ///
    /// INTENTION: Allow a service to subscribe to an event topic and provide
    /// detailed metadata about the event for discovery and documentation purposes.
    pub async fn subscribe_with_options(
        &self,
        topic: impl Into<String>,
        callback: EventCallback,
        options: EventRegistrationOptions,
    ) -> Result<String> {
        let delegate = &self.node_delegate;
        delegate
            .subscribe_with_options(topic.into(), callback, options)
            .await
    }

    pub async fn subscribe(
        &self,
        topic: impl Into<String>,
        callback: EventCallback,
    ) -> Result<String> {
        let delegate = &self.node_delegate;
        delegate.subscribe(topic.into(), callback).await
    }
}

impl LoggingContext for LifecycleContext {
    fn component(&self) -> Component {
        Component::Service
    }

    fn service_path(&self) -> Option<&str> {
        Some(&self.service_path)
    }

    fn logger(&self) -> &Logger {
        &self.logger
    }
}

/// Service request for an action on a specific service
///
/// INTENTION: Represent a request to perform an action on a service.
/// Includes the destination, requested action, and input data.
///
/// ARCHITECTURAL PRINCIPLE:
/// The ServiceRequest should be self-contained with all routing and
/// context information needed to process a request from start to finish.
pub struct ServiceRequest {
    /// Topic path for the service and action
    pub topic_path: TopicPath,
    /// Data for the request
    pub data: ArcValue,
    /// Request context
    pub context: Arc<RequestContext>,
}

impl ServiceRequest {
    /// Create a new service request
    ///
    /// INTENTION: Create a service request using the service path and action name.
    /// This method will construct the appropriate TopicPath and initialize the request.
    pub fn new(
        service_path: impl Into<String>,
        action_or_event: impl Into<String>,
        data: ArcValue,
        context: Arc<RequestContext>,
    ) -> Self {
        // Create a path string combining service path and action
        let service_path_string = service_path.into();
        let action_or_event_string = action_or_event.into();
        let path_string = format!("{service_path_string}/{action_or_event_string}");

        // Parse the path using the context's network_id method
        let topic_path =
            TopicPath::new(&path_string, &context.network_id()).expect("Invalid path format");

        Self {
            topic_path,
            data,
            context,
        }
    }

    /// Create a new service request with a TopicPath
    ///
    /// INTENTION: Create a service request using an existing TopicPath object.
    /// This is useful when the TopicPath has already been constructed and validated.
    pub fn new_with_topic_path(
        topic_path: TopicPath,
        data: ArcValue,
        context: Arc<RequestContext>,
    ) -> Self {
        Self {
            topic_path,
            data,
            context,
        }
    }

    /// Create a new service request with optional data
    ///
    /// INTENTION: Create a service request where the data parameter is optional.
    /// If no data is provided, ValueType::Null will be used.
    pub fn new_with_optional(
        service_path: impl Into<String>,
        action_or_event: impl Into<String>,
        data: Option<ArcValue>,
        context: Arc<RequestContext>,
    ) -> Self {
        // Create a TopicPath from the service path and action
        let service_path_string = service_path.into();
        let action_or_event_string = action_or_event.into();
        let path_string = format!("{service_path_string}/{action_or_event_string}");

        // Parse the path using the context's network_id method
        let topic_path =
            TopicPath::new(&path_string, &context.network_id()).expect("Invalid path format");

        Self {
            topic_path,
            data: data.unwrap_or_else(ArcValue::null),
            context,
        }
    }

    /// Get the service path from the topic path
    ///
    /// INTENTION: Extract the service path component from the topic path.
    /// This is useful for service identification and routing.
    pub fn path(&self) -> String {
        self.topic_path.service_path()
    }

    /// Get the action or event name from the topic path
    ///
    /// INTENTION: Extract the action or event name from the topic path.
    /// This identifies what operation is being requested.
    pub fn action_or_event(&self) -> String {
        // Get the action path and extract the last part which is the action name
        let action_path = self.topic_path.action_path();

        // If action_path contains a slash, take the part after the last slash
        if let Some(idx) = action_path.rfind('/') {
            action_path[idx + 1..].to_string()
        } else {
            // If there's no slash, it's just the action name itself
            action_path
        }
    }
}

// /// Response from a service handler
// #[derive(Debug, Clone)]
// pub struct ServiceResponse {
//     /// HTTP-like status code
//     pub status: u32,
//     /// Response data if any (immutable)
//     pub data: Option<ArcValue>,
//     /// Error message if any (immutable)
//     pub error: Option<String>,
// }

// impl ServiceResponse {
//     /// Create a new successful response with the given data
//     pub fn ok(data: ArcValue) -> Self {
//         Self {
//             status: 200,
//             data: Some(data),
//             error: None,
//         }
//     }

//     /// Create a new successful response without data
//     pub fn ok_empty() -> Self {
//         Self {
//             status: 200,
//             data: None,
//             error: None,
//         }
//     }

//     /// Create a new error response with the given message
//     pub fn error(status: i32, message: impl Into<String>) -> Self {
//         Self {
//             status: status as u32,
//             data: None,
//             error: Some(message.into()),
//         }
//     }

//     /// Create a standard bad request error response
//     pub fn bad_request(message: impl Into<String>) -> Self {
//         Self::error(400, message)
//     }

//     /// Create a standard not found error response
//     pub fn not_found(message: impl Into<String>) -> Self {
//         Self::error(404, message)
//     }

//     /// Create a standard internal server error response
//     pub fn internal_error(message: impl Into<String>) -> Self {
//         Self::error(500, message)
//     }

//     /// Create a standard method not allowed error response
//     pub fn method_not_allowed(message: impl Into<String>) -> Self {
//         Self::error(405, message)
//     }

//     /// Check if the response is successful
//     pub fn is_success(&self) -> bool {
//         self.status >= 200 && self.status < 300
//     }

//     /// Check if the response is an error
//     pub fn is_error(&self) -> bool {
//         !self.is_success()
//     }
// }

/// Options for a subscription
#[derive(Debug, Clone, Default)]
pub struct SubscriptionOptions {
    // Add subscription options as needed
}

/// Options for publishing an event
///
/// INTENTION: Provide configuration options for event publishing,
/// allowing control over delivery scope, guarantees, and retention.
#[derive(Debug, Clone, Default)]
pub struct PublishOptions {
    /// Whether this event should be broadcast to all nodes in the network
    pub broadcast: bool,

    /// Whether delivery should be guaranteed (at-least-once semantics)
    pub guaranteed_delivery: bool,

    /// How long the event should be retained for late subscribers (in seconds)
    /// None means no retention, 0 means forever
    pub retention_seconds: Option<u64>,

    /// Target a specific node or service instead of all subscribers
    pub target: Option<String>,
}

/// Options for registering an action handler
///
/// INTENTION: Provide a way to specify metadata about an action when registering it,
/// reducing the need for services to define complete metadata upfront.
// #[derive(Debug, Clone, Default)] // This line was redundant and removed
/// Options for registering an event subscription with metadata.
#[derive(Clone, Debug, Default)]
pub struct EventRegistrationOptions {
    /// Description of what the event signifies.
    pub description: Option<String>,
    /// Schema for the event data, for validation and documentation.
    pub data_schema: Option<FieldSchema>,
}

pub struct ActionRegistrationOptions {
    /// Description of what the action does
    pub description: Option<String>,
    /// Parameter schema for validation and documentation
    pub input_schema: Option<FieldSchema>,
    /// Return value schema for documentation
    pub output_schema: Option<FieldSchema>,
}

/// Interface for handling service requests
///
/// INTENTION: Define a consistent interface for handling node requests. This trait
/// is implemented by components that need to handle service requests, specifically
/// the Node component itself which should be responsible for routing requests to
/// appropriate services.
///
/// ARCHITECTURAL PRINCIPLE:
/// Request handling should be centralized in the Node component, with a clear
/// interface that allows for proper routing, logging, and error handling. This
/// separates the responsibility of request handling from service management.
#[async_trait::async_trait]
pub trait NodeRequestHandler: Send + Sync {
    /// Process a service request
    async fn request(&self, path: String, params: Option<ArcValue>) -> Result<ArcValue>;

    /// Publish an event to a topic
    async fn publish(&self, topic: String, data: Option<ArcValue>) -> Result<()>;

    /// Subscribe to a topic
    ///
    /// INTENTION: Register a callback that will be invoked when events are published
    /// to the specified topic. The callback receives both an EventContext and the event data.
    async fn subscribe(
        &self,
        topic: String,
        callback: Box<
            dyn Fn(Arc<EventContext>, ArcValue) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
                + Send
                + Sync,
        >,
    ) -> Result<String>;

    /// Subscribe to a topic with options
    ///
    /// INTENTION: Register a callback with specific delivery options for the subscription.
    /// The callback receives both an EventContext and the event data.
    async fn subscribe_with_options(
        &self,
        topic: String,
        callback: Box<
            dyn Fn(Arc<EventContext>, ArcValue) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
                + Send
                + Sync,
        >,
        options: SubscriptionOptions,
    ) -> Result<String>;

    /// Unsubscribe from a topic
    async fn unsubscribe(&self, topic: String, subscription_id: Option<&str>) -> Result<()>;
}

/// Helper trait to enable easy logging from an Arc<RequestContext>
pub trait ArcContextLogging {
    /// Log a debug level message
    fn debug(&self, message: impl Into<String>);

    /// Log an info level message
    fn info(&self, message: impl Into<String>);

    /// Log a warning level message
    fn warn(&self, message: impl Into<String>);

    /// Log an error level message
    fn error(&self, message: impl Into<String>);
}

/// Implement logging methods for Arc<RequestContext>
impl ArcContextLogging for Arc<RequestContext> {
    fn debug(&self, message: impl Into<String>) {
        self.logger.debug(message);
    }

    fn info(&self, message: impl Into<String>) {
        self.logger.info(message);
    }

    fn warn(&self, message: impl Into<String>) {
        self.logger.warn(message);
    }

    fn error(&self, message: impl Into<String>) {
        self.logger.error(message);
    }
}

/// Type alias for a boxed future returning a Result with ServiceResponse
///
/// INTENTION: Provide a consistent return type for asynchronous service methods,
/// simplifying method signatures and ensuring uniformity across the codebase.
pub type ServiceFuture = Pin<Box<dyn Future<Output = Result<ArcValue>> + Send>>;

/// Event Dispatcher trait
///
/// INTENTION: Define a consistent interface for publishing events from services.
/// This trait is implemented by components that need to dispatch events,
/// specifically the Node component which should be responsible for publishing
/// events to subscribers.
///
/// ARCHITECTURAL PRINCIPLE:
/// Event publishing should be centralized in the Node component, with a clear
/// interface that allows for proper topic-based routing and delivery to subscribers.
/// This separates the responsibility of event publishing from service management.
#[async_trait::async_trait]
pub trait EventDispatcher: Send + Sync {
    /// Publish an event to subscribers
    ///
    /// INTENTION: Distribute an event to all subscribers of the specified topic.
    /// Implementations should handle subscriber lookups and asynchronous delivery.
    // (Removed leftover code block and delimiters due to doctest failure. Intention and architectural documentation preserved.)
    async fn publish(
        &self,
        topic: &str,
        event: &str,
        data: Option<ArcValue>,
        network_id: &str,
    ) -> Result<()>;
}

/// Unified Node Delegate trait
///
/// INTENTION: Provide a single interface for all Node operations that services
/// need to interact with, combining both request handling and event dispatching.
///
/// ARCHITECTURAL PRINCIPLE:
/// A single unified interface simplifies service interactions with the Node,
/// reducing code duplication and complexity while maintaining clear architectural
/// boundaries. This follows the Interface Segregation Principle by providing
/// a focused, cohesive interface for services.
#[async_trait::async_trait]
pub trait NodeDelegate: Send + Sync {
    /// Process a service request
    async fn request<P>(
        &self,
        path: impl Into<String> + Send,
        payload: Option<P>,
    ) -> Result<ArcValue>
    where
        P: AsArcValue + Send + Sync;

    /// Simplified publish for common cases
    async fn publish(&self, topic: String, data: Option<ArcValue>) -> Result<()>;

    /// Subscribe to a topic
    async fn subscribe(
        &self,
        topic: String,
        callback: Box<
            dyn Fn(
                    Arc<EventContext>,
                    Option<ArcValue>,
                ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
                + Send
                + Sync,
        >,
    ) -> Result<String>;

    /// Subscribe with options for more control
    async fn subscribe_with_options(
        &self,
        topic: String,
        callback: Box<
            dyn Fn(
                    Arc<EventContext>,
                    Option<ArcValue>,
                ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>
                + Send
                + Sync,
        >,
        options: EventRegistrationOptions, // Changed from SubscriptionOptions
    ) -> Result<String>;

    /// Unsubscribe from a topic
    async fn unsubscribe(&self, subscription_id: Option<&str>) -> Result<()>;

    /// Register an action handler for a specific path
    ///
    /// INTENTION: Allow services to register handlers for actions through the NodeDelegate.
    async fn register_action_handler(
        &self,
        topic_path: TopicPath,
        handler: ActionHandler,
        metadata: Option<ActionMetadata>,
    ) -> Result<()>;
}

/// Registry Delegate trait for keys service operations
///
/// INTENTION: Provide a dedicated interface for the Keys Service
/// to interact with the core keys management without creating circular references.
/// This follows the same pattern as NodeDelegate but provides only
/// the functionality needed by keys operations.
#[async_trait::async_trait]
pub trait KeysDelegate: Send + Sync {
    async fn ensure_symmetric_key(&self, key_name: &str) -> Result<ArcValue>;
}

/// Registry Delegate trait for registry service operations
///
/// INTENTION: Provide a dedicated interface for the Registry Service
/// to interact with the Node without creating circular references.
/// This follows the same pattern as NodeDelegate but provides only
/// the functionality needed by registry operations.
#[async_trait::async_trait]
pub trait RegistryDelegate: Send + Sync {
    async fn get_service_state(&self, service_path: &TopicPath) -> Option<ServiceState>;

    /// Get metadata for a specific service
    async fn get_service_metadata(&self, service_path: &TopicPath) -> Option<ServiceMetadata>;

    /// Get metadata for all registered services with an option to filter internal services
    ///
    /// INTENTION: Retrieve metadata for all registered services with the option
    /// to exclude internal services (those with paths starting with $)
    async fn get_all_service_metadata(
        &self,
        include_internal_services: bool,
    ) -> HashMap<String, ServiceMetadata>;

    /// Get metadata for all actions under a specific service path
    ///
    /// INTENTION: Retrieve metadata for all actions registered under a service path.
    /// This is useful for service discovery and introspection.
    async fn get_actions_metadata(&self, service_topic_path: &TopicPath) -> Vec<ActionMetadata>;

    /// Register a remote action handler
    ///
    /// INTENTION: Allow RemoteLifecycleContext to register remote action handlers
    /// through this delegate to avoid circular references.
    async fn register_remote_action_handler(
        &self,
        topic_path: &TopicPath,
        handler: ActionHandler,
    ) -> Result<()>;

    async fn remove_remote_action_handler(&self, topic_path: &TopicPath) -> Result<()>;
}

/// Remote service lifecycle context
///
/// INTENTION: Provide remote services with the context needed for lifecycle operations
/// such as initialization, action registration, and shutdown. Similar to LifecycleContext
/// but with remote-specific methods.
pub struct RemoteLifecycleContext {
    /// Network ID for the context
    pub network_id: String,
    /// Service path - identifies the service within the network
    pub service_path: String,
    /// Optional configuration data
    pub config: Option<ArcValue>,
    /// Logger instance with service context
    pub logger: Arc<Logger>,
    /// Registry delegate for registry operations
    registry_delegate: Option<Arc<dyn RegistryDelegate + Send + Sync>>,
}

impl RemoteLifecycleContext {
    /// Create a new RemoteLifecycleContext with the given topic path and logger
    ///
    /// This is the primary constructor that takes the minimum required parameters.
    pub fn new(topic_path: &TopicPath, logger: Arc<Logger>) -> Self {
        Self {
            network_id: topic_path.network_id().to_string(),
            service_path: topic_path.service_path(),
            config: None,
            logger,
            registry_delegate: None,
        }
    }

    /// Add configuration to a RemoteLifecycleContext
    ///
    /// Use builder-style methods instead of specialized constructors.
    pub fn with_config(mut self, config: ArcValue) -> Self {
        self.config = Some(config);
        self
    }

    /// Add a RegistryDelegate to a RemoteLifecycleContext
    ///
    /// INTENTION: Provide access to registry operations during service lifecycle events,
    /// including action registration.
    pub fn with_registry_delegate(
        mut self,
        delegate: Arc<dyn RegistryDelegate + Send + Sync>,
    ) -> Self {
        self.registry_delegate = Some(delegate);
        self
    }

    /// Helper method to log debug level message
    pub fn debug(&self, message: impl Into<String>) {
        self.logger.debug(message);
    }

    /// Helper method to log info level message
    pub fn info(&self, message: impl Into<String>) {
        self.logger.info(message);
    }

    /// Helper method to log warning level message
    pub fn warn(&self, message: impl Into<String>) {
        self.logger.warn(message);
    }

    /// Helper method to log error level message
    pub fn error(&self, message: impl Into<String>) {
        self.logger.error(message);
    }

    pub async fn remove_remote_action_handler(&self, topic_path: &TopicPath) -> Result<()> {
        // Get the registry delegate
        let delegate = match &self.registry_delegate {
            Some(d) => d,
            None => return Err(anyhow!("No registry delegate available")),
        };

        // Call the delegate to remove the remote action handler
        delegate.remove_remote_action_handler(topic_path).await
    }

    /// Register a remote action handler
    ///
    /// INTENTION: Allow a remote service to register a handler function for a specific action.
    pub async fn register_remote_action_handler(
        &self,
        topic_path: &TopicPath,
        handler: ActionHandler,
    ) -> Result<()> {
        // Get the registry delegate
        let delegate = match &self.registry_delegate {
            Some(d) => d,
            None => return Err(anyhow!("No registry delegate available")),
        };

        // Call the delegate to register the remote action handler
        delegate
            .register_remote_action_handler(topic_path, handler)
            .await
    }
}

/// Service handler function type
/// Handler receives optional payload and context, returns a response
pub type ServiceHandler = Box<
    dyn Fn(
            Option<ArcValue>,
            Arc<RequestContext>,
        ) -> Pin<Box<dyn Future<Output = Option<ArcValue>> + Send>>
        + Send
        + Sync,
>;
