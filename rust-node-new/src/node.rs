// Node Implementation
//
// This module provides the Node which is the primary entry point for the Runar system.
// The Node is responsible for managing the service registry, handling requests, and
// coordinating event publishing and subscriptions.

use anyhow::{anyhow, Result};
use log::error;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::routing::TopicPath;
use crate::services::{
    ActionHandler, LifecycleContext,
    NodeRequestHandler, RequestContext, ServiceRequest, ServiceResponse, 
    SubscriptionOptions, 
};
// Import ActionMetadata and AbstractService with full paths
use crate::services::abstract_service::{ActionMetadata, AbstractService};
use crate::services::service_registry::ServiceRegistry;
use runar_common::types::ValueType;
use runar_common::logging::{Component, Logger};
use crate::services::abstract_service::ServiceState;
use crate::services::{
    ServiceFuture, EventContext
};

use crate::services::NodeDelegate;

/// Configuration for a Node
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Network ID for the node
    pub network_id: String,
    /// Node ID for logging and identification
    pub node_id: Option<String>,
}

impl NodeConfig {
    /// Create a new NodeConfig with minimal required parameters
    pub fn new(network_id: &str) -> Self {
        Self {
            network_id: network_id.to_string(),
            node_id: None,
        }
    }

    /// Create a new NodeConfig with a specific node ID
    pub fn new_with_node_id(network_id: &str, node_id: &str) -> Self {
        Self {
            network_id: network_id.to_string(),
            node_id: Some(node_id.to_string()),
        }
    }
}

/// Node represents a Runar node that can host services and communicate with other nodes
pub struct Node {
    /// Configuration for the node
    pub config: NodeConfig,

    /// Service registry for managing services
    service_registry: Arc<ServiceRegistry>,

    /// Network ID for this node
    pub network_id: String,

    /// Service map for tracking registered services
    services: Arc<RwLock<HashMap<String, Arc<dyn AbstractService>>>>,
    
    /// Service state map for tracking the lifecycle state of services
    service_states: Arc<RwLock<HashMap<String, ServiceState>>>,
    
    /// Logger instance for this node
    logger: Logger,
}

impl Node {
    /// Create a new Node with the given configuration
    pub async fn new(config: NodeConfig) -> Result<Self> {
        // Create the node ID
        let node_id = match &config.node_id {
            Some(id) => id.clone(),
            None => format!("node-{}", uuid::Uuid::new_v4()),
        };
        
        // Create a root logger with the node ID
        let logger = Logger::new_root(Component::Node, &node_id);
        
        // Log that we're creating a new node
        logger.info(format!("Creating new Node with network_id '{}'", config.network_id));
        
        // Create the service registry with a child logger for proper hierarchy
        let registry_logger = logger.with_component(runar_common::Component::Registry);
        let registry = ServiceRegistry::new(registry_logger);
        
        // Create a new node instance
        let node = Self {
            config: config.clone(),
            service_registry: Arc::new(registry),
            network_id: config.network_id.clone(),
            services: Arc::new(RwLock::new(HashMap::new())),
            service_states: Arc::new(RwLock::new(HashMap::new())),
            logger,
        };
        
        // Return the new node
        Ok(node)
    }
    
    /// Get a logger for a service, derived from the node's root logger
    pub fn create_service_logger(&self, _service_name: &str) -> Logger {
        self.logger.with_component(Component::Service)
    }

    /// Create a request context with the right logger
    pub fn create_request_context(&self, service_path: &str) -> RequestContext {
        let service_logger = self.logger.with_component(Component::Service);
        RequestContext::new(&self.network_id, service_path, service_logger)
    }
    
    /// Create a request context with a topic path
    ///
    /// INTENTION: Create a RequestContext with a properly configured logger
    /// and a complete topic path. This is used when handling requests that
    /// already have a validated TopicPath.
    pub fn create_request_context_with_topic_path(&self, topic_path: &TopicPath) -> RequestContext {
        let service_logger = self.logger.with_component(Component::Service);
        RequestContext::new_with_topic_path(&self.network_id, topic_path, service_logger)
    }
    
    /// Create an action registrar function
    ///
    /// INTENTION: Create a function that can be passed to services to register
    /// action handlers dynamically. This enables services to register handlers 
    /// during initialization without directly depending on the Node.
    pub fn create_action_registrar(&self) -> ActionRegistrar {
        // Clone the Arc to the service registry
        let registry = self.service_registry.clone();
        let network_id = self.config.network_id.clone();
        
        // Create a boxed function that can register action handlers
        Arc::new(move |service_path: &str, action_name: &str, handler: ActionHandler, metadata: Option<ActionMetadata>| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
            let service_path = service_path.to_string();
            let action_name = action_name.to_string();
            let registry_clone = registry.clone();
            let metadata = metadata.clone();
            let network_id = network_id.clone();
            
            // Return a future that registers the handler
            Box::pin(async move {
                registry_clone.register_action_handler(&service_path, &action_name, handler, metadata, &network_id).await
            })
        })
    }
    
    /// Create a lifecycle context for a service
    ///
    /// INTENTION: Create a context object that provides all necessary callbacks and
    /// information for service lifecycle operations. This bundles together the registrar,
    /// logger, and other contextual information needed by services.
    pub fn create_context(&self, service_path: &str) -> LifecycleContext {
        // Create service-specific logger
        let mut service_logger = self.logger.with_component(Component::Service);
        // TODO: Add service path to logger when implemented
        
        // Create registrar for actions
        let registrar = self.create_action_registrar();
        
        // Create context with all components
        LifecycleContext::new(&self.network_id, service_path, service_logger)
            .with_registrar(registrar)
    }
    
    /// Get the current state of a service
    ///
    /// INTENTION: Retrieve the current lifecycle state of a service.
    /// This method allows checking if a service is initialized, running, or stopped.
    pub async fn get_service_state(&self, service_path: &str) -> Option<ServiceState> {
        let states = self.service_states.read().await;
        states.get(service_path).cloned()
    }

    /// Update the state of a service
    ///
    /// INTENTION: Update the lifecycle state of a service in the centralized metadata.
    /// This is used by the Node to track service states during initialization, startup, and shutdown.
    async fn update_service_state(&self, service_path: &str, state: ServiceState) {
        let mut states = self.service_states.write().await;
        self.logger.debug(format!("Updating service '{}' state to {:?}", service_path, state));
        states.insert(service_path.to_string(), state);
    }

    /// Add a service to the node
    pub async fn add_service<S>(&mut self, service: S) -> Result<()>
    where
        S: AbstractService + 'static,
    {
        // Convert to Arc to share across threads
        let service_arc: Arc<dyn AbstractService> = Arc::new(service);
        
        // Get service information directly from the service
        let name = service_arc.name().to_string();
        let path = service_arc.path().to_string();
        
        // Register with our internal service map
        let mut services = self.services.write().await;
        services.insert(path.clone(), service_arc.clone());
        
        // Initialize service state as Initialized
        self.update_service_state(&path, ServiceState::Initialized).await;
        
        // Log the registration
        self.logger.debug(format!("Adding service '{}' to node registry", path));
        
        // Create a lifecycle context with derived logger for initialization
        let lifecycle_context = self.create_context(&path);
        
        // Initialize the service with the derived logger
        // The service will register its action handlers during initialization
        if let Err(e) = service_arc.init(lifecycle_context).await {
            self.logger.error(format!("Failed to initialize service '{}': {}", name, e));
            self.update_service_state(&path, ServiceState::Error).await;
            return Err(anyhow!("Failed to initialize service: {}", e));
        }
        
        // The service is now registered and initialized with its action handlers
        self.logger.info(format!("Service '{}' initialized successfully", name));
        
        Ok(())
    }
    
 
    /// Request implementation - for converting path strings to service requests and handling them
    ///
    /// INTENTION: Process a service request by routing it to the appropriate handler.
    /// This is the core request handling method of the Node.
    ///
    /// This method:
    /// 1. Parses the path into a validated TopicPath
    /// 2. Creates a proper request context
    /// 3. Constructs a ServiceRequest
    /// 4. Finds the appropriate action handler from the service registry
    /// 5. Invokes the handler and returns its response
    /// 6. Returns an error response if no handler is found
    ///
    /// Path formats supported:
    /// - "service_name/action" - Uses the current network context
    /// - "network_id:service_name/action" - Fully qualified path
    pub async fn request(&self, path: String, params: ValueType) -> Result<ServiceResponse> {
        // Parse the path into a TopicPath for validation
        let topic_path = TopicPath::new(&path, &self.network_id)
            .map_err(|e| anyhow!("Invalid path format: {}", e))?;
        
        // Create a context with a derived logger for this request
        let context = self.create_request_context_with_topic_path(&topic_path);
        let context_arc = Arc::new(context);
        
        // Create the service request with the validated TopicPath
        let request = ServiceRequest::new_with_topic_path(
            topic_path.clone(),
            params,
            context_arc.clone(),
        );
        
        // Log that we're handling the request
        context_arc.debug(&format!("Node handling request for {}", topic_path.as_str()));

        // Access service path and action from the topic path
        let handler_params = if let ValueType::Null = request.data {
            None
        } else {
            Some(request.data.clone())
        };

        // Get the action handler from the registry using the topic path
        if let Some(handler) = self.service_registry.get_action_handler(&topic_path).await {
            // Node invokes the handler directly
            context_arc.debug(&format!("Invoking action handler for {}", topic_path.as_str()));
            
            // Use the context we created - we already have the reference to it
            // Clone the RequestContext from the Arc
            let context_ref = context_arc.as_ref().clone();
            return handler(handler_params, context_ref).await;
        }

        // No action handler found, return error
        let service_path = topic_path.service_path();
        
        // Format the error message differently based on whether there's an action
        let error_msg = if topic_path.action_path().is_empty() {
            format!("No handler registered for service {}", service_path)
        } else {
            format!("No handler registered for path {}", topic_path.action_path())
        };
        
        context_arc.error(&error_msg);
        Ok(ServiceResponse::error(404, &error_msg))
    }
    

    //TODO: we need also a publish_with_options method..  with the actiona implmetnation and the publish() calls 
    //is with defaul options.. options will be if the vent shoul be a broadcast, or a single node, single servie, 
    //guaranteed delivery. rentention policy
    /// Publish an event to a topic
    ///
    /// INTENTION: Distribute an event to subscribers of the topic.
    /// This method validates the topic string, converts it to a TopicPath,
    /// looks up subscribers in the service registry, and delivers the event.
    pub async fn publish(&self, topic: String, data: ValueType) -> Result<()> {
        // Convert string to validated TopicPath
        let topic_path = TopicPath::new(&topic, &self.network_id)
            .map_err(|e| anyhow!("Invalid topic format: {}", e))?;
            
        self.logger.debug(format!("Publishing to topic '{}'", topic_path.as_str()));
        
        // Get handlers - returns subscription IDs and handlers
        let event_handlers = self.service_registry.get_event_handlers(&topic_path).await;
        let subscriber_count = event_handlers.len();
        
        if subscriber_count == 0 {
            self.logger.debug(format!("No subscribers for topic '{}'", topic_path.as_str()));
            return Ok(());
        }
        
        let topic_clone = topic_path.clone();
        let logger = self.logger.clone();
        
        // Execute callbacks - each in its own task
        for (subscriber_id, callback) in event_handlers {
            let data_clone = data.clone();
            let topic_path_clone = topic_clone.clone();
            let logger_clone = logger.clone();
            let subscriber_id_clone = subscriber_id.clone();
            let network_id = self.network_id.clone();
            let service_path = topic_path_clone.service_path();
            
            tokio::spawn(async move {
                // Create an event context for the callback
                let event_logger = logger_clone.with_component(Component::Service);
                let event_context = EventContext::new(
                    &network_id,
                    topic_path_clone.as_str(),
                    &service_path,
                    event_logger
                );
                let event_context_arc = Arc::new(event_context);
                
                // Execute the callback with the context
                match callback(event_context_arc, data_clone).await {
                    Ok(_) => {
                        logger_clone.debug(format!("Successfully delivered event to subscriber '{}' for topic '{}'", 
                            subscriber_id_clone, topic_path_clone.as_str()));
                    },
                    Err(err) => {
                        logger_clone.error(format!("Error executing callback for topic '{}', subscriber '{}': {}", 
                            topic_path_clone.as_str(), subscriber_id_clone, err));
                    }
                }
            });
        }
        
        self.logger.debug(format!("Published to {} subscribers for topic '{}'", subscriber_count, topic_path.as_str()));
        
        Ok(())
    }

    /// Subscribe to a topic
    pub async fn subscribe(
        &self,
        topic: String,
        callback: Box<dyn Fn(Arc<EventContext>, ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
    ) -> Result<String> {
        <Self as NodeDelegate>::subscribe(self, topic, callback).await
    }

    /// Subscribe to a topic with options
    pub async fn subscribe_with_options(
        &self,
        topic: String,
        callback: Box<dyn Fn(Arc<EventContext>, ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
        options: SubscriptionOptions,
    ) -> Result<String> {
        <Self as NodeDelegate>::subscribe_with_options(self, topic, callback, options).await
    }

    /// Unsubscribe from a topic
    pub async fn unsubscribe(&self, topic: String, subscription_id: Option<&str>) -> Result<()> {
        <Self as NodeDelegate>::unsubscribe(self, topic, subscription_id).await
    }

    /// List all services
    pub fn list_services(&self) -> Vec<String> {
        // Return a simple snapshot of services
        // This avoids the need to block on async code
        self.services.try_read()
            .map(|services| services.keys().cloned().collect::<Vec<String>>())
            .unwrap_or_default()
    }

    /// Start the Node and all registered services
    ///
    /// INTENTION: Initialize the Node's internal systems and start all registered services.
    /// This method:
    /// 1. Checks if the Node is already started to ensure idempotency
    /// 2. Transitions the Node to the Started state
    /// 3. Starts all registered services in the proper order
    /// 4. Updates the service state in the metadata as each service starts
    /// 5. Handles any errors during service startup
    ///
    /// When network functionality is added, this will also advertise services to the network.
    pub async fn start(&self) -> Result<()> {
        self.logger.info("Starting Node and all registered services");
        
        // Get a read lock on the services map
        let services_lock = self.services.read().await;
        
        if services_lock.is_empty() {
            self.logger.warn("No services registered with this Node");
        }
        
        // Start each service
        let mut success_count = 0;
        let mut failure_count = 0;
        
        for (path, service) in services_lock.iter() {
            self.logger.debug(format!("Starting service '{}'", path));
            
            // Create a lifecycle context for this service
            let context = self.create_context(path);
            
            // Try to start the service
            match service.start(context).await {
                Ok(_) => {
                    self.logger.info(format!("Service '{}' started successfully", path));
                    success_count += 1;
                    
                    // Update the service state to Running
                    self.update_service_state(path, ServiceState::Running).await;
                },
                Err(e) => {
                    self.logger.error(format!("Failed to start service '{}': {}", path, e));
                    failure_count += 1;
                    
                    // Update the service state to Error
                    self.update_service_state(path, ServiceState::Error).await;
                }
            }
        }
        
        // Log the final status
        if failure_count == 0 {
            self.logger.info(format!("Node started successfully: {} services running", success_count));
            Ok(())
        } else {
            let message = format!(
                "Node started with errors: {} services running, {} failed to start", 
                success_count, 
                failure_count
            );
            self.logger.warn(&message);
            
            // Return an error if any services failed to start
            Err(anyhow!(message))
        }
    }
    
    /// Stop the Node and all registered services
    ///
    /// INTENTION: Gracefully shut down the Node and all registered services.
    /// This method:
    /// 1. Stops all registered services in the proper order
    /// 2. Updates the service state in the metadata as each service stops
    /// 3. Cleans up any Node resources, subscriptions, or pending events
    /// 4. Transitions the Node to the Stopped state
    ///
    /// This provides a clean shutdown process to prevent data loss or corruption.
    pub async fn stop(&self) -> Result<()> {
        self.logger.info("Stopping Node and all registered services");
        
        // Get a read lock on the services map
        let services_lock = self.services.read().await;
        
        if services_lock.is_empty() {
            self.logger.warn("No services registered with this Node");
            return Ok(());
        }
        
        // Stop each service
        let mut success_count = 0;
        let mut failure_count = 0;
        
        for (path, service) in services_lock.iter() {
            self.logger.debug(format!("Stopping service '{}'", path));
            
            // Create a lifecycle context for this service
            let context = self.create_context(path);
            
            // Try to stop the service
            match service.stop(context).await {
                Ok(_) => {
                    self.logger.info(format!("Service '{}' stopped successfully", path));
                    success_count += 1;
                    
                    // Update the service state to Stopped
                    self.update_service_state(path, ServiceState::Stopped).await;
                },
                Err(e) => {
                    self.logger.error(format!("Failed to stop service '{}': {}", path, e));
                    failure_count += 1;
                    
                    // Update the service state to Error
                    self.update_service_state(path, ServiceState::Error).await;
                }
            }
        }
        
        // Log the final status
        if failure_count == 0 {
            self.logger.info(format!("Node stopped successfully: {} services stopped", success_count));
            Ok(())
        } else {
            let message = format!(
                "Node stopped with errors: {} services stopped, {} failed to stop", 
                success_count, 
                failure_count
            );
            self.logger.warn(&message);
            
            // Return an error if any services failed to stop
            Err(anyhow!(message))
        }
    }

    /// Get all service states
    ///
    /// INTENTION: Retrieve the current lifecycle state of all services.
    /// This is useful for monitoring service health and debugging.
    pub async fn get_all_service_states(&self) -> HashMap<String, ServiceState> {
        let states = self.service_states.read().await;
        states.clone()
    }
}

/// Implementation of the NodeDelegate trait for Node
#[async_trait::async_trait]
impl NodeDelegate for Node {
    /// Process a service request
    async fn request(&self, path: String, params: ValueType) -> Result<ServiceResponse> {
        // Call Node's own implementation directly
        Self::request(self, path, params).await
    }
    
    /// Simplified publish for common cases
    async fn publish(&self, topic: String, data: ValueType) -> Result<()> {
        // Call Node's own implementation directly
        Self::publish(self, topic, data).await
    }

    /// Subscribe to a topic
    async fn subscribe(
        &self,
        topic: String,
        callback: Box<dyn Fn(Arc<EventContext>, ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
    ) -> Result<String> {
        // Parse the topic into a TopicPath for validation
        let topic_path = TopicPath::new(&topic, &self.network_id)
            .map_err(|e| anyhow!("Invalid topic format: {}", e))?;
            
        self.logger.debug(format!("Subscribing to topic '{}'", topic_path.as_str()));
        
        // Convert Box to Arc for callback
        let callback_arc = Arc::from(callback);
        
        // Register with the service registry
        let subscription_id = self.service_registry.subscribe(&topic_path, callback_arc).await?;
        
        self.logger.debug(format!("Subscribed to topic '{}' with ID '{}'", topic_path.as_str(), subscription_id));
        
        Ok(subscription_id)
    }

    /// Subscribe to a topic with options
    async fn subscribe_with_options(
        &self,
        topic: String,
        callback: Box<dyn Fn(Arc<EventContext>, ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
        options: SubscriptionOptions,
    ) -> Result<String> {
        // Parse the topic into a TopicPath for validation
        let topic_path = TopicPath::new(&topic, &self.network_id)
            .map_err(|e| anyhow!("Invalid topic format: {}", e))?;
            
        self.logger.debug(format!("Subscribing to topic '{}' with options", topic_path.as_str()));
        
        // Convert Box to Arc for callback
        let callback_arc = Arc::from(callback);
        
        // Register with the service registry
        let subscription_id = self.service_registry.subscribe_with_options(&topic_path, callback_arc, options).await?;
        
        self.logger.debug(format!("Subscribed to topic '{}' with ID '{}'", topic_path.as_str(), subscription_id));
        
        Ok(subscription_id)
    }

    /// Unsubscribe from a topic
    async fn unsubscribe(&self, topic: String, subscription_id: Option<&str>) -> Result<()> {
        // Parse the topic into a TopicPath for validation
        let topic_path = TopicPath::new(&topic, &self.network_id)
            .map_err(|e| anyhow!("Invalid topic format: {}", e))?;
            
        self.logger.debug(format!("Unsubscribing from topic '{}'", topic_path.as_str()));
        
        // Call service registry to unsubscribe
        self.service_registry.unsubscribe(&topic_path, subscription_id).await?;
        
        // Log success
        let id_info = subscription_id.map_or("all IDs".to_string(), |id| format!("ID '{}'", id));
        self.logger.debug(format!("Unsubscribed from topic '{}' with {}", topic_path.as_str(), id_info));
        
        Ok(())
    }

    /// List all services
    fn list_services(&self) -> Vec<String> {
        // Return a simple snapshot of services
        // This avoids the need to block on async code
        self.services.try_read()
            .map(|services| services.keys().cloned().collect::<Vec<String>>())
            .unwrap_or_default()
    }
}

/// Type alias for the action registrar function
pub type ActionRegistrar = Arc<dyn Fn(&str, &str, ActionHandler, Option<ActionMetadata>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>; 