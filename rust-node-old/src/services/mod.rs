use anyhow::{anyhow, Result};
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid;
use std::pin::Pin;
use std::future::Future;

use crate::routing::TopicPath;

use crate::db::SqliteDatabase;
use crate::node::NodeConfig;

// Import types from runar_common
use runar_common::types::{ValueType, SerializableStruct};

// Export the abstract service module
pub mod abstract_service;
// Export the sqlite service module
pub mod sqlite;
// Export the node info service module
pub mod node_info;
// Export the registry service module
pub mod service_registry;
// Export the registry info module
pub mod registry_info;
// Export the utils module
pub mod utils;
// Export the remote service module
pub mod remote;
// Export the anonymous subscriber module
pub mod anonymous_subscriber;
// Export the manager module
pub mod manager;
// Export the distributed registry module (for macros)
pub mod distributed_registry;
// Export the error handling demo module
pub mod error_handling_demo;

// Re-export service types
pub use abstract_service::{AbstractService, ServiceMetadata, ServiceState};
pub use anonymous_subscriber::AnonymousSubscriberService;
pub use node_info::NodeInfoService;
pub use remote::{P2PTransport, RemoteService};
pub use sqlite::SqliteService;
pub use utils::ServiceResponseExt;
pub use error_handling_demo::ErrorHandlingDemoService;

// Re-export common types (safely)
pub mod types {
    pub use runar_common::types::{ValueType, SerializableStruct};
}

// Re-export distributed registry types (for macros)
pub use distributed_registry::{
    ActionHandler, 
    ProcessHandler, 
    EventSubscription, 
    PublicationInfo,
};

// Re-export registry objects if distributed slice feature is enabled
#[cfg(feature = "distributed_slice")]
pub use distributed_registry::{
    ACTION_REGISTRY,
    PROCESS_REGISTRY,
    SUBSCRIPTION_REGISTRY,
    PUBLICATION_REGISTRY,
    distributed_slice,
};

/// Handler for node requests - used to make service calls and handle events
#[async_trait::async_trait]
pub trait NodeRequestHandler: Send + Sync {
    /// Make a request to a service with additional options
    /// 
    /// This method provides a flexible API for making service requests with various options
    /// such as timeout, retries, custom request IDs, and additional metadata.
    /// 
    /// # Examples
    /// 
    /// Basic request with timeout:
    /// ```
    /// let options = RequestOptions::with_timeout(5000); // 5 second timeout
    /// node.request_with_options("service/action", params, options).await?;
    /// ```
    /// 
    /// Request with retry:
    /// ```
    /// let options = RequestOptions::new()
    ///     .timeout(5000)
    ///     .with_retry(3, 500); // retry up to 3 times with 500ms delay
    /// node.request_with_options("service/action", params, options).await?;
    /// ```
    /// 
    /// Request with custom ID and metadata:
    /// ```
    /// let mut metadata = HashMap::new();
    /// metadata.insert("source".to_string(), ValueType::String("user_interface".to_string()));
    /// 
    /// let options = RequestOptions::new()
    ///     .with_request_id("custom-request-123".to_string())
    ///     .with_metadata(metadata);
    /// node.request_with_options("service/action", params, options).await?;
    /// ```
    async fn request_with_options(&self, path: String, params: ValueType, options: RequestOptions) -> Result<ServiceResponse> {
        // Handle retries if enabled
        if options.retry && options.max_retries.is_some() {
            let max_retries = options.max_retries.unwrap();
            let retry_delay = options.retry_delay_ms.unwrap_or(500);
            
            // Attempt the request multiple times
            let mut attempt = 0;
            let mut last_error = None;
            
            while attempt <= max_retries {
                attempt += 1;
                
                // For each attempt, try with timeout if specified
                let result = if let Some(timeout_ms) = options.timeout_ms {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(timeout_ms),
                        self.request(path.clone(), params.clone())
                    ).await {
                        Ok(result) => result,
                        Err(_) => Err(anyhow::anyhow!("Request timed out")),
                    }
                } else {
                    // No timeout, just make the request
                    self.request(path.clone(), params.clone()).await
                };
                
                // Check the result
                match result {
                    Ok(response) => {
                        // Check if it's an error response that should be retried
                        if response.status == ResponseStatus::Error {
                            // Store the error and retry if we haven't exceeded max retries
                            last_error = Some(anyhow::anyhow!("Service error: {}", response.message));
                            
                            if attempt <= max_retries {
                                // Wait before retrying
                                tokio::time::sleep(std::time::Duration::from_millis(retry_delay)).await;
                                continue;
                            } else {
                                // Return the error response on the last attempt
                                return Ok(response);
                            }
                        } else {
                            // Success response, return it
                            return Ok(response);
                        }
                    },
                    Err(err) => {
                        // Store the error and retry if we haven't exceeded max retries
                        last_error = Some(err);
                        
                        if attempt <= max_retries {
                            // Wait before retrying
                            tokio::time::sleep(std::time::Duration::from_millis(retry_delay)).await;
                            continue;
                        }
                    }
                }
            }
            
            // If we get here, all retries failed
            return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Request failed after retries")));
        } else {
            // No retries, just handle timeout if specified
            if let Some(timeout_ms) = options.timeout_ms {
                match tokio::time::timeout(
                    std::time::Duration::from_millis(timeout_ms),
                    self.request(path, params)
                ).await {
                    Ok(result) => result,
                    Err(_) => Ok(ServiceResponse::error("Request timed out")),
                }
            } else {
                // No timeout or retries, just forward the request
                self.request(path, params).await
            }
        }
    }

    /// Make a request to a service
    async fn request(&self, path: String, params: ValueType) -> Result<ServiceResponse>;

    /// Publish an event
    async fn publish(&self, topic: String, data: ValueType) -> Result<()>;

    /// Subscribe to events on a topic with an async callback
    async fn subscribe(
        &self,
        topic: String,
        callback: Box<dyn Fn(ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
    ) -> Result<String>;
    
    /// Subscribe to events with options and an async callback
    async fn subscribe_with_options(
        &self,
        topic: String,
        callback: Box<dyn Fn(ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
        options: SubscriptionOptions,
    ) -> Result<String>;

    /// Unsubscribe from events
    async fn unsubscribe(&self, topic: String, subscription_id: Option<&str>) -> Result<()>;

    /// List available services
    fn list_services(&self) -> Vec<String> {
        Vec::new()
    }
    
    /// Get the current request context, if available
    /// This is used for determining the caller's identity in certain operations
    fn current_context(&self) -> Option<RequestContext> {
        None
    }
}

/// Options for subscription management
#[derive(Debug, Clone)]
pub struct SubscriptionOptions {
    /// Optional time-to-live for the subscription (None means no expiration)
    pub ttl: Option<std::time::Duration>,

    /// Maximum number of times this subscription should be triggered before auto-unsubscribing
    /// None means no limit
    pub max_triggers: Option<usize>,

    /// Whether this is a one-time subscription that should be removed after first trigger
    pub once: bool,

    /// A unique ID for this subscription (auto-generated if not provided)
    pub id: Option<String>,
    
    /// Context for the subscriber (automatically set)
    pub context: RequestContext,
}

impl Default for SubscriptionOptions {
    fn default() -> Self {
        Self {
            ttl: None,
            max_triggers: None,
            once: false,
            id: None,
            context: RequestContext::default(),
        }
    }
}

impl SubscriptionOptions {
    /// Create a new set of subscription options
    pub fn new(context: RequestContext) -> Self {
        Self {
            ttl: None,
            max_triggers: None,
            once: false,
            id: None,
            context,
        }
    }

    /// Set a time-to-live for the subscription
    pub fn with_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set a maximum number of triggers for the subscription
    pub fn with_max_triggers(mut self, max_triggers: usize) -> Self {
        self.max_triggers = Some(max_triggers);
        self
    }

    /// Set this subscription to trigger only once
    pub fn once(mut self) -> Self {
        self.once = true;
        self
    }

    /// Set a custom ID for this subscription
    pub fn with_id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    /// Generate a random ID if one is not already set
    pub fn ensure_id(&mut self) {
        if self.id.is_none() {
            self.id = Some(uuid::Uuid::new_v4().to_string());
        }
    }
}

/// Options for request management
#[derive(Debug, Clone)]
pub struct RequestOptions {
    /// Optional timeout for the request in milliseconds
    pub timeout_ms: Option<u64>,
    
    /// Optional request ID (auto-generated if not provided)
    pub request_id: Option<String>,
    
    /// Optional metadata for additional context
    pub metadata: Option<HashMap<String, ValueType>>,
    
    /// Whether to retry the request on failure
    pub retry: bool,
    
    /// Maximum number of retries
    pub max_retries: Option<usize>,
    
    /// Delay between retries in milliseconds
    pub retry_delay_ms: Option<u64>,
}

impl Default for RequestOptions {
    fn default() -> Self {
        Self {
            timeout_ms: None,
            request_id: None,
            metadata: None,
            retry: false,
            max_retries: None,
            retry_delay_ms: None,
        }
    }
}

impl RequestOptions {
    /// Create new request options
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Create request options with a timeout
    pub fn with_timeout(timeout_ms: u64) -> Self {
        let mut options = Self::default();
        options.timeout_ms = Some(timeout_ms);
        options
    }
    
    /// Set a timeout for the request
    pub fn timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }
    
    /// Set a custom request ID
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }
    
    /// Set metadata for the request
    pub fn with_metadata(mut self, metadata: HashMap<String, ValueType>) -> Self {
        self.metadata = Some(metadata);
        self
    }
    
    /// Enable retries for the request
    pub fn with_retry(mut self, max_retries: usize, retry_delay_ms: u64) -> Self {
        self.retry = true;
        self.max_retries = Some(max_retries);
        self.retry_delay_ms = Some(retry_delay_ms);
        self
    }
    
    /// Generate a random request ID if one is not already set
    pub fn ensure_request_id(&mut self) {
        if self.request_id.is_none() {
            self.request_id = Some(uuid::Uuid::new_v4().to_string());
        }
    }
}

/// Response status for service responses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseStatus {
    /// Success
    Success,
    /// Error
    Error,
}

/// Define our own wrapper to avoid the orphan rule violation for Arc cloning
pub struct StructArc(pub Box<dyn SerializableStruct + Send + Sync + 'static>);

impl Clone for StructArc {
    fn clone(&self) -> Self {
        StructArc(self.0.clone())
    }
}

/// Service request - represents a request to a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRequest {
    /// The path of the service
    pub path: String,
    /// The action to perform on the service
    pub action: String,
    /// The data for the action
    pub data: Option<ValueType>,
    /// Request ID for tracing
    pub request_id: Option<String>,
    /// Optional metadata for additional context
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, ValueType>>,
    /// Request context object (not serialized)
    #[serde(skip)]
    pub context: Arc<RequestContext>,
    /// Structured topic path (not serialized)
    /// This field will eventually replace path and action for routing
    #[serde(skip)]
    pub topic_path: Option<TopicPath>,
}

impl ServiceRequest {
    /// Create a new service request
    pub fn new<P: Into<String>, A: Into<String>, D: Into<ValueType>>(
        path: P,
        action: A,
        data: D,
        context: Arc<RequestContext>,
    ) -> Self {
        let path_str = path.into();
        let action_str = action.into();
        
        // Create a topic path from path and action
        // For now, we default to the network_id "default" for backward compatibility
        let topic_path = TopicPath::new_action("default", &path_str, &action_str);
        
        ServiceRequest {
            path: path_str,
            action: action_str,
            data: Some(data.into()),
            request_id: Some(uuid::Uuid::new_v4().to_string()),
            metadata: None,
            context,
            topic_path: Some(topic_path),
        }
    }

    /// Create a new service request with optional parameters
    pub fn new_with_optional<P: Into<String>, A: Into<String>>(
        path: P,
        action: A,
        data: Option<ValueType>,
        context: Arc<RequestContext>,
    ) -> Self {
        let path_str = path.into();
        let action_str = action.into();
        
        // Create a topic path from path and action
        let topic_path = TopicPath::new_action("default", &path_str, &action_str);
        
        ServiceRequest {
            path: path_str,
            action: action_str,
            data,
            request_id: Some(uuid::Uuid::new_v4().to_string()),
            metadata: None,
            context,
            topic_path: Some(topic_path),
        }
    }

    /// Create a new service request with metadata
    pub fn new_with_metadata<P: Into<String>, A: Into<String>, D: Into<ValueType>>(
        path: P,
        action: A,
        data: D,
        metadata: HashMap<String, ValueType>,
        context: Arc<RequestContext>,
    ) -> Self {
        let path_str = path.into();
        let action_str = action.into();
        
        // Create a topic path from path and action
        let topic_path = TopicPath::new_action("default", &path_str, &action_str);
        
        ServiceRequest {
            path: path_str,
            action: action_str,
            data: Some(data.into()),
            request_id: Some(uuid::Uuid::new_v4().to_string()),
            metadata: Some(metadata),
            context,
            topic_path: Some(topic_path),
        }
    }
    
    /// Set the TopicPath with network ID for this request
    pub fn with_topic_path(mut self, network_id: &str, service_path: &str, action: &str) -> Self {
        self.topic_path = Some(TopicPath::new_action(network_id, service_path, action));
        self
    }
    
    /// Get the network ID for this request
    pub fn network_id(&self) -> &str {
        match &self.topic_path {
            Some(tp) => &tp.network_id,
            None => "default" // Fallback for backward compatibility
        }
    }
    
    /// Parse a path string to update the request's topic_path
    /// The path string should be in the format: "[network_id:]service_path/action"
    pub fn parse_path_string(&mut self, path_str: &str) -> Result<()> {
        // Use a default network ID for parsing - ideally this should be obtained from context
        let default_network_id = "default";
        match TopicPath::parse(path_str, default_network_id) {
            Ok(topic_path) => {
                self.path = topic_path.service_path.clone();
                self.action = topic_path.action_or_event.clone();
                self.topic_path = Some(topic_path);
                Ok(())
            },
            Err(e) => Err(anyhow!("Failed to parse path string: {}", e))
        }
    }

    /// Get a data parameter from the request
    pub fn get_param(&self, key: &str) -> Option<ValueType> {
        self.data.as_ref().and_then(|v| match v {
            ValueType::Map(map) => map.get(key).cloned(),
            ValueType::Json(json) => json.get(key).map(|v| ValueType::Json(v.clone())),
            _ => None,
        })
    }

    /// Get a data parameter reference from the request
    pub fn get_param_ref(&self, key: &str) -> Option<&ValueType> {
        self.data.as_ref().and_then(|v| match v {
            ValueType::Map(map) => map.get(key),
            _ => None,
        })
    }

    /// Convert to JSON params
    pub fn to_json_params(&self) -> Value {
        json!({
            "path": self.path,
            "action": self.action,
            "data": self.data.as_ref().map(|v| v.to_json()),
            "request_id": self.request_id,
        })
    }
}

/// Service response - represents a response from a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResponse {
    /// Status of the response (success or error)
    pub status: ResponseStatus,
    /// Message describing the response
    pub message: String,
    /// The response data
    pub data: Option<ValueType>,
}

impl ServiceResponse {
    /// Create a success response with data
    pub fn success<T: Into<ValueType>>(message: String, data: Option<T>) -> Self {
        ServiceResponse {
            status: ResponseStatus::Success,
            message,
            data: data.map(|d| d.into()),
        }
    }

    /// Create an error response with a message
    pub fn error<T: Into<String>>(message: T) -> Self {
        ServiceResponse {
            status: ResponseStatus::Error,
            message: message.into(),
            data: None,
        }
    }
}

/// Service Manager - manages services and routes requests
/// This implementation is being refactored to use ServiceRegistry
/// in the future and will eventually be deprecated
pub struct ServiceManager {
    /// Map of service name to service implementation
    services: Arc<RwLock<HashMap<String, Arc<dyn AbstractService>>>>,
    /// The network ID
    network_id: String,
    /// Database connection
    db: Arc<SqliteDatabase>,
    /// Node configuration
    config: Arc<NodeConfig>,
    /// Node handler for making requests
    node_handler: Option<Arc<dyn NodeRequestHandler + Send + Sync>>,
}

impl ServiceManager {
    /// Create a new ServiceManager
    pub fn new(db: Arc<SqliteDatabase>, config: Arc<NodeConfig>) -> Self {
        ServiceManager {
            db,
            network_id: config.network_id.clone(),
            services: Arc::new(RwLock::new(HashMap::new())),
            config,
            node_handler: None,
        }
    }

    /// Create a new ServiceManager from a reference to NodeConfig
    pub fn new_from_ref(db: Arc<SqliteDatabase>, config: &NodeConfig) -> Self {
        // Create a new Arc<NodeConfig> from the reference by cloning
        let config_clone = config.clone();
        let config_arc = Arc::new(config_clone);

        ServiceManager {
            db,
            network_id: config.network_id.clone(),
            services: Arc::new(RwLock::new(HashMap::new())),
            config: config_arc,
            node_handler: None,
        }
    }

    /// Get the network ID
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Get the node configuration
    pub fn config(&self) -> Arc<NodeConfig> {
        self.config.clone()
    }

    /// Get the database connection
    pub fn get_db(&self) -> &Arc<SqliteDatabase> {
        &self.db
    }

    /// Initialize services
    pub async fn init_services(&mut self) -> Result<()> {
        info!("Initializing services for network ID: {}", self.network_id);

        // Require a valid node handler
        let node_handler = self.node_handler.clone()
            .ok_or_else(|| anyhow!("No node handler configured - ServiceManager must be initialized with a valid node handler"))?;

        // Create a request context for initialization
        let request_context = Arc::new(RequestContext::new_with_option(
            "service_manager".to_string(),
            None,
            node_handler,
        ));

        // Initialize the registry service
        let registry_service =
            crate::services::service_registry::ServiceRegistry::new(&self.network_id);
        
        // No need to initialize or start - ServiceRegistry is not an AbstractService

        // Get a reference to use later
        let _registry = Arc::new(registry_service);
        
        // Initialize the SQLite service
        let mut sqlite_service = sqlite::SqliteService::new(self.db.clone(), &self.network_id);
        sqlite_service.init(&request_context).await?;
        sqlite_service.start().await?;

        // Add it to our services map
        self.register_service(Arc::new(sqlite_service)).await?;

        // Initialize the node info service
        let mut node_info_service =
            node_info::NodeInfoService::new(&self.network_id, self.config.clone());
        node_info_service.init(&request_context).await?;
        node_info_service.start().await?;

        // Add it to our services map
        self.register_service(Arc::new(node_info_service)).await?;

        // Load services from the registry database
        let services = self.list_services().await;
        log::info!("Services initialized: {}", services.join(", "));

        Ok(())
    }

    /// Register a service with the ServiceManager
    /// Note: This is being refactored to use ServiceRegistry
    pub async fn register_service(&self, service: Arc<dyn AbstractService>) -> Result<()> {
        let mut services = self.services.write().await;
        let service_name = service.name().to_string();

        info!(
            "Registering service: {} at {}",
            service_name,
            service.path()
        );

        if services.contains_key(&service_name) {
            return Err(anyhow!("Service '{}' is already registered", service_name));
        }

        services.insert(service_name, service);

        Ok(())
    }

    /// Get a service by name
    pub async fn get_service(&self, name: &str) -> Option<Arc<dyn AbstractService>> {
        let services = self.services.read().await;
        services.get(name).cloned()
    }

    /// Get a service by path
    pub async fn get_service_by_path(&self, path: &str) -> Option<Arc<dyn AbstractService>> {
        let services = self.services.read().await;

        // Check for direct matches first
        for service in services.values() {
            if service.path() == path {
                return Some(service.clone());
            }
        }

        // Check for matches with the network ID prefix
        let full_path = if !path.starts_with(&self.network_id) {
            format!("{}/{}", self.network_id, path)
        } else {
            path.to_string()
        };

        for service in services.values() {
            if service.path() == full_path {
                return Some(service.clone());
            }
            // Also check if the path is just the service name
            if service.name() == path {
                return Some(service.clone());
            }
        }

        None
    }

    /// List all services
    pub async fn list_services(&self) -> Vec<String> {
        let services = self.services.read().await;
        services.keys().cloned().collect()
    }

    /// Get all services
    pub async fn get_all_services(&self) -> Vec<Arc<dyn AbstractService>> {
        let services = self.services.read().await;
        services.values().cloned().collect()
    }

    /// Handle a service request
    pub async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        // Get the service from the path
        let service_path = request.path.clone();
        let service = self.get_service_by_path(&service_path).await;

        match service {
            Some(service) => {
                // Forward the request to the service
                service.handle_request(request).await
            }
            None => {
                // Service not found
                Ok(ServiceResponse::error(format!(
                    "Service not found: {}",
                    service_path
                )))
            }
        }
    }

    /// Clone the ServiceManager
    pub fn clone(&self) -> Self {
        ServiceManager {
            db: self.db.clone(),
            network_id: self.network_id.clone(),
            services: self.services.clone(),
            config: self.config.clone(),
            node_handler: self.node_handler.clone(),
        }
    }

    /// Create a service manager from a NodeConfig
    pub fn create_from_node_config(config: Arc<NodeConfig>, db: Arc<SqliteDatabase>) -> Self {
        ServiceManager {
            db,
            network_id: config.network_id.to_string(),
            services: Arc::new(RwLock::new(HashMap::new())),
            config,
            node_handler: None,
        }
    }

    /// Create a service manager from a NodeConfig (owned version)
    pub fn create_from_config(config: &NodeConfig, db: Arc<SqliteDatabase>) -> Self {
        let config_arc = Arc::new(config.clone());
        ServiceManager {
            db,
            network_id: config.network_id.to_string(),
            services: Arc::new(RwLock::new(HashMap::new())),
            config: config_arc,
            node_handler: None,
        }
    }
}

// Re-export value conversion utilities from rust-common
pub use runar_common::utils::to_value_type;

/// Request context for service requests
///
/// It allows services to make requests to other services, publish events, and subscribe to events
/// without having direct access to the node instance.
#[derive(Clone)]
pub struct RequestContext {
    /// The path of the request
    pub path: String,
    /// Data associated with the request
    pub data: ValueType,
    /// Node handler for making requests to other services
    #[doc(hidden)]
    pub node_handler: Arc<dyn NodeRequestHandler + Send + Sync>,
    /// Explicit service path for the caller (extracted from path)
    /// Note: This field is currently populated automatically from the path
    /// but will require explicit initialization in a future version.
    service_path: String,
    /// Explicit network ID for the caller (extracted from path)
    /// Note: This field is currently populated automatically from the path
    /// but will require explicit initialization in a future version.
    network_id: String,
}

impl std::fmt::Debug for RequestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestContext")
            .field("path", &self.path)
            .field("data", &self.data)
            .field("node_handler", &"<node_handler>")
            .field("service_path", &self.service_path)
            .field("network_id", &self.network_id)
            .finish()
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        // Create a minimal implementation of NodeRequestHandler for default contexts
        struct MinimalDefaultHandler;
        
        #[async_trait::async_trait]
        impl NodeRequestHandler for MinimalDefaultHandler {
            async fn request(&self, _path: String, _params: ValueType) -> Result<ServiceResponse> {
                Ok(ServiceResponse::error("Default RequestContext used - not intended for production use"))
            }
            
            async fn publish(&self, _topic: String, _data: ValueType) -> Result<()> {
                Ok(())
            }
            
            async fn subscribe(
                &self,
                _topic: String,
                _callback: Box<dyn Fn(ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
            ) -> Result<String> {
                Ok("default-subscription".to_string())
            }
            
            async fn subscribe_with_options(
                &self,
                _topic: String,
                _callback: Box<dyn Fn(ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
                _options: SubscriptionOptions,
            ) -> Result<String> {
                Ok("default-subscription".to_string())
            }
            
            async fn unsubscribe(&self, _topic: String, _subscription_id: Option<&str>) -> Result<()> {
                Ok(())
            }
            
            fn current_context(&self) -> Option<RequestContext> {
                None
            }
        }
        
        RequestContext {
            path: "default-context".to_string(),
            data: ValueType::Map(HashMap::new()),
            node_handler: Arc::new(MinimalDefaultHandler),
            service_path: "default".to_string(),
            network_id: "default".to_string(),
        }
    }
}

impl RequestContext {
    /// Create a new RequestContext with explicit service path and network ID
    /// 
    /// This is the preferred constructor that allows specifying exact service path and network ID.
    /// In a future version, this will become the primary constructor and the 3-parameter version
    /// will be deprecated.
    pub fn new_with_option_v2<P: AsRef<str>>(
        path: P,
        data: Option<ValueType>,
        node_handler: Arc<dyn NodeRequestHandler + Send + Sync>,
        service_path: String,
        network_id: String,
    ) -> Self {
        RequestContext {
            path: path.as_ref().to_string(),
            data: data.unwrap_or_else(|| ValueType::Map(HashMap::new())),
            node_handler,
            service_path,
            network_id,
        }
    }

    /// Create a new RequestContext with optional ValueType
    /// 
    /// Note: This method signature will change in a future version to require
    /// explicit service_path and network_id parameters. This version automatically
    /// extracts those values from the path.
    pub fn new_with_option<P: AsRef<str>>(
        path: P,
        data: Option<ValueType>,
        node_handler: Arc<dyn NodeRequestHandler + Send + Sync>,
    ) -> Self {
        // Extract service path and network ID from path if possible
        let path_str = path.as_ref();
        let (service_path, network_id) = match crate::routing::TopicPath::parse(path_str, "") {
            Ok(tp) => (tp.service_path.clone(), tp.network_id.clone()),
            Err(_) => {
                // Fallback to extracting just the service part
                let parts: Vec<&str> = path_str.split('/').collect();
                if !parts.is_empty() {
                    (parts[0].to_string(), "".to_string())
                } else {
                    ("".to_string(), "".to_string())
                }
            }
        };
        
        Self::new_with_option_v2(path, data, node_handler, service_path, network_id)
    }

    /// Create a new RequestContext
    pub fn new<P: AsRef<str>, V: Into<ValueType>>(
        path: P,
        data: V,
        node_handler: Arc<dyn NodeRequestHandler + Send + Sync>,
    ) -> Self {
        Self::new_with_option(path, Some(data.into()), node_handler)
    }

    /// Create a RequestContext for a child request
    pub fn new_child<P: AsRef<str>, V: Into<ValueType>>(&self, path: P, data: V) -> Self {
        // Extract service path and network ID from the new path
        let path_str = path.as_ref();
        let (service_path, network_id) = match crate::routing::TopicPath::parse(path_str, &self.network_id) {
            Ok(tp) => (tp.service_path.clone(), tp.network_id.clone()),
            Err(_) => {
                // Fallback to extracting just the service part
                let parts: Vec<&str> = path_str.split('/').collect();
                if !parts.is_empty() {
                    (parts[0].to_string(), self.network_id.clone())
                } else {
                    (self.service_path.clone(), self.network_id.clone())
                }
            }
        };
        
        RequestContext {
            path: path.as_ref().to_string(),
            data: data.into(),
            node_handler: self.node_handler.clone(),
            service_path,
            network_id,
        }
    }
    
    /// Get the service path of the caller (now direct field access)
    pub fn service_path(&self) -> &str {
        &self.service_path
    }
    
    /// Get the network ID (now direct field access)
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Get a context value
    pub fn get(&self, key: &str) -> Option<ValueType> {
        match &self.data {
            ValueType::Map(map) => map.get(key).cloned(),
            ValueType::Json(json) => json.get(key).map(|v| ValueType::Json(v.clone())),
            _ => None,
        }
    }

    /// Set a context value
    pub fn set(&mut self, key: &str, value: ValueType) {
        match &mut self.data {
            ValueType::Map(map) => {
                map.insert(key.to_string(), value);
            }
            _ => {
                let mut map = HashMap::new();
                map.insert(key.to_string(), value);
                self.data = ValueType::Map(map);
            }
        }
    }

    /// Publish an event to a topic
    pub async fn publish<T: Into<String>, V: Into<ValueType>>(&self, topic: T, data: V) -> Result<()> {
        self.node_handler.publish(topic.into(), data.into()).await
    }

    /// Subscribe to events on a topic with an async callback
    pub async fn subscribe<T: Into<String>, F, Fut>(&self, topic: T, callback: F) -> Result<String>
    where
        F: Fn(ValueType) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let topic_str = topic.into();
        
        // Create a wrapper function that returns a Pin<Box<dyn Future>>
        let wrapper = Box::new(move |value: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
            Box::pin(callback(value))
        });
        
        self.node_handler.subscribe(
            topic_str,
            wrapper,
        ).await
    }

    /// Subscribe to events with additional options
    pub async fn subscribe_with_options<T: Into<String>, F, Fut>(
        &self, 
        topic: T,
        callback: F,
        mut options: SubscriptionOptions,
    ) -> Result<String>
    where
        F: Fn(ValueType) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let topic_str = topic.into();
        
        // Create a wrapper function that returns a Pin<Box<dyn Future>>
        let wrapper = Box::new(move |value: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
            Box::pin(callback(value))
        });
        
        // Set the context in the options if not already set
        options.context = self.clone();
        
        self.node_handler.subscribe_with_options(
            topic_str,
            wrapper,
            options,
        ).await
    }

    /// Unsubscribe from events on a topic
    pub async fn unsubscribe<T: Into<String>>(&self, topic: T, subscription_id: Option<&str>) -> Result<()> {
        self.node_handler.unsubscribe(topic.into(), subscription_id).await
    }

    /// Subscribe once to an event - automatically unsubscribes after first notification
    pub async fn once<T: Into<String>, F, Fut>(&self, topic: T, callback: F) -> Result<String>
    where
        F: Fn(ValueType) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let mut options = SubscriptionOptions::new(self.clone());
        options.once = true;
        self.subscribe_with_options(topic, callback, options).await
    }

    /// Get the request path
    pub fn path(&self) -> &str {
        &self.path
    }
}

#[cfg(test)]
mod request_context_tests {
    use super::*;
    use crate::routing::TopicPath;
    
    #[test]
    fn test_request_context_with_explicit_path() {
        let handler = Arc::new(create_test_handler());
        
        // Create context with explicit service path and network ID
        let context = RequestContext::new_with_option_v2(
            "service/action",
            None,
            handler.clone(),
            "custom_service".to_string(),
            "test_network".to_string()
        );
        
        // Verify the explicit values were used
        assert_eq!(context.service_path(), "custom_service");
        assert_eq!(context.network_id(), "test_network");
        
        // Verify that path was preserved as-is
        assert_eq!(context.path, "service/action");
    }
    
    #[test]
    fn test_request_context_path_extraction() {
        let handler = Arc::new(create_test_handler());
        
        // Test with service/action format
        let context = RequestContext::new_with_option(
            "service/action",
            None,
            handler.clone()
        );
        
        // Verify extraction worked correctly
        assert_eq!(context.service_path(), "service");
        assert_eq!(context.network_id(), "");
        
        // Test with network:service/action format
        let context2 = RequestContext::new_with_option(
            "network:service/action",
            None,
            handler.clone()
        );
        
        // Verify extraction parsed the network ID
        assert_eq!(context2.service_path(), "service");
        assert_eq!(context2.network_id(), "network");
    }
    
    #[test]
    fn test_request_context_child() {
        let handler = Arc::new(create_test_handler());
        
        // Create parent context with explicit network
        let parent = RequestContext::new_with_option_v2(
            "parent/action",
            None,
            handler.clone(),
            "parent".to_string(),
            "test_network".to_string()
        );
        
        // Create child context
        let child = parent.new_child("child/action", "test_data");
        
        // Verify child inherited network ID
        assert_eq!(child.service_path(), "child");
        assert_eq!(child.network_id(), "test_network");
        assert_eq!(child.path, "child/action");
    }
    
    // Helper function to create a test handler
    fn create_test_handler() -> impl NodeRequestHandler {
        // Simplified implementation for testing
        struct TestHandler;
        
        #[async_trait::async_trait]
        impl NodeRequestHandler for TestHandler {
            async fn request(&self, _path: String, _params: ValueType) -> Result<ServiceResponse> {
                Ok(ServiceResponse::success("Test".to_string(), None::<ValueType>))
            }
            
            async fn publish(&self, _topic: String, _data: ValueType) -> Result<()> {
                Ok(())
            }
            
            async fn subscribe(
                &self,
                _topic: String,
                _callback: Box<dyn Fn(ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
            ) -> Result<String> {
                Ok("test-id".to_string())
            }
            
            async fn subscribe_with_options(
                &self,
                _topic: String,
                _callback: Box<dyn Fn(ValueType) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>,
                _options: SubscriptionOptions,
            ) -> Result<String> {
                Ok("test-id".to_string())
            }
            
            async fn unsubscribe(&self, _topic: String, _subscription_id: Option<&str>) -> Result<()> {
                Ok(())
            }
        }
        
        TestHandler
    }
}

