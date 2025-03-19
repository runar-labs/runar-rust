use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use serde::{Serialize, Deserialize};

/// Service information trait
pub trait ServiceInfo: Send + Sync {
    /// Get the service name
    fn service_name(&self) -> &str;
    
    /// Get the service path
    fn service_path(&self) -> &str;
    
    /// Get the service description
    fn service_description(&self) -> &str;
    
    /// Get the service version
    fn service_version(&self) -> &str;
}

/// Service state
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ServiceState {
    /// Service is initializing
    Initializing,
    /// Service is running
    Running,
    /// Service is stopped
    Stopped,
    /// Service has encountered an error
    Error,
}

/// Service metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceMetadata {
    /// Service name
    pub name: String,
    /// Service path
    pub path: String,
    /// Service state
    pub state: ServiceState,
    /// Service description
    pub description: String,
    /// Service operations
    pub operations: Vec<String>,
    /// Service version
    pub version: String,
}

/// Service response status
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ResponseStatus {
    /// Success response
    Success,
    /// Error response
    Error,
}

/// Value type for request parameters and response data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ValueType {
    /// String value
    String(String),
    /// Integer value
    Integer(i64),
    /// Float value
    Float(f64),
    /// Boolean value
    Boolean(bool),
    /// Array of values
    Array(Vec<ValueType>),
    /// Map of key-value pairs
    Map(HashMap<String, ValueType>),
    /// Binary data
    Bytes(Vec<u8>),
    /// Null value
    Null,
}

impl Default for ValueType {
    fn default() -> Self {
        ValueType::Null
    }
}

/// Service request
#[derive(Clone, Debug)]
pub struct ServiceRequest {
    /// Request ID
    pub request_id: Option<String>,
    /// Service path
    pub path: String,
    /// Operation to perform
    pub operation: String,
    /// Operation parameters
    pub params: Option<ValueType>,
    /// Request context
    pub request_context: Arc<RequestContext>,
}

/// Service response
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceResponse {
    /// Response status
    pub status: ResponseStatus,
    /// Response message
    pub message: String,
    /// Response data
    pub data: Option<ValueType>,
}

impl ServiceResponse {
    /// Create a success response
    pub fn success(message: String) -> Self {
        Self {
            status: ResponseStatus::Success,
            message,
            data: None,
        }
    }
    
    /// Create a success response with data
    pub fn success_with_data(message: String, data: ValueType) -> Self {
        Self {
            status: ResponseStatus::Success,
            message,
            data: Some(data),
        }
    }
    
    /// Create an error response
    pub fn error(message: String) -> Self {
        Self {
            status: ResponseStatus::Error,
            message,
            data: None,
        }
    }
}

/// Request context
pub struct RequestContext {
    /// Request source
    pub source: String,
    /// Request parameters
    pub params: HashMap<String, ValueType>,
    /// Node request handler
    pub node: Arc<dyn NodeRequestHandler>,
}

impl RequestContext {
    /// Create a new request context
    pub fn new(
        source: String,
        params: HashMap<String, ValueType>,
        node: Arc<dyn NodeRequestHandler>,
    ) -> Self {
        Self {
            source,
            params,
            node,
        }
    }
    
    /// Create a new request context with optional parameters
    pub fn new_with_option(
        source: String,
        params: Option<ValueType>,
        node: Arc<dyn NodeRequestHandler>,
    ) -> Self {
        let params_map = match params {
            Some(ValueType::Map(map)) => map,
            Some(other) => {
                let mut map = HashMap::new();
                map.insert("value".to_string(), other);
                map
            },
            None => HashMap::new(),
        };
        
        Self {
            source,
            params: params_map,
            node,
        }
    }
    
    /// Get the service path from the source
    pub fn service_path(&self) -> String {
        if self.source.contains('/') {
            self.source.split('/').next().unwrap_or("").to_string()
        } else {
            self.source.clone()
        }
    }
    
    /// Subscribe to a topic
    pub async fn subscribe<F, Fut>(&self, topic: &str, handler: F) -> Result<()>
    where
        F: Fn(ValueType) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        // In a real implementation, this would register the subscription
        Ok(())
    }
    
    /// Publish an event to a topic
    pub async fn publish(&self, topic: &str, data: ValueType) -> Result<()> {
        // Use the node to publish the event
        self.node.publish(topic.to_string(), data).await
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        // Create a dummy node handler
        let dummy_node = Arc::new(DummyNodeHandler {});
        
        Self {
            source: "default".to_string(),
            params: HashMap::new(),
            node: dummy_node,
        }
    }
}

/// Node request handler
#[async_trait]
pub trait NodeRequestHandler: Send + Sync {
    /// Make a request to a service
    async fn request(&self, path: String, params: ValueType) -> Result<ServiceResponse>;
    
    /// Publish an event to a topic
    async fn publish(&self, topic: String, data: ValueType) -> Result<()> {
        // Default implementation does nothing
        Ok(())
    }
}

/// Dummy node handler for default context
struct DummyNodeHandler {}

#[async_trait]
impl NodeRequestHandler for DummyNodeHandler {
    async fn request(&self, _path: String, _params: ValueType) -> Result<ServiceResponse> {
        Ok(ServiceResponse::error("DummyNodeHandler cannot process requests".to_string()))
    }
}

/// Abstract service trait
#[async_trait]
pub trait AbstractService: ServiceInfo + Send + Sync {
    /// Get the service name
    fn name(&self) -> &str;
    
    /// Get the service path
    fn path(&self) -> &str;
    
    /// Get the service description
    fn description(&self) -> &str;
    
    /// Get the service state
    fn state(&self) -> ServiceState;
    
    /// Get the service metadata
    fn metadata(&self) -> ServiceMetadata;
    
    /// Initialize the service
    async fn init(&mut self, context: &RequestContext) -> Result<()>;
    
    /// Start the service
    async fn start(&mut self) -> Result<()>;
    
    /// Stop the service
    async fn stop(&mut self) -> Result<()>;
    
    /// Handle a service request
    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse>;
    
    /// Handle an operation
    async fn handle_operation(&self, operation: &str, params: &Option<ValueType>) -> Result<ServiceResponse>;
} 