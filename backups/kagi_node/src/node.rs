use crate::services::{AbstractService, RequestContext, ServiceRequest, ServiceResponse, ServiceState, ServiceMetadata, ValueType, ResponseStatus, NodeRequestHandler};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{debug, info, warn, error};
use uuid;

/// Node implementation for the KAGI system
pub struct Node {
    // Service registry
    service_registry: Arc<RwLock<HashMap<String, Arc<dyn AbstractService>>>>,
    // Configuration
    config: NodeConfig,
}

/// Node configuration
pub struct NodeConfig {
    /// Node identifier
    pub id: String,
    /// Node data path
    pub data_path: String,
    /// Node database path
    pub db_path: String,
}

impl NodeConfig {
    /// Create a new node configuration
    pub fn new(id: &str, data_path: &str, db_path: &str) -> Self {
        Self {
            id: id.to_string(),
            data_path: data_path.to_string(),
            db_path: db_path.to_string(),
        }
    }
}

/// Node request handler implementation
pub struct NodeRequestHandlerImpl {
    /// Service registry
    service_registry: Arc<RwLock<HashMap<String, Arc<dyn AbstractService>>>>,
}

impl NodeRequestHandlerImpl {
    /// Create a new node request handler
    pub fn new(service_registry: Arc<RwLock<HashMap<String, Arc<dyn AbstractService>>>>) -> Self {
        Self { service_registry }
    }
}

#[async_trait::async_trait]
impl NodeRequestHandler for NodeRequestHandlerImpl {
    async fn request(&self, path: String, params: ValueType) -> Result<ServiceResponse> {
        // Parse the path into service name and operation
        // Format should be "serviceName/operation"
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow!(
                "Invalid path format, expected 'serviceName/operation'"
            ));
        }

        let service_name = parts[0].to_string();
        let operation = parts[1].to_string();

        // Create a request context for the request
        let context = Arc::new(RequestContext::new_with_option(
            format!("node_request_{}", uuid::Uuid::new_v4()),
            Some(params.clone()),
            Arc::new(NodeRequestHandlerImpl::new(self.service_registry.clone())),
        ));
        
        // Create a service request
        let request = ServiceRequest {
            path: service_name.clone(),
            operation,
            params: Some(params),
            request_id: Some(uuid::Uuid::new_v4().to_string()),
            request_context: context,
        };
        
        // Find the target service
        let services = self.service_registry.read().await;
        if let Some(service) = services.get(&service_name) {
            // Call the service
            service.handle_request(request).await
        } else {
            // Service not found
            Ok(ServiceResponse {
                status: ResponseStatus::Error,
                message: format!("Service not found: {}", service_name),
                data: None,
            })
        }
    }
    
    async fn publish(&self, topic: String, data: ValueType) -> Result<()> {
        // In a real implementation, this would use the event system
        println!("Publishing to topic {}: {:?}", topic, data);
        Ok(())
    }
}

impl Node {
    /// Create a new node
    pub async fn new(config: NodeConfig) -> Result<Self> {
        Ok(Self {
            service_registry: Arc::new(RwLock::new(HashMap::new())),
            config,
        })
    }
    
    /// Initialize the node
    pub async fn init(&mut self) -> Result<()> {
        // Here we would initialize core services
        info!("Node initialized with ID: {}", self.config.id);
        Ok(())
    }
    
    /// Start the node
    pub async fn start(&mut self) -> Result<()> {
        // Start all services
        info!("Node started");
        Ok(())
    }
    
    /// Stop the node
    pub async fn stop(&mut self) -> Result<()> {
        // Stop all services
        info!("Node stopped");
        Ok(())
    }
    
    /// Add a service to the node
    pub async fn add_service<S>(&mut self, mut service: S) -> Result<()>
    where
        S: AbstractService + 'static,
    {
        // Create a request context for initialization
        let request_context = Arc::new(RequestContext::new(
            service.name().to_string(),
            HashMap::new(),
            Arc::new(NodeRequestHandlerImpl::new(self.service_registry.clone())),
        ));

        // Initialize the service
        info!("Initializing service: {}", service.name());
        service.init(&request_context).await?;

        // Start the service
        info!("Starting service: {}", service.name());
        service.start().await?;

        // Register with the service registry
        let service_path = service.path().to_string();
        info!("Registering service: {} at path {}", service.name(), service_path);
        
        self.service_registry
            .write()
            .await
            .insert(service_path, Arc::new(service));

        Ok(())
    }
    
    /// Call a service with the given path, operation, and parameters
    pub async fn call<P: Into<String>, O: Into<String>, V: Into<ValueType>>(
        &self,
        path: P,
        operation: O,
        params: V,
    ) -> Result<ServiceResponse> {
        // Combine path and operation into the new format
        let path_str = path.into();
        let op_str = operation.into();
        let full_path = format!("{}/{}", path_str, op_str);

        // Forward to the request method
        self.request(full_path, params).await
    }

    /// Make a request to a service
    pub async fn request<P: Into<String>, V: Into<ValueType>>(
        &self,
        path: P,
        params: V,
    ) -> Result<ServiceResponse> {
        let path_str = path.into();
        let params_value = params.into();
        
        // Process the parameters and make the actual request
        self.process_request(path_str, params_value).await
    }
    
    /// Publish an event to a topic
    pub async fn publish<T: Into<String>, V: Into<ValueType>>(
        &self,
        topic: T,
        data: V,
    ) -> Result<()> {
        let topic_str = topic.into();
        let data_value = data.into();
        
        // Create a request handler to publish the event
        let node_handler = NodeRequestHandlerImpl::new(self.service_registry.clone());
        node_handler.publish(topic_str, data_value).await
    }
    
    /// Helper method that does the actual request processing
    async fn process_request(&self, path_str: String, params_value: ValueType) -> Result<ServiceResponse> {
        // Parse the path into service name and operation
        // Format should be "serviceName/operation"
        let parts: Vec<&str> = path_str.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow!(
                "Invalid path format, expected 'serviceName/operation'"
            ));
        }

        let service_name = parts[0].to_string();
        let operation = parts[1].to_string();
        
        // Create a request context for the request
        let context = Arc::new(RequestContext::new(
            format!("node_request_{}", uuid::Uuid::new_v4()),
            HashMap::new(),
            Arc::new(NodeRequestHandlerImpl::new(self.service_registry.clone())),
        ));
        
        // Handle direct parameter values (non-Map ValueType)
        let processed_params = match &params_value {
            ValueType::Map(_) => {
                // Already a map, use as is
                params_value
            },
            _ => {
                // For any other ValueType, we need to wrap it in a parameter map
                let param_name = self.guess_parameter_name(&service_name, &operation, &params_value);
                
                // Create a map with the single parameter
                let mut param_map = HashMap::new();
                param_map.insert(param_name, params_value);
                ValueType::Map(param_map)
            }
        };
        
        let request = ServiceRequest {
            path: service_name.clone(),
            operation,
            params: Some(processed_params),
            request_id: Some(uuid::Uuid::new_v4().to_string()),
            request_context: context,
        };
        
        // Find the target service
        let services = self.service_registry.read().await;
        if let Some(service) = services.get(&service_name) {
            // Call the service
            service.handle_request(request).await
        } else {
            // Service not found
            Ok(ServiceResponse {
                status: ResponseStatus::Error,
                message: format!("Service not found: {}", service_name),
                data: None,
            })
        }
    }

    /// Guess a parameter name based on the service, operation, and value type
    fn guess_parameter_name(&self, service: &str, operation: &str, value: &ValueType) -> String {
        // Common parameter names for specific operations
        match operation {
            "get" | "read" | "retrieve" | "fetch" => "id".to_string(),
            "search" | "find" | "query" => "query".to_string(),
            "create" | "add" | "insert" => "data".to_string(),
            "update" | "modify" | "edit" => "data".to_string(),
            "delete" | "remove" => "id".to_string(),
            _ => {
                // Fallback to value-type based naming
                match value {
                    ValueType::String(_) => "text".to_string(),
                    ValueType::Integer(_) => "id".to_string(),
                    ValueType::Float(_) => "value".to_string(),
                    ValueType::Boolean(_) => "flag".to_string(),
                    ValueType::Array(_) => "items".to_string(),
                    ValueType::Map(_) => "data".to_string(),
                    ValueType::Bytes(_) => "binary".to_string(),
                    ValueType::Null => "data".to_string(),
                }
            }
        }
    }
} 