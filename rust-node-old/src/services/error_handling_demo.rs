//! A demo service to demonstrate the standardized error handling approach

use anyhow::{Result, Context};
use async_trait::async_trait;
use log::{debug, info};
use std::sync::Arc;

use crate::services::{
    AbstractService, RequestContext, ServiceRequest, ServiceResponse, ServiceResponseExt, ServiceState,
};
use crate::services::abstract_service::{ActionMetadata, EventMetadata};
use runar_common::errors::{
    ServiceError, DatabaseError, NetworkError, ConfigError, ConversionError
};
use runar_common::types::ValueType;

/// Demo service that demonstrates the standardized error handling approach
pub struct ErrorHandlingDemoService {
    /// Service name
    name: String,
    /// Service path
    path: String,
    /// Service state
    state: ServiceState,
}

impl ErrorHandlingDemoService {
    /// Create a new demo service
    pub fn new(network_id: &str) -> Self {
        ErrorHandlingDemoService {
            name: "error_demo".to_string(),
            path: format!("{}/error_demo", network_id),
            state: ServiceState::Created,
        }
    }
    
    /// Demo method that returns a service error
    async fn demo_service_error(&self, request: &ServiceRequest) -> Result<ServiceResponse> {
        debug!("Processing service error demo with request: {:?}", request);
        
        // Extract the error type from the request
        let error_type = if let Some(ValueType::Map(data)) = &request.data {
            if let Some(ValueType::String(error_type)) = data.get("error_type") {
                error_type.as_str()
            } else {
                "service_not_found"
            }
        } else {
            "service_not_found"
        };
        
        // Create an error based on the requested type
        let error = match error_type {
            "service_not_found" => ServiceError::ServiceNotFound("demo_service".to_string()),
            "unsupported_operation" => ServiceError::UnsupportedOperation(
                "invalid_operation".to_string(), 
                "error_demo".to_string()
            ),
            "authorization_failed" => ServiceError::AuthorizationFailed(
                "protected_action".to_string(),
                "error_demo".to_string()
            ),
            "invalid_request" => ServiceError::InvalidRequest(
                "Missing required parameter 'id'".to_string()
            ),
            "database" => ServiceError::Database(
                DatabaseError::QueryError("SQL syntax error near 'WHERE'".to_string())
            ),
            "network" => ServiceError::Network(
                NetworkError::ConnectionError("Connection refused".to_string())
            ),
            "internal" => ServiceError::Internal(
                "Unexpected internal error".to_string()
            ),
            _ => ServiceError::ServiceNotFound("unknown_service".to_string()),
        };
        
        // Return the error response using our new extension method
        Ok(ServiceResponse::from_service_error(error))
    }
    
    /// Demo method that returns a database error
    async fn demo_database_error(&self, request: &ServiceRequest) -> Result<ServiceResponse> {
        debug!("Processing database error demo with request: {:?}", request);
        
        // Extract the error type from the request
        let error_type = if let Some(ValueType::Map(data)) = &request.data {
            if let Some(ValueType::String(error_type)) = data.get("error_type") {
                error_type.as_str()
            } else {
                "connection"
            }
        } else {
            "connection"
        };
        
        // Create an error based on the requested type
        let error = match error_type {
            "connection" => DatabaseError::ConnectionError(
                "Failed to connect to database: connection refused".to_string()
            ),
            "query" => DatabaseError::QueryError(
                "SQL syntax error in query".to_string()
            ),
            "migration" => DatabaseError::MigrationError(
                "Failed to apply migration: table already exists".to_string()
            ),
            "not_found" => DatabaseError::NotFound(
                "Record with ID '123' not found".to_string()
            ),
            "constraint" => DatabaseError::ConstraintViolation(
                "Unique constraint violated for field 'email'".to_string()
            ),
            "transaction" => DatabaseError::TransactionError(
                "Transaction failed to commit".to_string()
            ),
            _ => DatabaseError::QueryError("Unknown database error".to_string()),
        };
        
        // Return the error response using our new extension method
        Ok(ServiceResponse::from_database_error(error))
    }
    
    /// Demo method that returns a network error
    async fn demo_network_error(&self, _request: &ServiceRequest) -> Result<ServiceResponse> {
        let error = NetworkError::ConnectionError(
            "Failed to connect to peer at 192.168.1.100:8000".to_string()
        );
        
        Ok(ServiceResponse::from_network_error(error))
    }
    
    /// Demo method that returns a config error
    async fn demo_config_error(&self, _request: &ServiceRequest) -> Result<ServiceResponse> {
        let error = ConfigError::MissingValue(
            "Required configuration value 'database.url' is missing".to_string()
        );
        
        Ok(ServiceResponse::from_config_error(error))
    }
    
    /// Demo method that returns a conversion error
    async fn demo_conversion_error(&self, _request: &ServiceRequest) -> Result<ServiceResponse> {
        let error = ConversionError::TypeConversionFailed(
            "user_id".to_string(),
            "integer".to_string(),
            "Value 'abc' cannot be converted to an integer".to_string()
        );
        
        Ok(ServiceResponse::from_conversion_error(error))
    }
    
    /// Demo method that uses anyhow errors
    async fn demo_anyhow_error(&self, _request: &ServiceRequest) -> Result<ServiceResponse> {
        // Create an error chain with anyhow
        let raw_error = anyhow::anyhow!("Primary error");
        let result: Result<ValueType> = Err(raw_error)
            .with_context(|| "Additional context")
            .with_context(|| "Even more context");
            
        // Use the from_result extension method to convert the Result<ValueType> to Result<ServiceResponse>
        ServiceResponse::from_result(result)
    }
    
    /// Demo method for context-based error handling
    async fn demo_context_error(&self, _request: &ServiceRequest) -> Result<ServiceResponse> {
        // Simulate a failing operation with context
        let base_error = anyhow::anyhow!("Database connection failed");
        let operation_result: Result<String> = Err(base_error)
            .with_context(|| "Error while fetching user profile")
            .with_context(|| "User profile service unavailable");
            
        // Convert to a ServiceResponse manually
        match operation_result {
            Ok(value) => Ok(ServiceResponse::success("Operation successful".to_string(), Some(value))),
            Err(err) => Ok(ServiceResponse::from_error(err)),
        }
    }
}

#[async_trait]
impl AbstractService for ErrorHandlingDemoService {
    fn name(&self) -> &str {
        &self.name
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn state(&self) -> ServiceState {
        self.state
    }
    
    fn version(&self) -> &str {
        "1.0"
    }
    
    fn description(&self) -> &str {
        "A demo service to demonstrate the standardized error handling approach"
    }
    
    fn actions(&self) -> Vec<ActionMetadata> {
        vec![
            ActionMetadata { name: "service_error".to_string() },
            ActionMetadata { name: "database_error".to_string() },
            ActionMetadata { name: "network_error".to_string() },
            ActionMetadata { name: "config_error".to_string() },
            ActionMetadata { name: "conversion_error".to_string() },
            ActionMetadata { name: "anyhow_error".to_string() },
            ActionMetadata { name: "context_error".to_string() },
        ]
    }
    
    fn events(&self) -> Vec<EventMetadata> {
        Vec::new()
    }
    
    async fn init(&mut self, _context: &RequestContext) -> Result<()> {
        info!("Initializing ErrorHandlingDemoService");
        self.state = ServiceState::Initialized;
        Ok(())
    }
    
    async fn start(&mut self) -> Result<()> {
        info!("Starting ErrorHandlingDemoService");
        self.state = ServiceState::Running;
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        info!("Stopping ErrorHandlingDemoService");
        self.state = ServiceState::Stopped;
        Ok(())
    }
    
    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        debug!("ErrorHandlingDemoService handling request: {:?}", request);
        
        match request.action.as_str() {
            "service_error" => self.demo_service_error(&request).await,
            "database_error" => self.demo_database_error(&request).await,
            "network_error" => self.demo_network_error(&request).await,
            "config_error" => self.demo_config_error(&request).await,
            "conversion_error" => self.demo_conversion_error(&request).await,
            "anyhow_error" => self.demo_anyhow_error(&request).await,
            "context_error" => self.demo_context_error(&request).await,
            _ => {
                // Handle unknown action using the new error type
                let error = ServiceError::UnsupportedOperation(
                    request.action,
                    self.name.clone()
                );
                Ok(ServiceResponse::from_service_error(error))
            }
        }
    }
} 