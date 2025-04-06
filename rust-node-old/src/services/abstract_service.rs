use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::services::{ServiceRequest, ServiceResponse, RequestContext};

/// Represents the lifecycle state of a service
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    /// Service is created but not initialized
    Created,
    /// Service is initialized but not running
    Initialized,
    /// Service is running
    Running,
    /// Service is paused
    Paused,
    /// Service is stopped
    Stopped,
    /// Service has failed
    Failed,
}

/// Metadata about a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMetadata {
    /// The name of the service
    pub name: String,
    /// The path of the service
    pub path: String,
    /// Current state of the service
    pub state: ServiceState,
    /// Description of the service
    pub description: String,
    /// Available operations on the service
    pub operations: Vec<String>,
    /// Service version
    pub version: String,
}

/// Metadata about an action provided by a service
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionMetadata {
    /// The name of the action
    pub name: String,
}

/// Metadata about an event emitted by a service
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMetadata {
    /// The name of the event
    pub name: String,
}

/// CRUD operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrudOperationType {
    /// Create a new document
    Create,
    /// Read documents
    Read,
    /// Update documents
    Update,
    /// Delete documents
    Delete,
}

/// Abstract service trait - defines common behavior for all services
#[async_trait]
pub trait AbstractService: Send + Sync + 'static {
    /// Get the service name
    fn name(&self) -> &str;

    /// Get the service path
    fn path(&self) -> &str;

    /// Get the current state of the service
    fn state(&self) -> ServiceState;

    /// Get a description of the service
    fn description(&self) -> &str;
    
    /// Get the service version
    fn version(&self) -> &str;
    
    /// Get metadata about actions provided by this service
    fn actions(&self) -> Vec<ActionMetadata> {
        // Default empty implementation
        Vec::new()
    }
    
    /// Get metadata about the events emitted by this service
    fn events(&self) -> Vec<EventMetadata> {
        // Default empty implementation
        Vec::new()
    }

    /// Initialize the service with a request context
    async fn init(&mut self, ctx: &RequestContext) -> Result<()>;

    /// Start the service
    async fn start(&mut self) -> Result<()>;

    /// Stop the service
    async fn stop(&mut self) -> Result<()>;

    /// Handle a service request
    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse>;

    /// Get information about the service
    async fn get_info(&self) -> Result<crate::services::ValueType> {
        let mut map = std::collections::HashMap::new();
        map.insert("name".to_string(), crate::services::ValueType::String(self.name().to_string()));
        map.insert("path".to_string(), crate::services::ValueType::String(self.path().to_string()));
        map.insert("state".to_string(), crate::services::ValueType::String(self.state().to_string()));
        map.insert("description".to_string(), crate::services::ValueType::String(self.description().to_string()));
        map.insert("version".to_string(), crate::services::ValueType::String(self.version().to_string()));
        Ok(crate::services::ValueType::Map(map))
    }
    
    /// Get metadata about the service (derived from other methods)
    fn metadata(&self) -> ServiceMetadata {
        ServiceMetadata {
            name: self.name().to_string(),
            path: self.path().to_string(),
            state: self.state(),
            description: self.description().to_string(),
            operations: self.actions().into_iter().map(|a| a.name).collect(),
            version: self.version().to_string(),
        }
    }
}

impl ServiceMetadata {
    pub fn new(operations: Vec<String>, description: String) -> Self {
        Self {
            operations,
            description,
            name: String::new(),
            path: String::new(),
            state: ServiceState::Created,
            version: String::new(),
        }
    }
}

impl Default for ServiceMetadata {
    fn default() -> Self {
        Self {
            name: String::new(),
            path: String::new(),
            state: ServiceState::Created,
            description: String::new(),
            operations: Vec::new(),
            version: String::new(),
        }
    }
}

impl fmt::Display for ServiceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceState::Created => write!(f, "Created"),
            ServiceState::Initialized => write!(f, "Initialized"),
            ServiceState::Running => write!(f, "Running"),
            ServiceState::Stopped => write!(f, "Stopped"),
            ServiceState::Failed => write!(f, "Failed"),
            ServiceState::Paused => write!(f, "Paused"),
        }
    }
}
