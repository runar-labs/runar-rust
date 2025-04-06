use anyhow::Result;
use async_trait::async_trait;
use runar_node::services::abstract_service::{AbstractService, ServiceState, ActionMetadata};
use runar_node::services::ResponseStatus;
use runar_node::{ServiceRequest, ServiceResponse};
use runar_common::types::ValueType;
use runar_common::vmap_f64;

/// A simple math service for testing purposes
#[derive(Clone)]
pub struct MathService {
    name: String,
    state: ServiceState,
}

impl MathService {
    /// Create a new math service
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            state: ServiceState::Created,
        }
    }
    
    /// Handle add operation: adds two numbers
    async fn handle_add(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        let a = match &request.data {
            Some(data) => vmap_f64!(data, "a", 0.0),
            None => 0.0,
        };
        let b = match &request.data {
            Some(data) => vmap_f64!(data, "b", 0.0),
            None => 0.0,
        };
        let result = a + b;
        
        Ok(ServiceResponse {
            status: ResponseStatus::Success,
            message: format!("{} + {} = {}", a, b, result),
            data: Some(ValueType::Number(result)),
        })
    }
    
    /// Handle subtract operation: subtracts second number from first
    async fn handle_subtract(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        let a = match &request.data {
            Some(data) => vmap_f64!(data, "a", 0.0),
            None => 0.0,
        };
        let b = match &request.data {
            Some(data) => vmap_f64!(data, "b", 0.0),
            None => 0.0,
        };
        let result = a - b;
        
        Ok(ServiceResponse {
            status: ResponseStatus::Success,
            message: format!("{} - {} = {}", a, b, result),
            data: Some(ValueType::Number(result)),
        })
    }
    
    /// Handle multiply operation: multiplies two numbers
    async fn handle_multiply(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        let a = match &request.data {
            Some(data) => vmap_f64!(data, "a", 0.0),
            None => 0.0,
        };
        let b = match &request.data {
            Some(data) => vmap_f64!(data, "b", 0.0),
            None => 0.0,
        };
        let result = a * b;
        
        Ok(ServiceResponse {
            status: ResponseStatus::Success,
            message: format!("{} * {} = {}", a, b, result),
            data: Some(ValueType::Number(result)),
        })
    }
    
    /// Handle divide operation: divides first number by second
    async fn handle_divide(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        let a = match &request.data {
            Some(data) => vmap_f64!(data, "a", 0.0),
            None => 0.0,
        };
        let b = match &request.data {
            Some(data) => vmap_f64!(data, "b", 1.0),
            None => 1.0,
        };
        
        if b == 0.0 {
            return Ok(ServiceResponse {
                status: ResponseStatus::Error,
                message: "Cannot divide by zero".to_string(),
                data: None,
            });
        }
        
        let result = a / b;
        
        Ok(ServiceResponse {
            status: ResponseStatus::Success,
            message: format!("{} / {} = {}", a, b, result),
            data: Some(ValueType::Number(result)),
        })
    }
}

#[async_trait]
impl AbstractService for MathService {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn path(&self) -> &str {
        "math"
    }
    
    fn state(&self) -> ServiceState {
        self.state
    }
    
    fn description(&self) -> &str {
        "A simple math service that provides basic arithmetic operations"
    }
    
    fn version(&self) -> &str {
        "1.0.0"
    }
    
    fn actions(&self) -> Vec<ActionMetadata> {
        vec![
            ActionMetadata { name: "add".to_string() },
            ActionMetadata { name: "subtract".to_string() },
            ActionMetadata { name: "multiply".to_string() },
            ActionMetadata { name: "divide".to_string() },
        ]
    }
    
    async fn init(&mut self, _ctx: &runar_node::RequestContext) -> Result<()> {
        println!("MathService init called");
        self.state = ServiceState::Initialized;
        Ok(())
    }
    
    async fn start(&mut self) -> Result<()> {
        println!("MathService start called");
        self.state = ServiceState::Running;
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        println!("MathService stop called");
        self.state = ServiceState::Stopped;
        Ok(())
    }
    
    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        // Debug the exact request path and action we're receiving
        println!("\n=== MathService handle_request called ===");
        println!("Path: '{}'", request.path);
        println!("Action: '{}'", request.action);
        
        // Delegate to specialized methods based on action
        match request.action.as_str() {
            "add" => self.handle_add(request).await,
            "subtract" => self.handle_subtract(request).await,
            "multiply" => self.handle_multiply(request).await,
            "divide" => self.handle_divide(request).await,
            _ => {
                println!("  → Error: unknown action '{}'", request.action);
                Ok(ServiceResponse {
                    status: ResponseStatus::Error,
                    message: format!("Unknown action: {}", request.action),
                    data: None,
                })
            }
        }
    }
} 