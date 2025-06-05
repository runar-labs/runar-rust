// This file is temporarily disabled during migration from kagi to runar
// It needs to be updated to use the new crate names and structures
// Development tool for debugging macros only - not part of production build

/*
// This file is for debugging macro expansion
// See the generated code by running:
// cargo rustc --features=node_implementation -p runar_macros --bin macro_debug -- -Z unstable-options --pretty=expanded

use std::sync::Arc;
use runar_macros::{action, subscribe};
use runar_node::services::{RequestContext, ServiceResponse, ValueType, ServiceState, ServiceMetadata, ServiceRequest};
use anyhow::Result;
use runar_node::services::abstract_service::AbstractService;
use async_trait::async_trait;

// Define the ServiceInfo trait for testing
pub trait ServiceInfo {
    fn service_name(&self) -> &str;
    fn service_path(&self) -> &str;
    fn service_description(&self) -> &str;
    fn service_version(&self) -> &str;
}

// Define a simple service for testing macros
#[derive(Clone)]
pub struct DebugService {
    name: String,
}

impl DebugService {
    pub fn new() -> Self {
        Self {
            name: "debug_service".to_string(),
        }
    }

    // Test action macro
    #[action(name = "test_action")]
    async fn test_action(&self, data: String) -> Result<ServiceResponse> {
        println!("Test action called with data: {}", data);
        Ok(ServiceResponse::success("Action executed successfully".to_string(), Option::<String>::None))
    }

    // Test action with context
    #[action(name = "test_action_with_context")]
    async fn test_with_context(&self, context: &RequestContext, message: String) -> Result<ServiceResponse> {
        println!("Test action with context called: {:?}, message: {}", context, message);
        Ok(ServiceResponse::success("Action with context executed successfully".to_string(), Option::<String>::None))
    }

    // Test action for request handling
    #[action]
    async fn process_request(&self, context: &RequestContext, operation: &str, params: &ValueType) -> Result<ServiceResponse> {
        println!("Process request called: op={}, params={:?}", operation, params);
        Ok(ServiceResponse::success("Process executed successfully".to_string(), Option::<String>::None))
    }

    // Test subscribe macro
    #[subscribe(topic = "test/topic")]
    async fn on_test_event(&self, payload: ValueType) -> Result<()> {
        println!("Received event on test/topic: {:?}", payload);
        Ok(())
    }
}

#[async_trait]
impl AbstractService for DebugService {
    fn name(&self) -> &str {
        &self.name
    }

    fn path(&self) -> &str {
        "/debug_service"
    }

    fn state(&self) -> ServiceState {
        ServiceState::Running
    }

    fn description(&self) -> &str {
        "Service DebugService"
    }

    fn metadata(&self) -> ServiceMetadata {
        ServiceMetadata::new(vec![], "Debug Service".to_string())
    }

    async fn init(&mut self, _context: &RequestContext) -> Result<()> {
        println!("Initializing DebugService");
        Ok(())
    }

    async fn start(&mut self) -> Result<()> {
        println!("Starting DebugService");
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        println!("Stopping DebugService");
        Ok(())
    }

    async fn handle_request(&self, request: ServiceRequest) -> Result<ServiceResponse> {
        println!("Handling request: {:?}", request);
        Ok(ServiceResponse::success("Request handled successfully".to_string(), Option::<String>::None))
    }
}

fn main() {
    println!("Macro debug binary - for testing macro expansion");
}
*/

// Empty main function to satisfy the compiler
fn main() {
    println!("Macro debug binary is currently disabled during migration");
}
