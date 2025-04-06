use anyhow::Result;
use runar_node::services::abstract_service::{AbstractService, ServiceState, ActionMetadata};
use runar_node::services::ResponseStatus;
use runar_node::vmap;

// Import test utilities
mod test_utils {
    include!("test_utils/mod.rs");
}

// Import the math service
mod fixtures {
    pub mod math_service {
        include!("fixtures/math_service.rs");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::fixtures::math_service::MathService;
    use super::test_utils::create_test_node;
    
    #[tokio::test]
    async fn test_service_metadata() {
        let service = MathService::new("test_math");
        
        // Test basic metadata
        assert_eq!(service.name(), "test_math");
        assert_eq!(service.path(), "math");
        assert_eq!(service.description(), "A simple math service that provides basic arithmetic operations");
        assert_eq!(service.version(), "1.0.0");
        assert_eq!(service.state(), ServiceState::Created);
        
        // Test actions
        let actions = service.actions();
        assert!(actions.contains(&ActionMetadata { name: "add".to_string() }));
        assert!(actions.contains(&ActionMetadata { name: "subtract".to_string() }));
        assert!(actions.contains(&ActionMetadata { name: "multiply".to_string() }));
        assert!(actions.contains(&ActionMetadata { name: "divide".to_string() }));
        assert_eq!(actions.len(), 4);
        
        // Test metadata method
        let metadata = service.metadata();
        assert_eq!(metadata.name, "test_math");
        assert_eq!(metadata.path, "math");
        assert_eq!(metadata.state, ServiceState::Created);
        
        // Verify operations in metadata are derived from actions
        let operations = metadata.operations;
        assert_eq!(operations.len(), 4);
        assert!(operations.contains(&"add".to_string()));
        assert!(operations.contains(&"subtract".to_string()));
        assert!(operations.contains(&"multiply".to_string()));
        assert!(operations.contains(&"divide".to_string()));
    }
    
    #[tokio::test]
    async fn test_service_lifecycle() -> Result<()> {
        println!("\n=== Running test_service_lifecycle ===");
        
        // Create a test node with temporary storage
        let (mut node, _temp_dir, _config) = create_test_node().await?;
        
        // Create the math service
        let math_service = MathService::new("math");
        
        // Register the service with the node
        node.add_service(math_service).await?;
        
        // Start the node
        node.start().await?;
        
        // Test a valid request to ensure the service is running properly
        println!("Sending request math/add to node...");
        let request_data = vmap!{
            "a" => 5.0,
            "b" => 3.0
        };
        let response = node.request("math/add", request_data).await?;
        
        // Print the actual response for debugging
        println!("Response from math/add: {:#?}", response);
        
        // Now we should get a success response
        assert_eq!(response.status, ResponseStatus::Success);
        assert_eq!(response.message, "5 + 3 = 8");
        
        // Stop the node
        node.stop().await?;
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_math_operations() -> Result<()> {
        println!("\n=== Running test_math_operations ===");
        
        // Create a test node with temporary storage
        let (mut node, _temp_dir, _config) = create_test_node().await?;
        
        // Create the math service
        let math_service = MathService::new("math");
        
        // Register the service with the node
        node.add_service(math_service).await?;
        
        // Start the node
        node.start().await?;
        
        // Test add operation
        let request_data = vmap!{
            "a" => 5.0,
            "b" => 3.0
        };
        let response = node.request("math/add", request_data).await?;
        assert_eq!(response.status, ResponseStatus::Success);
        assert_eq!(response.message, "5 + 3 = 8");
        assert!(response.data.is_some(), "Response data should be present");
        
        // Test subtract operation
        let request_data = vmap!{
            "a" => 10.0,
            "b" => 4.0
        };
        let response = node.request("math/subtract", request_data).await?;
        assert_eq!(response.status, ResponseStatus::Success);
        assert_eq!(response.message, "10 - 4 = 6");
        assert!(response.data.is_some(), "Response data should be present");
        
        // Test multiply operation
        let request_data = vmap!{
            "a" => 5.0,
            "b" => 6.0
        };
        let response = node.request("math/multiply", request_data).await?;
        assert_eq!(response.status, ResponseStatus::Success);
        assert_eq!(response.message, "5 * 6 = 30");
        assert!(response.data.is_some(), "Response data should be present");
        
        // Test divide operation
        let request_data = vmap!{
            "a" => 20.0,
            "b" => 4.0
        };
        let response = node.request("math/divide", request_data).await?;
        assert_eq!(response.status, ResponseStatus::Success);
        assert_eq!(response.message, "20 / 4 = 5");
        assert!(response.data.is_some(), "Response data should be present");
        
        // Test division by zero error
        let request_data = vmap!{
            "a" => 10.0,
            "b" => 0.0
        };
        let response = node.request("math/divide", request_data).await?;
        assert_eq!(response.status, ResponseStatus::Error);
        assert_eq!(response.message, "Cannot divide by zero");
        
        // Test an invalid action
        let request_data = vmap!{
            "a" => 5.0,
            "b" => 3.0
        };
        let response = node.request("math/invalid_action", request_data).await?;
        assert_eq!(response.status, ResponseStatus::Error);
        assert!(response.message.contains("Unknown action"));
        
        // Stop the node
        node.stop().await?;
        
        Ok(())
    }
} 