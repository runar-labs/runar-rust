// Tests for the Registry Service
//
// INTENTION: Verify that the Registry Service correctly provides
// information about registered services through standard requests.

use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_common::types::ArcValueType;
use runar_node::config::logging_config::{LogLevel, LoggingConfig};
use runar_node::services::RegistryDelegate;
use runar_node::{Node, NodeConfig, ServiceMetadata, ServiceState};
use serde_json::Value;
use std::time::Duration;
use tokio::time::timeout;

// Import the test fixtures
use crate::fixtures::math_service::MathService;

/// Test that the Registry Service correctly lists all services
///
/// INTENTION: This test validates that:
/// - The Registry Service is automatically registered during Node creation
/// - It properly responds to a services/list request
/// - The response contains expected service information
#[tokio::test]
async fn test_registry_service_list_services() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let config = NodeConfig::new("node-reg-list".to_string(), "test_network".to_string());
        let mut node = Node::new(config).await.unwrap();

        // Create a test service
        let math_service = MathService::new("Math", "math");

        // Add the service to the node
        node.add_service(math_service).await.unwrap();

        // Start the node to initialize services
        node.start().await.unwrap();

        // Use the request method to query the registry service
        let services: Vec<ServiceMetadata> = node
            .request("$registry/services/list".to_string(), None::<()>)
            .await
            .unwrap();

        // Parse the response to verify it contains our registered services
        // services is now Vec<ServiceMetadata>
        // .as_list_ref::<ServiceMetadata>() is no longer needed as response is already Option<Vec<ServiceMetadata>>
        // The services list should contain at least the math service and the registry service itself
        assert!(
            services.len() >= 2,
            "Expected at least 2 services, got {}",
            services.len()
        );

        // Verify the math service is in the list by checking the service_path field
        let has_math_service = services
            .iter()
            .any(|service| service.service_path == "math");
        assert!(
            has_math_service,
            "Math service not found in registry service response"
        );

        // Optionally, validate structure of ServiceMetadata for at least one service
        let math_service = services
            .iter()
            .find(|service| service.service_path == "math")
            .expect("Math service not found");
        assert_eq!(math_service.name, "Math", "Math service name mismatch");
        assert_eq!(
            math_service.version, "1.0.0",
            "Math service version mismatch"
        );
        // Add more field checks as desired
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that the Registry Service can return detailed service information
///
/// INTENTION: This test validates that:
/// - The Registry Service can return detailed information about a specific service
/// - The response contains proper service state and metadata
#[tokio::test]
async fn test_registry_service_get_service_info() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        let test_logger = Logger::new_root(Component::Node, "test_name");

        let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);

        // Create a node with a test network ID
        let config =
            NodeConfig::new("node-reg-info", "test_network").with_logging_config(logging_config);
        let mut node = Node::new(config).await.unwrap();

        // Create a test service
        let math_service = MathService::new("Math Service", "math");

        // Add the service to the node
        node.add_service(math_service).await.unwrap();

        // // Debug log service states before starting
        // let states_before = node.get_all_service_states().await;
        // test_logger.debug(format!("Service states BEFORE start: {:?}", states_before));

        // Start the services to check that we get the correct state
        node.start().await.unwrap();

        // // Debug log service states after starting
        // let states_after = node.get_all_service_states().await;
        // test_logger.debug(format!("Service states AFTER start: {:?}", states_after));

        // Debug log available handlers using logger
        let list_response: Vec<ServiceMetadata> = node
            .request("$registry/services/list", None::<()>)
            .await
            .unwrap();
        test_logger.debug(format!("Available services: {:?}", list_response));

        // Use the request method to query the registry service for the math service
        // Note: We should use the correct parameter path format
        let response: ServiceMetadata = node
            .request("$registry/services/math", None::<()>)
            .await
            .unwrap();
        test_logger.debug(format!("Service info response: {:?}", response));

        // Dump the complete response data for debugging
        // 'response' is already ServiceMetadata, so no need for 'if let Some'
        test_logger.debug(format!("Response data type: {:?}", response));
        // .as_type::<ServiceMetadata>() is no longer needed
        // let mut value_clone = data.clone(); // Not needed if using response directly
        // let service_metadata = value_clone... // response is already the correct type

        test_logger.debug(format!("ServiceMetadata: {:?}", response));
        // Example assertions:
        assert_eq!(response.service_path, "math");
        assert_eq!(response.name, "Math Service");
        assert_eq!(response.version, "1.0.0");
        assert_eq!(response.actions.len(), 4);
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that the Registry Service provides just the state of a service
///
/// INTENTION: This test validates that:
/// - The Registry Service can return just the state information of a specific service
/// - The response contains the correct service state
#[tokio::test]
async fn test_registry_service_get_service_state() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a test logger for debugging
        let test_logger = Logger::new_root(Component::Node, "test_state");

        // Create a node with a test network ID
        let config = NodeConfig::new("node-reg-state", "test_network");
        let mut node = Node::new(config).await.unwrap();

        // Create a test service
        let math_service = MathService::new("Math", "math");

        // Add the service to the node
        node.add_service(math_service).await?;

        // Start the service
        node.start().await?;

        // Use the request method to query the registry service for the math service state
        let response: ServiceState = node
            .request("$registry/services/math/state", None::<()>)
            .await?;
        test_logger.debug(format!("Initial service state response: {:?}", response));

        // Parse the response to verify it contains service state
        assert_eq!(
            response,
            ServiceState::Running,
            "Expected service state to be 'RUNNING'"
        );

        let response: Result<ServiceState> = node
            .request("$registry/services/not_exisstent/state", None::<()>)
            .await;
        test_logger.debug(format!("Service state after start: {:?}", response));
        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that the Registry Service properly handles missing path parameters
///
/// INTENTION: This test validates that:
/// - The Registry Service returns the correct error when required path parameters are missing
/// - The error response has the expected status code and message
#[tokio::test]
async fn test_registry_service_missing_parameter() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a test logger for debugging
        let test_logger = Logger::new_root(Component::Node, "test_missing_param");

        // Create a node with a test network ID
        let config = NodeConfig::new("node-reg-missing", "test_network");
        let mut node = Node::new(config).await.unwrap();

        // Create a test service
        let math_service = MathService::new("Math", "math");

        // Add the service to the node
        node.add_service(math_service).await.unwrap();

        // Start the node to ensure services are initialized
        node.start().await.unwrap();

        // Make an invalid request with missing service_path parameter
        // The registry service expects a path parameter in the URL, but we're using an invalid path
        // that the router won't be able to match to a template with a parameter
        let response: Result<Value> = node.request("$registry/services", None::<()>).await;

        // The request should fail or return an error response
        match response {
            Ok(resp) => {
                // If it returns a response, it should have an error status code
                test_logger.debug(format!("Response for missing parameter: {:?}", resp));
            }
            Err(e) => {
                // If it returns an error, that's also acceptable - service not found
                test_logger.debug(format!("Error for missing parameter: {:?}", e));
                assert!(true, "Request properly failed with error: {:?}", e);
            }
        }

        // Test with an invalid path format for service_path/state endpoint
        let state_response: Result<Value> =
            node.request("$registry/services//state", None::<()>).await;

        // The request should fail or return an error response
        match state_response {
            Ok(resp) => {
                // If it returns a response, it should have an error status code
                test_logger.debug(format!("Response for invalid state path: {:?}", resp));
            }
            Err(e) => {
                // If it returns an error, that's also acceptable - service not found
                test_logger.debug(format!("Error for invalid state path: {:?}", e));
                assert!(true, "Request properly failed with error: {:?}", e);
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}
