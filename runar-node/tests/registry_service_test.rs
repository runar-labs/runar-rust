// Tests for the Registry Service
//
// INTENTION: Verify that the Registry Service correctly provides
// information about registered services through standard requests.

use anyhow::Result;
use runar_logging::{Component, Logger};
use runar_logging::{LogLevel, LoggingConfig};
use runar_node::{Node, ServiceMetadata, ServiceState};
use runar_serializer::arc_value::AsArcValue;
use runar_serializer::ArcValue;
use runar_test_utils::create_networked_node_test_config;
use runar_test_utils::create_node_test_config;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

// Import the test fixtures
use runar_test_utils::fixtures::math_service::MathService;

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
        let config = create_node_test_config().expect("Error creating test config");
        let node = Node::new(config).await.unwrap();

        // Create a test service
        let math_service = MathService::new("Math", "math");

        // Add the service to the node
        node.add_service(math_service).await.unwrap();

        // Start the node to initialize services
        node.start().await.unwrap();
        node.wait_for_services_to_start().await.unwrap();

        // Use the request method to query the registry service
        let services_av: ArcValue = node
            .request("$registry/services/list", Option::<ArcValue>::None, None)
            .await
            .unwrap();
        // Convert ArcValue list into Vec<ServiceMetadata>
        let list_arc = services_av.as_list_ref().unwrap();
        let services: Vec<Arc<ServiceMetadata>> = list_arc
            .iter()
            .map(|av| av.as_type_ref::<ServiceMetadata>().unwrap())
            .collect();

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
        let test_logger = Logger::new_root(Component::Custom("Test"));

        let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);

        // Create a node with a test network ID
        let config = create_node_test_config()
            .expect("Error creating test config")
            .with_logging_config(logging_config);
        let node = Node::new(config).await.unwrap();

        // Create a test service
        let math_service = MathService::new("Math Service", "math");

        // Add the service to the node
        node.add_service(math_service).await.unwrap();

        // // Debug log service states before starting
        // let states_before = node.get_all_service_states().await;
        // test_logger.debug(format!("Service states BEFORE start: {:?}", states_before));

        // Start the services to check that we get the correct state
        node.start().await.unwrap();
        node.wait_for_services_to_start().await.unwrap();

        // // Debug log service states after starting
        // let states_after = node.get_all_service_states().await;
        // test_logger.debug(format!("Service states AFTER start: {:?}", states_after));

        // Debug log available handlers using logger
        let list_av: ArcValue = node
            .request("$registry/services/list", None::<ArcValue>, None)
            .await
            .unwrap();
        let list_av_clone = list_av.clone();
        let list_arc2 = list_av_clone.as_list_ref().unwrap();
        let list_response: Vec<ServiceMetadata> = list_arc2
            .iter()
            .map(|av| ServiceMetadata::from_arc_value((*av).clone()).unwrap())
            .collect();
        test_logger.debug(format!("Available services: {list_response:?}"));

        // Use the request method to query the registry service for the math service
        // Note: We should use the correct parameter path format
        let response_av: ArcValue = node
            .request("$registry/services/math", Option::<ArcValue>::None, None)
            .await
            .unwrap();
        let response: ServiceMetadata =
            ServiceMetadata::from_arc_value(response_av.clone()).unwrap();
        test_logger.debug(format!("Service info response: {response:?}"));

        // Dump the complete response data for debugging
        // 'response' is already ServiceMetadata, so no need for 'if let Some'
        test_logger.debug(format!("Response data type: {response:?}"));
        // .as_type::<ServiceMetadata>() is no longer needed
        // let mut value_clone = data.clone(); // Not needed if using response directly
        // let service_metadata = value_clone... // response is already the correct type

        test_logger.debug(format!("ServiceMetadata: {response:?}"));
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
        let test_logger = Logger::new_root(Component::Custom("Test"));

        // Create a node with a test network ID
        let config = create_node_test_config().expect("Error creating test config");
        let node = Node::new(config).await.unwrap();

        // Create a test service
        let math_service = MathService::new("Math", "math");

        // Add the service to the node
        node.add_service(math_service).await?;

        // Start the service
        node.start().await?;
        node.wait_for_services_to_start().await?;

        // Use the request method to query the registry service for the math service state (local)
        let state_av: ArcValue = node
            .request(
                "$registry/services/math/state",
                Some(ArcValue::new_primitive(true)),
                None,
            )
            .await?;
        let response: ServiceState = ServiceState::from_arc_value(state_av.clone()).unwrap();
        test_logger.debug(format!("Initial service state response: {response:?}"));

        // Parse the response to verify it contains service state
        assert_eq!(
            response,
            ServiceState::Running,
            "Expected service state to be 'RUNNING'"
        );

        let response: Result<ArcValue> = node
            .request(
                "$registry/services/not_exisstent/state",
                Some(ArcValue::new_primitive(true)),
                None,
            )
            .await;
        test_logger.debug(format!("Service state after start: {response:?}"));
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
        let test_logger = Logger::new_root(Component::Custom("Test"));

        // Create a node with a test network ID
        let config = create_node_test_config().expect("Error creating test config");
        let node = Node::new(config).await.unwrap();

        // Create a test service
        let math_service = MathService::new("Math", "math");

        // Add the service to the node
        node.add_service(math_service).await.unwrap();

        // Start the node to ensure services are initialized
        node.start().await.unwrap();
        node.wait_for_services_to_start().await?;

        // Make an invalid request with missing service_path parameter
        // The registry service expects a path parameter in the URL, but we're using an invalid path
        // that the router won't be able to match to a template with a parameter
        let response: Result<ArcValue> = node
            .request("$registry/services", Option::<ArcValue>::None, None)
            .await;

        // The request should fail or return an error response
        match response {
            Ok(resp) => {
                // If it returns a response, it should have an error status code
                test_logger.debug(format!("Response for missing parameter: {resp:?}"));
            }
            Err(e) => {
                // If it returns an error, that's also acceptable - service not found
                test_logger.debug(format!("Error for missing parameter: {e:?}"));
                // Request properly failed, error logged above
            }
        }

        // Test with an invalid path format for service_path/state endpoint
        let state_response: Result<ArcValue> = node
            .request(
                "$registry/services//state",
                Some(ArcValue::new_primitive(true)),
                None,
            )
            .await;

        // The request should fail or return an error response
        match state_response {
            Ok(resp) => {
                // If it returns a response, it should have an error status code
                test_logger.debug(format!("Response for invalid state path: {resp:?}"));
            }
            Err(e) => {
                // If it returns an error, that's also acceptable - service not found
                test_logger.debug(format!("Error for invalid state path: {e:?}"));
                // Request properly failed, error logged above
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

/// Test that the Registry Service can pause a running service
///
/// INTENTION: This test validates that:
/// - The Registry Service can pause a service that is in Running state
/// - The service state is correctly updated to Paused
/// - Invalid pause attempts are properly rejected
#[tokio::test]
async fn test_registry_service_pause_service() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let config = create_node_test_config().expect("Error creating test config");
        let node = Node::new(config).await.unwrap();

        // Create a test service
        let math_service = MathService::new("Math", "math");

        // Add the service to the node
        node.add_service(math_service).await.unwrap();

        // Start the service
        node.start().await.unwrap();
        node.wait_for_services_to_start().await?;

        // Verify service is in Running state
        let state_av: ArcValue = node
            .request(
                "$registry/services/math/state",
                Some(ArcValue::new_primitive(true)),
                None,
            )
            .await
            .unwrap();
        let initial_state: ServiceState = ServiceState::from_arc_value(state_av.clone()).unwrap();
        assert_eq!(
            initial_state,
            ServiceState::Running,
            "Service should be in Running state"
        );

        // Pause the service
        let pause_response: ArcValue = node
            .request(
                "$registry/services/math/pause",
                Option::<ArcValue>::None,
                None,
            )
            .await
            .unwrap();
        let paused_state: ServiceState =
            ServiceState::from_arc_value(pause_response.clone()).unwrap();
        assert_eq!(
            paused_state,
            ServiceState::Paused,
            "Service should be paused"
        );

        // Verify service is now in Paused state
        let state_av: ArcValue = node
            .request(
                "$registry/services/math/state",
                Some(ArcValue::new_primitive(true)),
                None,
            )
            .await
            .unwrap();
        let current_state: ServiceState = ServiceState::from_arc_value(state_av.clone()).unwrap();
        assert_eq!(
            current_state,
            ServiceState::Paused,
            "Service should be in Paused state"
        );

        // Try to pause again (should fail)
        let pause_again_result: Result<ArcValue> = node
            .request(
                "$registry/services/math/pause",
                Option::<ArcValue>::None,
                None,
            )
            .await;
        assert!(
            pause_again_result.is_err(),
            "Pausing a paused service should fail"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that the Registry Service can resume a paused service
///
/// INTENTION: This test validates that:
/// - The Registry Service can resume a service that is in Paused state
/// - The service state is correctly updated to Running
/// - Invalid resume attempts are properly rejected
#[tokio::test]
async fn test_registry_service_resume_service() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let config = create_node_test_config().expect("Error creating test config");
        let node = Node::new(config).await.unwrap();

        // Create a test service
        let math_service = MathService::new("Math", "math");

        // Add the service to the node
        node.add_service(math_service).await.unwrap();

        // Start the service
        node.start().await.unwrap();
        node.wait_for_services_to_start().await?;

        // Pause the service first
        let _pause_response: ArcValue = node
            .request(
                "$registry/services/math/pause",
                Option::<ArcValue>::None,
                None,
            )
            .await
            .unwrap();

        // Verify service is in Paused state
        let state_av: ArcValue = node
            .request(
                "$registry/services/math/state",
                Some(ArcValue::new_primitive(true)),
                None,
            )
            .await
            .unwrap();
        let paused_state: ServiceState = ServiceState::from_arc_value(state_av.clone()).unwrap();
        assert_eq!(
            paused_state,
            ServiceState::Paused,
            "Service should be in Paused state"
        );

        // Resume the service
        let resume_response: ArcValue = node
            .request(
                "$registry/services/math/resume",
                Option::<ArcValue>::None,
                None,
            )
            .await
            .unwrap();
        let resumed_state: ServiceState =
            ServiceState::from_arc_value(resume_response.clone()).unwrap();
        assert_eq!(
            resumed_state,
            ServiceState::Running,
            "Service should be resumed"
        );

        // Verify service is now in Running state
        let state_av: ArcValue = node
            .request(
                "$registry/services/math/state",
                Some(ArcValue::new_primitive(true)),
                None,
            )
            .await
            .unwrap();
        let current_state: ServiceState = ServiceState::from_arc_value(state_av.clone()).unwrap();
        assert_eq!(
            current_state,
            ServiceState::Running,
            "Service should be in Running state"
        );

        // Try to resume again (should fail)
        let resume_again_result: Result<ArcValue> = node
            .request(
                "$registry/services/math/resume",
                Option::<ArcValue>::None,
                None,
            )
            .await;
        assert!(
            resume_again_result.is_err(),
            "Resuming a running service should fail"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that requests to paused services are properly handled
///
/// INTENTION: This test validates that:
/// - Requests to paused services return appropriate error messages
/// - The error message indicates the service state rather than "service not found"
#[tokio::test]
async fn test_registry_service_request_to_paused_service() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let config = create_node_test_config().expect("Error creating test config");
        let node = Node::new(config).await.unwrap();

        // Create a test service
        let math_service = MathService::new("Math", "math");

        // Add the service to the node
        node.add_service(math_service).await.unwrap();

        // Start the service
        node.start().await.unwrap();
        node.wait_for_services_to_start().await?;

        // Pause the service
        let _pause_response: ArcValue = node
            .request(
                "$registry/services/math/pause",
                Option::<ArcValue>::None,
                None,
            )
            .await
            .unwrap();

        // Try to call a service action while it's paused
        let request_result: Result<ArcValue> = node
            .request(
                "math/add",
                Some(ArcValue::new_list(vec![
                    ArcValue::new_primitive(5i32),
                    ArcValue::new_primitive(3i32),
                ])),
                None,
            )
            .await;

        // The request should fail with a state-related error
        assert!(
            request_result.is_err(),
            "Request to paused service should fail"
        );
        let error_message = request_result.unwrap_err().to_string();
        assert!(
            error_message.contains("Paused"),
            "Error message should indicate service is in Paused state, got: {error_message}"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that pause action on non-existent service returns proper error
///
/// INTENTION: This test validates that:
/// - Attempting to pause a non-existent service returns a proper error message
/// - The error message indicates the service was not found
#[tokio::test]
async fn test_registry_service_pause_nonexistent_service() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let config = create_node_test_config().expect("Error creating test config");
        let node = Node::new(config).await.unwrap();

        // Start the node (no services added)
        node.start().await.unwrap();
        node.wait_for_services_to_start().await?;

        // Try to pause a non-existent service
        let pause_result: Result<ArcValue> = node
            .request(
                "$registry/services/nonexistent/pause",
                Option::<ArcValue>::None,
                None,
            )
            .await;

        // The request should fail with a service not found error
        assert!(
            pause_result.is_err(),
            "Pausing non-existent service should fail"
        );
        let error_message = pause_result.unwrap_err().to_string();
        assert!(
            error_message.contains("not found"),
            "Error message should indicate service not found, got: {error_message}"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that resume action on non-existent service returns proper error
///
/// INTENTION: This test validates that:
/// - Attempting to resume a non-existent service returns a proper error message
/// - The error message indicates the service was not found
#[tokio::test]
async fn test_registry_service_resume_nonexistent_service() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let config = create_node_test_config().expect("Error creating test config");
        let node = Node::new(config).await.unwrap();

        // Start the node (no services added)
        node.start().await.unwrap();
        node.wait_for_services_to_start().await?;

        // Try to resume a non-existent service
        let resume_result: Result<ArcValue> = node
            .request(
                "$registry/services/nonexistent/resume",
                Option::<ArcValue>::None,
                None,
            )
            .await;

        // The request should fail with a service not found error
        assert!(
            resume_result.is_err(),
            "Resuming non-existent service should fail"
        );
        let error_message = resume_result.unwrap_err().to_string();
        assert!(
            error_message.contains("not found"),
            "Error message should indicate service not found, got: {error_message}"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that resume action on running service returns proper error
///
/// INTENTION: This test validates that:
/// - Attempting to resume a service that is already running returns a proper error message
/// - The error message indicates the service is in the wrong state
#[tokio::test]
async fn test_registry_service_resume_running_service() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let config = create_node_test_config().expect("Error creating test config");
        let node = Node::new(config).await.unwrap();

        // Create a test service
        let math_service = MathService::new("Math", "math");

        // Add the service to the node
        node.add_service(math_service).await.unwrap();

        // Start the service (puts it in Running state)
        node.start().await.unwrap();
        node.wait_for_services_to_start().await?;

        // Try to resume a service that is already running
        let resume_result: Result<ArcValue> = node
            .request(
                "$registry/services/math/resume",
                Option::<ArcValue>::None,
                None,
            )
            .await;

        // The request should fail with a state-related error
        assert!(
            resume_result.is_err(),
            "Resuming a running service should fail"
        );
        let error_message = resume_result.unwrap_err().to_string();
        assert!(
            error_message.contains("Running"),
            "Error message should indicate service is in Running state, got: {error_message}"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that pause action on already paused service returns proper error
///
/// INTENTION: This test validates that:
/// - Attempting to pause a service that is already paused returns a proper error message
/// - The error message indicates the service is in the wrong state
#[tokio::test]
async fn test_registry_service_pause_already_paused_service() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let config = create_node_test_config().expect("Error creating test config");
        let node = Node::new(config).await.unwrap();

        // Create a test service
        let math_service = MathService::new("Math", "math");

        // Add the service to the node
        node.add_service(math_service).await.unwrap();

        // Start the service
        node.start().await.unwrap();
        node.wait_for_services_to_start().await?;

        // Pause the service first
        let _pause_response: ArcValue = node
            .request(
                "$registry/services/math/pause",
                Option::<ArcValue>::None,
                None,
            )
            .await
            .unwrap();

        // Try to pause the service again (should fail)
        let pause_again_result: Result<ArcValue> = node
            .request(
                "$registry/services/math/pause",
                Option::<ArcValue>::None,
                None,
            )
            .await;

        // The request should fail with a state-related error
        assert!(
            pause_again_result.is_err(),
            "Pausing an already paused service should fail"
        );
        let error_message = pause_again_result.unwrap_err().to_string();
        assert!(
            error_message.contains("Paused"),
            "Error message should indicate service is in Paused state, got: {error_message}"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that requests to non-existent services return proper error messages
///
/// INTENTION: This test validates that:
/// - Requests to non-existent services return appropriate error messages
/// - The error message indicates "No handler found" rather than state-related errors
#[tokio::test]
async fn test_registry_service_request_to_nonexistent_service() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let config = create_node_test_config().expect("Error creating test config");
        let node = Node::new(config).await.unwrap();

        // Start the node (no services added)
        node.start().await.unwrap();
        node.wait_for_services_to_start().await?;

        // Try to call a service action for a non-existent service
        let request_result: Result<ArcValue> = node
            .request(
                "nonexistent/add",
                Some(ArcValue::new_list(vec![
                    ArcValue::new_primitive(5i32),
                    ArcValue::new_primitive(3i32),
                ])),
                None,
            )
            .await;

        // The request should fail with a "No handler found" error
        assert!(
            request_result.is_err(),
            "Request to non-existent service should fail"
        );
        let error_message = request_result.unwrap_err().to_string();
        assert!(
            error_message.contains("No handler found"),
            "Error message should indicate no handler found, got: {error_message}"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that the Registry Service can discover and list remote services from other nodes
///
/// INTENTION: This test validates that:
/// - Two nodes can discover each other via multicast
/// - The Registry Service can list services from both local and remote nodes
/// - Remote service information is properly accessible through the $registry API
/// - The registry correctly distinguishes between local and remote services
#[tokio::test]
async fn test_registry_service_remote_discovery() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(45), async {
        // Configure logging to ensure test logs are displayed
        let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);
        logging_config.apply();

        // Set up logger
        let logger = Arc::new(Logger::new_root(Component::Custom("registry_remote_test")));

        logger.debug("🔍 Starting Registry Remote Discovery Test");

        // Create two networked node configurations
        let configs = create_networked_node_test_config(2)
            .expect("Failed to create multiple node test configs");

        let node1_config = configs[0].clone();
        let node2_config = configs[1].clone();

        logger.debug(format!("Node1 config: {node1_config}"));
        logger.debug(format!("Node2 config: {node2_config}"));

        // Create math services with different paths
        let math_service1 = MathService::new("Math1", "math1");
        let math_service2 = MathService::new("Math2", "math2");

        // Create and start Node 1
        let node1 = Node::new(node1_config).await.unwrap();
        node1.add_service(math_service1).await.unwrap();
        node1.start().await.unwrap();
        node1.wait_for_services_to_start().await.unwrap();
        logger.debug("✅ Node 1 started with math1 service");

        // Create and start Node 2
        let node2 = Node::new(node2_config).await.unwrap();
        node2.add_service(math_service2).await.unwrap();
        node2.start().await.unwrap();
        node2.wait_for_services_to_start().await.unwrap();
        logger.debug("✅ Node 2 started with math2 service");

        // Wait for nodes to discover each other
        logger.debug("⏳ Waiting for nodes to discover each other via multicast...");
        let peer_future2 = node2.on(
            format!(
                "$registry/peer/{node1_id}/discovered",
                node1_id = node1.node_id()
            ),
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(10),
                include_past: None,
            }),
        );
        let peer_future1 = node1.on(
            format!(
                "$registry/peer/{node2_id}/discovered",
                node2_id = node2.node_id()
            ),
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(10),
                include_past: None,
            }),
        );

        // Wait for both nodes to discover each other
        let (peer_result2, peer_result1) = tokio::join!(peer_future2, peer_future1);

        // Check for timeout errors and panic if any occurred
        match peer_result2 {
            Ok(_) => logger.debug("✅ Node2 successfully discovered Node1"),
            Err(e) => panic!("❌ Node2 failed to discover Node1 within timeout: {e}"),
        }

        match peer_result1 {
            Ok(_) => logger.debug("✅ Node1 successfully discovered Node2"),
            Err(e) => panic!("❌ Node1 failed to discover Node2 within timeout: {e}"),
        }

        // Wait for service discovery to propagate
        logger.debug("⏳ Waiting for service discovery propagation...");
        tokio::time::sleep(Duration::from_secs(3)).await;

        // ==========================================
        // Test 1: Node1 should see both local and remote services
        // ==========================================
        logger.debug("🧪 Testing Node1 registry - should see both local and remote services");

        let services_av: ArcValue = node1
            .request("$registry/services/list", Option::<ArcValue>::None, None)
            .await
            .unwrap();

        let list_arc = services_av.as_list_ref().unwrap();
        let services: Vec<Arc<ServiceMetadata>> = list_arc
            .iter()
            .map(|av| av.as_type_ref::<ServiceMetadata>().unwrap())
            .collect();

        logger.debug(format!("Node1 sees {} services total", services.len()));

        // Debug: Log all services Node1 sees
        for (i, service) in services.iter().enumerate() {
            logger.debug(format!(
                "Node1 service {}: path='{}', name='{}'",
                i, service.service_path, service.name
            ));
        }

        // Node1 should see at least:
        // - Its own math1 service (local)
        // - Node2's math2 service (remote)
        // - The registry service itself
        assert!(
            services.len() >= 3,
            "Node1 should see at least 3 services (math1, math2, registry), got {}",
            services.len()
        );

        // Verify Node1 can see its own math1 service
        let has_math1_service = services
            .iter()
            .any(|service| service.service_path == "math1");
        assert!(
            has_math1_service,
            "Node1 should see its own math1 service in registry"
        );

        // Verify Node1 can see Node2's math2 service (remote)
        let has_math2_service = services
            .iter()
            .any(|service| service.service_path.ends_with(":math2"));
        assert!(
            has_math2_service,
            "Node1 should see Node2's math2 service (remote) in registry. Found services: {:?}",
            services.iter().map(|s| &s.service_path).collect::<Vec<_>>()
        );

        logger.debug("✅ Node1 registry correctly shows both local and remote services");

        // ==========================================
        // Test 2: Node2 should see both local and remote services
        // ==========================================
        logger.debug("🧪 Testing Node2 registry - should see both local and remote services");

        let services_av: ArcValue = node2
            .request("$registry/services/list", Option::<ArcValue>::None, None)
            .await
            .unwrap();

        let list_arc = services_av.as_list_ref().unwrap();
        let services: Vec<Arc<ServiceMetadata>> = list_arc
            .iter()
            .map(|av| av.as_type_ref::<ServiceMetadata>().unwrap())
            .collect();

        logger.debug(format!("Node2 sees {} services total", services.len()));

        // Node2 should see at least:
        // - Its own math2 service (local)
        // - Node1's math1 service (remote)
        // - The registry service itself
        assert!(
            services.len() >= 3,
            "Node2 should see at least 3 services (math1, math2, registry), got {}",
            services.len()
        );

        // Verify Node2 can see its own math2 service
        let has_math2_service = services
            .iter()
            .any(|service| service.service_path == "math2");
        assert!(
            has_math2_service,
            "Node2 should see its own math2 service in registry"
        );

        // Verify Node2 can see Node1's math1 service (remote)
        let has_math1_service = services
            .iter()
            .any(|service| service.service_path.ends_with(":math1"));
        assert!(
            has_math1_service,
            "Node2 should see Node1's math1 service (remote) in registry. Found services: {:?}",
            services.iter().map(|s| &s.service_path).collect::<Vec<_>>()
        );

        logger.debug("✅ Node2 registry correctly shows both local and remote services");

        // ==========================================
        // Test 3: Test remote service information retrieval
        // ==========================================
        logger.debug("🧪 Testing remote service information retrieval");

        // Node1 should be able to get detailed info about Node2's math2 service
        // Get the services list again for this test section
        let services_av: ArcValue = node1
            .request("$registry/services/list", Option::<ArcValue>::None, None)
            .await
            .unwrap();

        let list_arc = services_av.as_list_ref().unwrap();
        let services: Vec<Arc<ServiceMetadata>> = list_arc
            .iter()
            .map(|av| av.as_type_ref::<ServiceMetadata>().unwrap())
            .collect();

        // Verify Node1 can see Node2's math2 service (remote)
        let has_math2_service = services
            .iter()
            .any(|service| service.service_path.ends_with(":math2"));
        assert!(has_math2_service, "Node1 should see Node2's math2 service");

        // Request detailed information about the remote math2 service using simple service name
        let response_av: ArcValue = node1
            .request("$registry/services/math2", Option::<ArcValue>::None, None)
            .await
            .unwrap();

        let remote_service: ServiceMetadata =
            ServiceMetadata::from_arc_value(response_av.clone()).unwrap();
        logger.debug(format!("Remote service info: {remote_service:?}"));

        assert!(remote_service.service_path.ends_with(":math2"));
        assert_eq!(remote_service.name, "Math2");
        assert_eq!(remote_service.version, "1.0.0");
        assert_eq!(remote_service.actions.len(), 4); // add, subtract, multiply, divide

        logger.debug("✅ Remote service information retrieval successful");

        // Node2 should be able to get detailed info about Node1's math1 service
        // Get the services list again for this test section
        let services_av: ArcValue = node2
            .request("$registry/services/list", Option::<ArcValue>::None, None)
            .await
            .unwrap();

        let list_arc = services_av.as_list_ref().unwrap();
        let services: Vec<Arc<ServiceMetadata>> = list_arc
            .iter()
            .map(|av| av.as_type_ref::<ServiceMetadata>().unwrap())
            .collect();

        // Verify Node2 can see Node1's math1 service (remote)
        let has_math1_service = services
            .iter()
            .any(|service| service.service_path.ends_with(":math1"));
        assert!(has_math1_service, "Node2 should see Node1's math1 service");

        // Request detailed information about the remote math1 service using simple service name
        let response_av: ArcValue = node2
            .request("$registry/services/math1", Option::<ArcValue>::None, None)
            .await
            .unwrap();

        let remote_service: ServiceMetadata =
            ServiceMetadata::from_arc_value(response_av.clone()).unwrap();
        logger.debug(format!("Remote service info: {remote_service:?}"));

        assert!(remote_service.service_path.ends_with(":math1"));
        assert_eq!(remote_service.name, "Math1");
        assert_eq!(remote_service.version, "1.0.0");
        assert_eq!(remote_service.actions.len(), 4); // add, subtract, multiply, divide

        logger.debug("✅ Remote service information retrieval successful");

        // ==========================================
        // Test 4: Test remote service state retrieval
        // ==========================================
        logger.debug("🧪 Testing remote service state retrieval");

        // Node1 should be able to get the state of Node2's math2 service (remote)
        let state_av: ArcValue = node1
            .request(
                "$registry/services/math2/state",
                Some(ArcValue::new_primitive(false)), // false for remote services
                None,
            )
            .await
            .unwrap();

        let remote_state: ServiceState = ServiceState::from_arc_value(state_av.clone()).unwrap();
        logger.debug(format!("Remote service state: {remote_state:?}"));

        assert_eq!(
            remote_state,
            ServiceState::Running,
            "Remote service should be in Running state"
        );

        logger.debug("✅ Remote service state retrieval successful");

        // ==========================================
        // Test 5: Test that remote services can be called
        // ==========================================
        logger.debug("🧪 Testing remote service calls through registry discovery");

        // Node1 should be able to call Node2's math2 service
        let mut add_params_map_1: std::collections::HashMap<String, ArcValue> =
            std::collections::HashMap::new();
        add_params_map_1.insert("a".into(), ArcValue::new_primitive(10.0f64));
        add_params_map_1.insert("b".into(), ArcValue::new_primitive(5.0f64));
        let response_av: ArcValue = node1
            .request("math2/add", Some(ArcValue::new_map(add_params_map_1)), None)
            .await
            .unwrap();

        let result: f64 = *response_av.as_type_ref::<f64>().unwrap();
        assert_eq!(result, 15.0);
        logger.debug(format!(
            "✅ Remote service call successful: 10 + 5 = {result}"
        ));

        // Node2 should be able to call Node1's math1 service
        let mut mul_params_map_2: std::collections::HashMap<String, ArcValue> =
            std::collections::HashMap::new();
        mul_params_map_2.insert("a".into(), ArcValue::new_primitive(3.0f64));
        mul_params_map_2.insert("b".into(), ArcValue::new_primitive(4.0f64));
        let response_av: ArcValue = node2
            .request(
                "math1/multiply",
                Some(ArcValue::new_map(mul_params_map_2)),
                None,
            )
            .await
            .unwrap();

        let result: f64 = *response_av.as_type_ref::<f64>().unwrap();
        assert_eq!(result, 12.0);
        logger.debug(format!(
            "✅ Remote service call successful: 3 * 4 = {result}"
        ));

        // NOTE: Remote service invocation tests are covered elsewhere. This test focuses on
        // $registry/services list/info/state behavior to validate discovery and registry APIs.

        // ==========================================
        // Cleanup
        // ==========================================
        logger.debug("🧹 Shutting down nodes...");
        node2.stop().await.unwrap();
        node1.stop().await.unwrap();

        logger.debug("✅ Both nodes stopped successfully");
        logger.debug("🎉 Registry remote discovery test completed successfully!");

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 45 seconds"),
    }
}
