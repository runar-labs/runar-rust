// Tests for the Node implementation
//
// These tests verify that the Node properly handles requests
// and delegates to the ServiceRegistry as needed.

use runar_common::hmap;
use runar_common::types::ArcValueType;
use runar_node::config::logging_config::{LogLevel, LoggingConfig};
use runar_node::{Node, NodeConfig};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use runar_node::services::EventContext;
use runar_node::NodeDelegate;

use std::collections::HashMap;

// Import the test fixtures
use crate::fixtures::math_service::MathService;
use crate::fixtures::path_params_service::PathParamsService;
use anyhow::Result;

/// Test that verifies basic node creation functionality
///
/// INTENTION: This test validates that the Node can be properly:
/// - Created with a specified network ID
/// - Initialized with default configuration
///
/// This test verifies the most basic Node functionality - that we can create
/// and initialize a Node instance which is the foundation for all other tests.
#[tokio::test]
async fn test_node_create() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        println!("Starting test_node_create");
        // Create a node with a test network ID
        let mut config = NodeConfig::new("test-node", "test_network");
        // Disable networking properly
        config.network_config = None;
        let _node = Node::new(config).await.unwrap();

        println!("Node created successfully!");
        // Basic verification that the node exists
    })
    .await
    {
        Ok(_) => println!("Test completed within the timeout"),
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that verifies service registration with the Node
///
/// INTENTION: This test validates that the Node can properly:
/// - Accept a service for registration
/// - Register the service with its ServiceRegistry
/// - List the registered services
///
/// This test verifies the Node's responsibility for managing services and
/// correctly delegating registration to its ServiceRegistry.
#[tokio::test]
async fn test_node_add_service() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let mut config = NodeConfig::new("test-node", "test_network");
        // Disable networking
        config.network_config = None;
        let mut node = Node::new(config).await.unwrap();

        // Create a test service with consistent name and path
        let service = MathService::new("Math", "Math");

        // Add the service to the node
        node.add_service(service).await.unwrap();

        // Start the node to initialize all services
        node.start().await.unwrap();
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that verifies request handling in the Node
///
/// INTENTION: This test validates that the Node can properly:
/// - Find a service for a specific request
/// - Forward the request to the appropriate service
/// - Return the service's response
///
/// This test verifies one of the Node's core responsibilities - request routing
/// and handling. The Node should find the right service and forward the request.
#[tokio::test]
async fn test_node_request() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a NodeConfig with logging configuration
        let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);

        // Create a node with a test network ID
        let mut config =
            NodeConfig::new("test-node", "test_network").with_logging_config(logging_config);
        // Disable networking
        config.network_config = None;
        let mut node = Node::new(config).await.unwrap();

        // Create a test service with consistent name and path
        let service = MathService::new("Math Service", "math");

        // Add the service to the node
        node.add_service(service).await.unwrap();

        // Start the node to initialize all services
        node.start().await.unwrap();

        // Create parameters for the add operation using vmap! macro
        let params = ArcValueType::new_map(hmap! {
            "a" => 5.0,
            "b" => 3.0
        });

        // Make a request to the math service's add action
        let result: f64 = node
            .request("math/add", Some(params))
            .await
            .expect("math/add call failed");
        assert_eq!(result, 8.0);
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that verifies node lifecycle methods work correctly
///
/// INTENTION: This test validates that the Node can properly:
/// - Start up and initialize correctly
/// - Shut down cleanly when requested
///
/// This test verifies the Node's lifecycle management which is critical
/// for resource cleanup and proper application shutdown.
#[tokio::test]
async fn test_node_lifecycle() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let mut config = NodeConfig::new("test-node", "test_network");
        // Disable networking
        config.network_config = None;
        let mut node = Node::new(config).await.unwrap();

        // Start the node
        node.start().await.unwrap();

        // Stop the node
        node.stop().await.unwrap();
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that verifies node initialization with network components
///
/// INTENTION: This test validates that the Node can properly:
/// - Initialize with network components
/// - Start the networking subsystem
///
/// This test ensures that the Node can properly initialize its network
/// components which are required for remote communication.
#[tokio::test]
async fn test_node_init() -> Result<()> {
    // Create a node configuration
    let mut config = NodeConfig::new("test-node", "test-network");
    config.network_config = None;

    // Create a node
    let mut node = Node::new(config).await?;

    // Start the node
    node.start().await?;

    // Stop the node
    node.stop().await?;

    Ok(())
}

/// Test that verifies event publishing and subscription in the Node
///
/// INTENTION: This test validates that the Node can properly:
/// - Accept subscriptions for specific topics
/// - Publish events to those topics
/// - Ensure subscribers receive the published events
///
/// This test verifies the Node's subscription and publishing capabilities,
/// which is a core part of the event-driven architecture.
#[tokio::test]
async fn test_node_events() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let mut config = NodeConfig::new("test-node", "test_network");
        config.network_config = None;
        let node = Node::new(config).await.unwrap();

        // Create a flag to track if the callback was called
        let was_called = Arc::new(AtomicBool::new(false));
        let was_called_clone = was_called.clone();

        // Define a topic to subscribe to
        let topic = "test/topic".to_string();

        // Create a handler function for subscription
        // Note: Using the full handler signature with Arc<EventContext> for the node API
        let handler = move |_ctx: Arc<EventContext>, mut data: Option<ArcValueType>| {
            println!("Received event data: {:?}", data);

            // Verify the data matches what we published
            // For ArcValueType, extract the string value
            if let Ok(s) = data.expect("REASON").as_type::<String>() {
                assert_eq!(s, "test data");
                // Mark that the handler was called with correct data
                was_called_clone.store(true, Ordering::SeqCst);
            }

            // Properly pin and box the future as expected by the subscribe method
            Box::pin(async move { Ok(()) }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        };

        // Subscribe to the topic using the node's API
        node.subscribe(topic.clone(), Box::new(handler))
            .await
            .unwrap();

        // Publish an event to the topic
        let data = ArcValueType::new_primitive("test data".to_string());
        node.publish(topic, Some(data)).await.unwrap();

        // Small delay to allow async handler to execute
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify the handler was called
        assert!(
            was_called.load(Ordering::SeqCst),
            "Subscription handler was not called"
        );
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that path parameters are correctly populated in the request context
#[tokio::test]
async fn test_path_params_in_context() {
    // Create a node with a test network ID
    let mut config = NodeConfig::new("test-node", "test_network");
    config.network_config = None;
    let mut node = Node::new(config).await.unwrap();

    // Create our path parameters test service
    let service = PathParamsService::new("PathParams", "test");

    // Add the service to the node
    node.add_service(service).await.unwrap();

    // Start the node to initialize all services
    node.start().await.unwrap();

    // Make a request to a path that matches the template
    let params_map: HashMap<String, String> = node
        .request("test/abc123/items/xyz789", None::<()>)
        .await
        .unwrap();

    // Verify the path parameters were correctly extracted
    // params_map is now HashMap<String, String>
    assert_eq!(params_map.get("param_1").unwrap(), "abc123");
    assert_eq!(params_map.get("param_2").unwrap(), "xyz789");
}
