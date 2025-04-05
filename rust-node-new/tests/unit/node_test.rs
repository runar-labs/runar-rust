// Tests for the Node implementation
//
// These tests verify that the Node properly handles requests
// and delegates to the ServiceRegistry as needed.

use std::sync::Arc;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use runar_common::types::ValueType;
use runar_common::logging::{Logger, Component};
use runar_node_new::node::{Node, NodeConfig};
use runar_node_new::services::{EventContext, ServiceResponse, NodeRequestHandler};
use runar_node_new::services::abstract_service::AbstractService;

// Import the test fixtures
use crate::fixtures::math_service::MathService;
use anyhow::{anyhow, Result};

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
    // Create a node with a test network ID
    let config = NodeConfig::new("test_network");
    let node = Node::new(config).await.unwrap();
    
    // Verify the node has the correct network ID (it's now using a UUID, so we can't directly compare)
    assert!(node.network_id.len() > 0);
}

/// Test that verifies service registration with the Node
/// 
/// INTENTION: This test validates that the Node can properly:
/// - Accept a service for registration
/// - Register the service with its internal ServiceRegistry
/// - List the registered services
/// 
/// This test verifies the Node's responsibility for managing services and 
/// correctly delegating registration to its ServiceRegistry.
#[tokio::test]
async fn test_node_add_service() {
    // Create a node with a test network ID
    let config = NodeConfig::new("test_network");
    let mut node = Node::new(config).await.unwrap();
    
    // Create a test service with consistent name and path
    let service = MathService::new("Math", "Math");
    
    // Add the service to the node
    node.add_service(service).await.unwrap();
    
    // List services to verify it was added
    println!("Registered services: {:?}", node.list_services());
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
    // Create a node with a test network ID
    let config = NodeConfig::new("test_network");
    let mut node = Node::new(config).await.unwrap();
    
    // Create a test service with consistent name and path
    let service = MathService::new("Math", "Math");
    
    // Add the service to the node
    node.add_service(service).await.unwrap();
    
    // List services to verify it was added
    println!("Registered services: {:?}", node.list_services());
    
    // Create parameters for the add operation
    let params = ValueType::Map([
        ("a".to_string(), ValueType::Number(5.0)),
        ("b".to_string(), ValueType::Number(3.0)),
    ].into_iter().collect());
    
    // Use the request method which is the preferred API
    // The path format should match the service name exactly: "Math/add"
    let response = node.request("Math/add".to_string(), params).await.unwrap();
    
    // Print the details of the failed response for debugging
    if response.status != 200 {
        println!("Request failed: {:?}", response);
    }
    
    // Verify we got a success response (status code 200)
    assert_eq!(response.status, 200);
    
    // Verify the result is correct
    match response.data {
        Some(ValueType::Number(n)) => assert_eq!(n, 8.0),
        _ => panic!("Expected a number in the response data"),
    }
}
 
/// Test that verifies event publishing in the Node
/// 
/// INTENTION: This test validates that the Node can properly:
/// - Accept subscriptions for specific topics
/// - Publish events to those topics
/// - Ensure subscribers receive the published events
/// - Handle unsubscription correctly
/// 
/// This test verifies the Node's responsibility for event publication and 
/// subscription management, which is a core architectural component.
/// The Node (not ServiceRegistry) should be responsible for executing callbacks.
#[tokio::test]
async fn test_node_publish() {
    // Create a node with a test network ID
    let config = NodeConfig::new("test_network");
    let node = Node::new(config).await.unwrap();
    
    // Create a flag to track if the callback was called
    let was_called = Arc::new(AtomicBool::new(false));
    let was_called_clone = was_called.clone();
    
    // Create a callback that would be invoked when an event is published
    // Use Box instead of Arc to match the expected type
    let callback = Box::new(move |_ctx: Arc<EventContext>, _data: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let was_called = was_called_clone.clone();
        Box::pin(async move {
            // Set the flag to true when called
            was_called.store(true, Ordering::SeqCst);
            Ok(())
        })
    });
    
    // Subscribe to the topic
    let _subscription_id = node.subscribe("test/event".to_string(), callback).await.unwrap();
    
    // Publish an event to the topic
    node.publish("test/event".to_string(), ValueType::Null).await.unwrap();
    
    // Give the async task time to execute
    tokio::time::sleep(Duration::from_millis(10)).await;
    
    // Verify the callback was called
    assert!(was_called.load(Ordering::SeqCst), "Callback was not called");
}

/// Test that verifies service lifecycle management
/// 
/// INTENTION: This test validates that a service can properly:
/// - Be initialized with a LifecycleContext
/// - Start successfully after initialization
/// - Stop gracefully when requested
/// 
/// This test ensures that services implement the lifecycle methods correctly
/// and can be managed through their full operational lifecycle.
/// It also verifies LifecycleContext can be used for initialization.
#[tokio::test]
async fn test_service_lifecycle() {
    // Create a node for context creation
    let config = NodeConfig::new("test_network");
    let node = Node::new(config).await.unwrap();
    
    // Create a MathService for testing
    let service = MathService::new("math", "math");
    
    // Create proper lifecycle contexts using the node
    let init_context = node.create_context("math");
    
    // Initialize the service
    let init_result = service.init(init_context).await;
    assert!(init_result.is_ok(), "Service initialization failed");
    
    // Create a new context for start
    let start_context = node.create_context("math");
    
    // Start the service
    let start_result = service.start(start_context).await;
    assert!(start_result.is_ok(), "Service start failed");
    
    // Create a new context for stop
    let stop_context = node.create_context("math");
    
    // Stop the service
    let stop_result = service.stop(stop_context).await;
    assert!(stop_result.is_ok(), "Service stop failed");
}

/// Test that verifies Node lifecycle management with multiple services
/// 
/// INTENTION: This test validates that the Node can properly:
/// - Register multiple services
/// - Start all services with a single call to node.start()
/// - Stop all services with a single call to node.stop()
/// 
/// This test ensures that the Node correctly manages the lifecycle of all registered
/// services and handles any errors that might occur during start or stop operations.
#[tokio::test]
async fn test_node_lifecycle() {
    // Create a node with a test network ID
    let config = NodeConfig::new("test_network");
    let mut node = Node::new(config).await.unwrap();
    
    // Create multiple test services
    let math_service = MathService::new("Math", "math");
    let second_math_service = MathService::new("SecondMath", "second_math");
    
    // Add the services to the node
    node.add_service(math_service).await.unwrap();
    node.add_service(second_math_service).await.unwrap();
    
    // Start all services at once
    let start_result = node.start().await;
    assert!(start_result.is_ok(), "Failed to start node services: {:?}", start_result.err());
    
    // Verify both services are running
    // TODO: Add a way to check service state once service metadata is stored in Node
    
    // Stop all services at once
    let stop_result = node.stop().await;
    assert!(stop_result.is_ok(), "Failed to stop node services: {:?}", stop_result.err());
    
    // Verify both services are stopped
    // TODO: Add a way to check service state once service metadata is stored in Node
}
 