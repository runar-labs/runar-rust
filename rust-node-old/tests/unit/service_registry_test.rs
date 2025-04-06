use std::sync::Arc;
use std::sync::Mutex;
use std::future::Future;
use std::pin::Pin;

use runar_common::types::ValueType;
use runar_node::services::{RequestContext, ServiceRequest, ServiceResponse, ResponseStatus};
use runar_node::services::abstract_service::{AbstractService, ServiceState};
use runar_node::services::service_registry::ServiceRegistry;
use runar_node::routing::TopicPath;
use runar_node::NodeRequestHandler;
use anyhow::Result;

// Import the test fixtures instead of creating custom mocks
use crate::fixtures::math_service::MathService;

#[tokio::test]
async fn test_register_and_get_service() {
    // Create a service registry
    let registry = ServiceRegistry::new();

    // Create a test service
    let service = MathService::new("Math");
    
    // Register the service with explicit network ID
    registry.register_service("test_network", Arc::new(service)).await.unwrap();
    
    // Get the service using a TopicPath
    let topic_path = TopicPath::new_service("test_network", "Math");
    let retrieved = registry.get_service_by_topic_path(&topic_path).await.unwrap();
    
    // Verify the service type
    assert_eq!(retrieved.name(), "Math");
}

#[tokio::test]
async fn test_register_multiple_services() {
    // Create a service registry
    let registry = ServiceRegistry::new();

    // Create two test services
    // TODO> the parameter here is the name.. we nbeed to add name and path to this tedst fixture.. to avoid confusion like in thids test. whre Math1 
    //which is the name is being used to get the servie. snd it shiould not.. the path is whsat should be used.
    let service1 = MathService::new("Math1", "math1");
    let service2 = MathService::new("Math2", "math2");
    
    // Register both services with explicit network ID
    registry.register_service("test_network", Arc::new(service1)).await.unwrap();
    registry.register_service("test_network", Arc::new(service2)).await.unwrap();
    
    // Get each service using topic paths
    let topic_path1 = TopicPath::new_action("test_network", "math1/add");
    //TODO: get_service_by_topic_path rename to get_service .. it should be the default way to get a service
    let retrieved1 = registry.get_service_by_topic_path(&topic_path1).await.unwrap();
    
    let topic_path2 = TopicPath::new_service("test_network", "Math2");
    let retrieved2 = registry.get_service_by_topic_path(&topic_path2).await.unwrap();
    
    // Verify the service types
    assert_eq!(retrieved1.name(), "Math1");
    assert_eq!(retrieved2.name(), "Math2");
}

#[tokio::test]
async fn test_path_lookup() {
    // Create a service registry
    let registry = ServiceRegistry::new();

    // Create a test service with a path
    let service = MathService::new("Math");
    
    // Register the service with explicit network ID
    registry.register_service("test_network", Arc::new(service)).await.unwrap();
    
    // Create a topic path for lookup
    let topic_path = TopicPath::new_service("test_network", "math");
    
    // Get the service by topic path
    let retrieved = registry.get_service_by_topic_path(&topic_path).await.unwrap();
    
    // Verify the service path
    assert_eq!(retrieved.path(), "math");
}

#[tokio::test]
async fn test_full_path_lookup() {
    // Create a service registry
    let registry = ServiceRegistry::new();

    // Create a test service
    let service = MathService::new("Math");
    
    // Register the service with explicit network ID
    registry.register_service("test_network", Arc::new(service)).await.unwrap();
    
    // Create request context for the service
    let request = ServiceRequest::new_with_optional(
        "math",
        "add",
        None,
        Arc::new(RequestContext::default())
    );
    
    // Attempt to get the service
    let response = registry.handle_request(request).await.unwrap();
    
    // Verify we got a successful response
    assert_eq!(response.status, ResponseStatus::Success);
}

#[tokio::test]
async fn test_service_not_found() {
    // Create a service registry
    let registry = ServiceRegistry::new();
    
    // Create a topic path for a service that doesn't exist
    let topic_path = TopicPath::new_service("test_network", "NonExistentService");
    
    // Attempt to get the service by topic path
    let result = registry.get_service_by_topic_path(&topic_path).await;
    
    // Verify that no service was found
    assert!(result.is_none());
}

#[tokio::test]
async fn test_topic_path_lookup() {
    // Create a service registry
    let registry = ServiceRegistry::new();
    
    // Create a test service
    let service = MathService::new("Math");
    
    // Register the service with network ID
    registry.register_service("test_network", Arc::new(service)).await.unwrap();
    
    // Create a topic path
    let topic_path = TopicPath::new_action("test_network", "math", "add");
    
    // Use the topic path to find the service
    let retrieved = registry.get_service_by_topic_path(&topic_path).await.unwrap();
    
    // Verify the service was found correctly
    assert_eq!(retrieved.name(), "Math");
}

#[tokio::test]
async fn test_simple_subscription() {
    // Create a service registry
    let registry = ServiceRegistry::new();
    
    // Topic to subscribe to
    let topic = "test/event";
    
    // Value to update in the callback
    let called = Arc::new(Mutex::new(false));
    let called_clone = called.clone();
    
    // Create a callback that will be invoked when an event is published
    let callback = Box::new(move |_: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let called = called_clone.clone();
        Box::pin(async move {
            let mut guard = called.lock().unwrap();
            *guard = true;
            Ok(())
        })
    });
    
    // Subscribe to the topic
    let subscription_id = registry.subscribe(topic.to_string(), callback).await.unwrap();
    
    // Publish an event to the topic
    registry.publish(topic.to_string(), ValueType::Number(42.0)).await.unwrap();
    
    // Small delay to allow callback to execute
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Verify that the callback was called
    let called_value = *called.lock().unwrap();
    assert!(called_value, "Callback was not called");
    
    // Unsubscribe
    registry.unsubscribe(topic.to_string(), Some(&subscription_id)).await.unwrap();
}

#[tokio::test]
async fn test_unsubscribe() {
    // Create a service registry
    let registry = ServiceRegistry::new();
    
    // Topic to subscribe to
    let topic = "test/event";
    
    // Value to update in the callback
    let called = Arc::new(Mutex::new(0));
    let called_clone = called.clone();
    
    // Create a callback that will be invoked when an event is published
    let callback = Box::new(move |_: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let called = called_clone.clone();
        Box::pin(async move {
            let mut guard = called.lock().unwrap();
            *guard += 1;
            Ok(())
        })
    });
    
    // Subscribe to the topic
    let subscription_id = registry.subscribe(topic.to_string(), callback).await.unwrap();
    
    // Publish an event to the topic
    registry.publish(topic.to_string(), ValueType::Number(42.0)).await.unwrap();
    
    // Small delay to allow callback to execute
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Verify that the callback was called once
    {
        let count = *called.lock().unwrap();
        assert_eq!(count, 1, "Callback should have been called once");
    }
    
    // Unsubscribe
    registry.unsubscribe(topic.to_string(), Some(&subscription_id)).await.unwrap();
    
    // Publish another event to the topic
    registry.publish(topic.to_string(), ValueType::Number(100.0)).await.unwrap();
    
    // Small delay to allow callback to execute if it were still subscribed
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Verify that the callback was not called again
    let count = *called.lock().unwrap();
    assert_eq!(count, 1, "Callback should not have been called again after unsubscribing");
}

#[tokio::test]
async fn test_list_services() {
    // Create a service registry
    let registry = ServiceRegistry::new();
    
    // Initially there should be no services
    let services = registry.list_services();
    assert!(services.is_empty(), "Expected no services initially");
    
    // Create and register a test service
    let service = MathService::new("Math1");
    registry.register_service("test_network", Arc::new(service)).await.unwrap();
    
    // Create and register a second test service
    let service2 = MathService::new("Math2");
    registry.register_service("test_network", Arc::new(service2)).await.unwrap();
    
    // Now there should be two services
    let services = registry.list_services();
    assert_eq!(services.len(), 2, "Expected two services");
    
    // The services should be "Math1" and "Math2"
    assert!(services.contains(&"Math1".to_string()), "Missing service 'Math1'");
    assert!(services.contains(&"Math2".to_string()), "Missing service 'Math2'");
}

#[tokio::test]
async fn test_network_isolation() {
    // Create a service registry
    let registry = ServiceRegistry::new();
    
    // Create test services
    let service1 = MathService::new("MathService");
    let service2 = MathService::new("MathService"); // Same name, different network
    
    // Register services on different networks
    registry.register_service("network1", Arc::new(service1)).await.unwrap();
    registry.register_service("network2", Arc::new(service2)).await.unwrap();
    
    // Look up services by network
    let topic_path1 = TopicPath::new_service("network1", "MathService");
    let topic_path2 = TopicPath::new_service("network2", "MathService");
    
    let service1 = registry.get_service_by_topic_path(&topic_path1).await;
    let service2 = registry.get_service_by_topic_path(&topic_path2).await;
    
    // Verify both services were found on their correct networks
    assert!(service1.is_some(), "Service on network1 should be found");
    assert!(service2.is_some(), "Service on network2 should be found");
    
    // Verify we get services from the correct networks
    assert_eq!(service1.unwrap().name(), "MathService");
    assert_eq!(service2.unwrap().name(), "MathService");
    
    // List services for a specific network
    let network1_services = registry.list_services_for_network("network1");
    let network2_services = registry.list_services_for_network("network2");
    
    assert_eq!(network1_services.len(), 1, "Network1 should have 1 service");
    assert_eq!(network2_services.len(), 1, "Network2 should have 1 service");
} 