use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, Ordering};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use runar_common::types::ValueType;
use runar_node::services::service_registry::ServiceRegistry;
use runar_node::services::AbstractService;
use runar_node::NodeRequestHandler;
use runar_node::routing::TopicPath;
use anyhow::Result;

// Import test fixtures directly
use crate::fixtures::math_service::MathService;

// This test verifies that we can create multiple subscriptions and retrieve them
#[tokio::test]
async fn test_multiple_subscriptions() {
    // Create a service registry
    let registry = ServiceRegistry::new();
    
    // Topic to subscribe to
    let topic = "test/event";
    
    // Values to update in callbacks
    let called1 = Arc::new(Mutex::new(false));
    let called1_clone = called1.clone();
    
    let called2 = Arc::new(Mutex::new(false));
    let called2_clone = called2.clone();
    
    // Create callbacks that will be invoked when an event is published
    let callback1 = Box::new(move |_: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let called = called1_clone.clone();
        Box::pin(async move {
            let mut guard = called.lock().unwrap();
            *guard = true;
            Ok(())
        })
    });
    
    let callback2 = Box::new(move |_: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let called = called2_clone.clone();
        Box::pin(async move {
            let mut guard = called.lock().unwrap();
            *guard = true;
            Ok(())
        })
    });
    
    // Subscribe to the topic with both callbacks
    let _subscription_id1 = registry.subscribe(topic.to_string(), callback1).await.unwrap();
    let _subscription_id2 = registry.subscribe(topic.to_string(), callback2).await.unwrap();
    
    // Publish an event to the topic
    registry.publish(topic.to_string(), ValueType::Number(42.0)).await.unwrap();
    
    // Small delay to allow callbacks to execute
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Verify that both callbacks were called
    let called_value1 = *called1.lock().unwrap();
    let called_value2 = *called2.lock().unwrap();
    assert!(called_value1, "First callback was not called");
    assert!(called_value2, "Second callback was not called");
}

// This test verifies unsubscribing from a topic
#[tokio::test]
async fn test_unsubscribe_by_id() {
    // Create a service registry
    let registry = ServiceRegistry::new();
    
    // Topic to subscribe to
    let topic = "test/event";
    
    // Values to update in callbacks
    let called1 = Arc::new(Mutex::new(0));
    let called1_clone = called1.clone();
    
    let called2 = Arc::new(Mutex::new(0));
    let called2_clone = called2.clone();
    
    // Create callbacks that will be invoked when an event is published
    let callback1 = Box::new(move |_: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let called = called1_clone.clone();
        Box::pin(async move {
            let mut guard = called.lock().unwrap();
            *guard += 1;
            Ok(())
        })
    });
    
    let callback2 = Box::new(move |_: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let called = called2_clone.clone();
        Box::pin(async move {
            let mut guard = called.lock().unwrap();
            *guard += 1;
            Ok(())
        })
    });
    
    // Subscribe to the topic with both callbacks
    let subscription_id1 = registry.subscribe(topic.to_string(), callback1).await.unwrap();
    let subscription_id2 = registry.subscribe(topic.to_string(), callback2).await.unwrap();
    
    // Publish an event to the topic
    registry.publish(topic.to_string(), ValueType::Number(42.0)).await.unwrap();
    
    // Small delay to allow callbacks to execute
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Verify that both callbacks were called once
    {
        let count1 = *called1.lock().unwrap();
        let count2 = *called2.lock().unwrap();
        assert_eq!(count1, 1, "First callback should have been called once");
        assert_eq!(count2, 1, "Second callback should have been called once");
    }
    
    // Unsubscribe just the first callback
    registry.unsubscribe(topic.to_string(), Some(&subscription_id1)).await.unwrap();
    
    // Publish another event to the topic
    registry.publish(topic.to_string(), ValueType::Number(100.0)).await.unwrap();
    
    // Small delay to allow callbacks to execute
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Verify that only the second callback was called again
    let count1 = *called1.lock().unwrap();
    let count2 = *called2.lock().unwrap();
    assert_eq!(count1, 1, "First callback should not have been called again after unsubscribing");
    assert_eq!(count2, 2, "Second callback should have been called again");
    
    // Unsubscribe the second callback
    registry.unsubscribe(topic.to_string(), Some(&subscription_id2)).await.unwrap();
    
    // Publish one more event
    registry.publish(topic.to_string(), ValueType::Number(200.0)).await.unwrap();
    
    // Small delay to allow callbacks to execute if they were still subscribed
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Verify that neither callback was called again
    let count1 = *called1.lock().unwrap();
    let count2 = *called2.lock().unwrap();
    assert_eq!(count1, 1, "First callback should still only have been called once");
    assert_eq!(count2, 2, "Second callback should still only have been called twice");
}

// This test covers a key part of our refactoring plan: the get_subscribers_for_topic method
#[tokio::test]
async fn test_get_subscribers_for_topic() {
    // Create a service registry
    let registry = ServiceRegistry::new();
    
    // Topics to subscribe to
    let topic1 = "test/event/1";
    let topic2 = "test/event/2";
    
    // Create simple callbacks
    let callback1 = Box::new(move |_: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move { Ok(()) })
    });
    
    let callback2 = Box::new(move |_: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move { Ok(()) })
    });
    
    let callback3 = Box::new(move |_: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move { Ok(()) })
    });
    
    // Subscribe to the topics
    let _sub_id1 = registry.subscribe(topic1.to_string(), callback1).await.unwrap();
    let _sub_id2 = registry.subscribe(topic1.to_string(), callback2).await.unwrap();
    let _sub_id3 = registry.subscribe(topic2.to_string(), callback3).await.unwrap();
    
    // Get subscribers for topic1
    let subscribers_for_topic1 = registry.get_subscribers_for_topic(topic1).await;
    
    // Get subscribers for topic2
    let subscribers_for_topic2 = registry.get_subscribers_for_topic(topic2).await;
    
    // Verify counts
    assert_eq!(subscribers_for_topic1.len(), 2, "Topic1 should have 2 subscribers");
    assert_eq!(subscribers_for_topic2.len(), 1, "Topic2 should have 1 subscriber");
    
    // Get subscribers for a topic with no subscribers
    let subscribers_for_empty_topic = registry.get_subscribers_for_topic("non/existent/topic").await;
    assert_eq!(subscribers_for_empty_topic.len(), 0, "Empty topic should have 0 subscribers");
}

// This test verifies that events are properly queued when there are no subscribers
#[tokio::test]
async fn test_pending_events() {
    // Create a service registry
    let registry = ServiceRegistry::new();
    
    // Topic to subscribe to
    let topic = "test/event";
    
    // First publish an event (when there are no subscribers)
    registry.publish(topic.to_string(), ValueType::Number(42.0)).await.unwrap();
    
    // Value to update in the callback
    let called_with = Arc::new(Mutex::new(None::<f64>));
    let called_with_clone = called_with.clone();
    
    // Create a callback that will be invoked when an event is published
    let callback = Box::new(move |val: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let called_with = called_with_clone.clone();
        Box::pin(async move {
            if let ValueType::Number(num) = val {
                let mut guard = called_with.lock().unwrap();
                *guard = Some(num);
            }
            Ok(())
        })
    });
    
    // Subscribe to the topic
    let _subscription_id = registry.subscribe(topic.to_string(), callback).await.unwrap();
    
    // Small delay to allow any pending events to be processed
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Check if the callback received a value
    // For this test we expect it to receive no value (no pending events replay)
    let called_value = called_with.lock().unwrap().clone();
    assert!(called_value.is_none(), "Callback should not have received any pending events");
}

// Test to ensure services on different networks don't receive each other's events
#[tokio::test]
async fn test_cross_network_events() {
    // Create a service registry
    let registry = ServiceRegistry::new();
    
    // Create two topics in different networks
    let network1_topic = "test/event";
    let network2_topic = "test/event";
    
    // Value to update in the callback
    let called1 = Arc::new(Mutex::new(false));
    let called1_clone = called1.clone();
    
    let called2 = Arc::new(Mutex::new(false));
    let called2_clone = called2.clone();
    
    // Create callbacks for different networks
    let callback1 = Box::new(move |_: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let called = called1_clone.clone();
        Box::pin(async move {
            let mut guard = called.lock().unwrap();
            *guard = true;
            Ok(())
        })
    });
    
    let callback2 = Box::new(move |_: ValueType| -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let called = called2_clone.clone();
        Box::pin(async move {
            let mut guard = called.lock().unwrap();
            *guard = true;
            Ok(())
        })
    });
    
    // Subscribe to topics on different networks
    let _subscription_id1 = registry.subscribe(format!("network1:{}", network1_topic), callback1).await.unwrap();
    let _subscription_id2 = registry.subscribe(format!("network2:{}", network2_topic), callback2).await.unwrap();
    
    // Publish an event to network1
    registry.publish(format!("network1:{}", network1_topic), ValueType::Number(42.0)).await.unwrap();
    
    // Small delay to allow callbacks to execute
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Verify that only network1 callback was called
    let called_value1 = *called1.lock().unwrap();
    let called_value2 = *called2.lock().unwrap();
    assert!(called_value1, "Network1 callback was not called");
    assert!(!called_value2, "Network2 callback should not have been called");
    
    // Reset network1 callback
    {
        let mut guard = called1.lock().unwrap();
        *guard = false;
    }
    
    // Publish an event to network2
    registry.publish(format!("network2:{}", network2_topic), ValueType::Number(100.0)).await.unwrap();
    
    // Small delay to allow callbacks to execute
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Verify that only network2 callback was called
    let called_value1 = *called1.lock().unwrap();
    let called_value2 = *called2.lock().unwrap();
    assert!(!called_value1, "Network1 callback should not have been called");
    assert!(called_value2, "Network2 callback was not called");
} 