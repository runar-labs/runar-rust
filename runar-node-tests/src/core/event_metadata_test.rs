// Tests for the event metadata retrieval functionality
//
// These tests validate that the ServiceRegistry properly tracks
// which services subscribe to which events and can retrieve that information.

use anyhow::Result;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use runar_common::logging::{Component, Logger};
use runar_node::routing::TopicPath;
use runar_node::services::service_registry::ServiceRegistry;
use runar_node::services::{EventContext, EventRegistrationOptions};
use runar_serializer::ArcValue;

/// Test that verifies the get_events_metadata_by_subscriber method returns correct metadata for events
///
/// INTENTION: This test validates that the registry can properly:
/// - Register multiple event subscriptions for a service
/// - Return the correct metadata for all events a service has subscribed to
#[tokio::test]
async fn test_get_subscription_metadata() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Set up test logger
        let logger = Arc::new(Logger::new_root(Component::Service));

        // Create registry
        let registry = ServiceRegistry::new(logger.clone());

        // Create a service path and event paths
        //let service_path = TopicPath::new("sensor-service", "test-network").unwrap();
        let temperature_event_path =
            TopicPath::new("sensor-service/temperature_changed", "test-network").unwrap();
        let humidity_event_path =
            TopicPath::new("sensor-service/humidity_changed", "test-network").unwrap();
        let pressure_event_path =
            TopicPath::new("sensor-service/pressure_changed", "test-network").unwrap();

        // Create event callbacks
        let temperature_callback = Arc::new(
            |_ctx: Arc<EventContext>,
             _: Option<ArcValue>|
             -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
                Box::pin(async move {
                    // Do nothing for test
                    Ok(())
                })
            },
        );

        let humidity_callback = Arc::new(
            |_ctx: Arc<EventContext>,
             _: Option<ArcValue>|
             -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
                Box::pin(async move {
                    // Do nothing for test
                    Ok(())
                })
            },
        );

        let pressure_callback = Arc::new(
            |_ctx: Arc<EventContext>,
             _: Option<ArcValue>|
             -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
                Box::pin(async move {
                    // Do nothing for test
                    Ok(())
                })
            },
        );

        // Register the event subscriptions
        let temperature_subscription_id = registry
            .register_local_event_subscription(
                &temperature_event_path,
                temperature_callback,
                &EventRegistrationOptions::default(),
            )
            .await
            .unwrap();

        registry
            .register_local_event_subscription(
                &humidity_event_path,
                humidity_callback,
                &EventRegistrationOptions::default(),
            )
            .await
            .unwrap();

        registry
            .register_local_event_subscription(
                &pressure_event_path,
                pressure_callback,
                &EventRegistrationOptions::default(),
            )
            .await
            .unwrap();

        // Get the events metadata for the service using the subscriber-based approach
        let search_path = TopicPath::new("sensor-service/*", "test-network").unwrap();
        let subscriptions_metadata = registry.get_subscriptions_metadata(&search_path).await;

        // Verify that we got metadata for all three events
        assert_eq!(
            subscriptions_metadata.len(),
            3,
            "Should have metadata for all three events"
        );

        // Verify the paths of the events in the metadata
        let event_paths: Vec<String> = subscriptions_metadata
            .iter()
            .map(|m| m.path.clone())
            .collect();
        assert!(
            event_paths.contains(&temperature_event_path.as_str().to_string()),
            "Missing temperature event path"
        );
        assert!(
            event_paths.contains(&humidity_event_path.as_str().to_string()),
            "Missing humidity event path"
        );
        assert!(
            event_paths.contains(&pressure_event_path.as_str().to_string()),
            "Missing pressure event path"
        );

        registry
            .unsubscribe_local(&temperature_subscription_id)
            .await
            .unwrap();

        // Verify that the unsubscribed event is no longer in the metadata
        let updated_events_metadata = registry.get_subscriptions_metadata(&search_path).await;
        assert_eq!(
            updated_events_metadata.len(),
            2,
            "Should have metadata for two events after unsubscription"
        );

        let updated_event_paths: Vec<String> = updated_events_metadata
            .iter()
            .map(|m| m.path.clone())
            .collect();
        assert!(
            !updated_event_paths.contains(&temperature_event_path.as_str().to_string()),
            "Temperature event should be removed"
        );
        assert!(
            updated_event_paths.contains(&humidity_event_path.as_str().to_string()),
            "Humidity event should still be present"
        );
        assert!(
            updated_event_paths.contains(&pressure_event_path.as_str().to_string()),
            "Pressure event should still be present"
        );
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}
