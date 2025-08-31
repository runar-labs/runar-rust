use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_common::routing::TopicPath;
use runar_node::services::service_registry::{EventHandler, ServiceRegistry};
use runar_node::services::EventRegistrationOptions;
use std::sync::{Arc, Mutex};

/// Test multiple subscriptions to the same topic
#[tokio::test]
async fn test_multiple_subscriptions_same_topic() -> Result<()> {
    let logger = Arc::new(Logger::new_root(Component::Custom("Test")));
    let registry = ServiceRegistry::new(logger.clone());

    let topic_path = TopicPath::new("test/event", "network1").map_err(|e| anyhow::anyhow!(e))?;

    // Create two counters to track which handlers get called
    let counter1 = Arc::new(Mutex::new(0));
    let counter2 = Arc::new(Mutex::new(0));

    // Create first subscription
    let counter1_clone = counter1.clone();
    let handler1: EventHandler = Arc::new(move |_ctx, _data| {
        let counter = counter1_clone.clone();
        Box::pin(async move {
            *counter.lock().unwrap() += 1;
            println!("Handler 1 called");
            Ok(())
        })
    });

    // Create second subscription
    let counter2_clone = counter2.clone();
    let handler2: EventHandler = Arc::new(move |_ctx, _data| {
        let counter = counter2_clone.clone();
        Box::pin(async move {
            *counter.lock().unwrap() += 1;
            println!("Handler 2 called");
            Ok(())
        })
    });

    // Register both subscriptions
    let sub_id1 = registry
        .register_local_event_subscription(
            &topic_path,
            handler1,
            &EventRegistrationOptions::default(),
        )
        .await?;

    let sub_id2 = registry
        .register_local_event_subscription(
            &topic_path,
            handler2,
            &EventRegistrationOptions::default(),
        )
        .await?;

    println!("Registered subscription 1: {sub_id1}");
    println!("Registered subscription 2: {sub_id2}");

    // Get all subscribers - should be 2
    let subscribers = registry.get_local_event_subscribers(&topic_path).await;
    println!("Found {} subscribers", subscribers.len());

    assert_eq!(subscribers.len(), 2, "Should have 2 subscribers");

    // Just verify we have the correct number of subscribers
    // (We can't easily test the handler execution without a full Node setup)

    // Verify subscriber IDs are different
    let sub_ids: Vec<String> = subscribers.iter().map(|(id, _, _)| id.clone()).collect();
    assert_ne!(
        sub_ids[0], sub_ids[1],
        "Subscription IDs should be different"
    );

    Ok(())
}
