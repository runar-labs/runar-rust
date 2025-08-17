use anyhow::Result;
use runar_node::node::Node;
use runar_node::services::NodeDelegate;
use runar_serializer::ArcValue;
use runar_test_utils::create_node_test_config;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Test local event dispatch without networking
#[tokio::test]
async fn test_local_event_dispatch_multiple_subscribers() -> Result<()> {
    // Create a node with NO networking
    let config = create_node_test_config()?;
    let node = Node::new(config).await?;

    // Create counters to track which handlers get called
    let counter1 = Arc::new(Mutex::new(0));
    let counter2 = Arc::new(Mutex::new(0));

    // Create two subscriptions to the same topic BEFORE starting the node
    let counter1_clone = counter1.clone();
    let sub_id1 = node
        .subscribe(
            "test/event",
            Arc::new(move |_ctx, data| {
                let counter = counter1_clone.clone();
                Box::pin(async move {
                    *counter.lock().unwrap() += 1;
                    println!("Handler 1 called with data: {data:?}");
                    Ok(())
                })
            }),
            Some(runar_node::services::EventRegistrationOptions::default()),
        )
        .await?;

    let counter2_clone = counter2.clone();
    let sub_id2 = node
        .subscribe(
            "test/event",
            Arc::new(move |_ctx, data| {
                let counter = counter2_clone.clone();
                Box::pin(async move {
                    *counter.lock().unwrap() += 1;
                    println!("Handler 2 called with data: {data:?}");
                    Ok(())
                })
            }),
            Some(runar_node::services::EventRegistrationOptions::default()),
        )
        .await?;

    println!("Created subscription 1: {sub_id1}");
    println!("Created subscription 2: {sub_id2}");

    // Start the node
    node.start().await?;
    println!("Node started");

    // Publish an event
    let test_data = ArcValue::new_primitive(42.0);
    node.publish("test/event", Some(test_data)).await?;
    println!("Event published");

    // Give handlers time to execute
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check that both handlers were called
    let count1 = *counter1.lock().unwrap();
    let count2 = *counter2.lock().unwrap();

    println!("Counter 1: {count1}, Counter 2: {count2}");

    assert_eq!(count1, 1, "Handler 1 should have been called once");
    assert_eq!(count2, 1, "Handler 2 should have been called once");

    // Clean up
    node.unsubscribe(&sub_id1).await?;
    node.unsubscribe(&sub_id2).await?;

    Ok(())
}

/// Test the exact scenario from the remote test - MathService + external subscription
#[tokio::test]
async fn test_math_service_plus_external_subscription() -> Result<()> {
    use crate::fixtures::math_service::MathService;

    // Create a node with NO networking
    let config = create_node_test_config()?;
    let  node = Node::new(config).await?;

    // Add MathService (this will create its own subscription to math/added)
    let math_service = MathService::new("math1", "math1");
    node.add_service(math_service).await?;

    // Create an external subscription to the same event BEFORE starting
    let received_data = Arc::new(Mutex::new(None));
    let received_data_clone = received_data.clone();

    let sub_id = node
        .subscribe(
            "math1/math/added",
            Arc::new(move |_ctx, data| {
                let received = received_data_clone.clone();
                Box::pin(async move {
                    println!("External handler received: {data:?}");
                    *received.lock().unwrap() = data.clone();
                    Ok(())
                })
            }),
            Some(runar_node::services::EventRegistrationOptions::default()),
        )
        .await?;

    println!("Created external subscription: {sub_id}");

    // Start the node
    node.start().await?;
    println!("Node started with MathService");
    node.wait_for_services_to_start().await?;

    // Call the math operation (which should publish math/added)
    let result = node
        .request(
            "math1/add",
            Some(runar_macros_common::params! { "a" => 5.0, "b" => 3.0 }),
        )
        .await?;
    let result_value = result.as_type_ref::<f64>()?;
    assert_eq!(*result_value, 8.0);
    println!("Math operation completed: 5 + 3 = {result_value}");

    // Give handlers time to execute
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check that the external subscription received the event
    let received = received_data.lock().unwrap().clone();
    assert!(
        received.is_some(),
        "External subscription should have received the math/added event"
    );

    if let Some(data) = received {
        let event_value = data.as_type_ref::<f64>()?;
        assert_eq!(*event_value, 8.0, "Event data should match the math result");
        println!("✅ External subscription received correct data: {event_value}");
    }

    // Clean up
    node.unsubscribe(&sub_id).await?;

    Ok(())
}
