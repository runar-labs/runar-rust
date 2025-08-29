use anyhow::Result;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

use runar_common::logging::{Component, Logger};
use runar_common::routing::TopicPath;
use runar_node::services::{EventContext, EventRegistrationOptions};
use runar_node::{Node, ServiceRegistry};
use runar_serializer::ArcValue;
use runar_test_utils::create_node_test_config;

#[cfg(test)]
mod service_registry_wildcard_tests {
    use super::*;

    /// Test event handler for wildcard subscriptions
    #[tokio::test]
    async fn test_wildcard_event_subscriptions() -> Result<()> {
        // Create service registry
        let registry = ServiceRegistry::new(Arc::new(Logger::new_root(Component::Custom("Test"))));

        // Create a counter to track event deliveries
        let counter = Arc::new(Mutex::new(0));

        // Create a callback that increments the counter
        let counter_clone = counter.clone();
        let callback = Arc::new(move |_ctx: Arc<EventContext>, _data: Option<ArcValue>| {
            let counter = counter_clone.clone();
            Box::pin(async move {
                let mut lock = counter.lock().await;
                *lock += 1;
                Ok(())
            }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        });

        // Subscribe to a pattern with a single-level wildcard
        let pattern1 = TopicPath::new("main:services/*/state", "default").expect("Valid pattern");
        let _sub_id1 = registry
            .register_local_event_subscription(
                &pattern1,
                callback.clone(),
                &EventRegistrationOptions::default(),
            )
            .await?;

        // Subscribe to a pattern with a multi-level wildcard
        let pattern2 = TopicPath::new("main:events/>", "default").expect("Valid pattern");
        let _sub_id2 = registry
            .register_local_event_subscription(
                &pattern2,
                callback.clone(),
                &EventRegistrationOptions::default(),
            )
            .await?;

        // Subscribe to a specific path to compare
        let specific_path =
            TopicPath::new("main:services/math/add", "default").expect("Valid path");
        let _sub_id3 = registry
            .register_local_event_subscription(
                &specific_path,
                callback.clone(),
                &EventRegistrationOptions::default(),
            )
            .await?;

        // Publish to various topics and check if they match

        // Should match pattern1
        let topic1 = TopicPath::new("main:services/auth/state", "default").expect("Valid path");
        let topic2 = TopicPath::new("main:services/math/state", "default").expect("Valid path");

        // Should match pattern2
        let topic3 = TopicPath::new("main:events/user/created", "default").expect("Valid path");
        let topic4 = TopicPath::new("main:events/system/started", "default").expect("Valid path");

        // Should match specific_path
        let topic5 = TopicPath::new("main:services/math/add", "default").expect("Valid path");

        // Should not match any subscriptions
        let topic6 = TopicPath::new("main:services/auth/login", "default").expect("Valid path");

        // Get handlers for each topic and call them
        let data = ArcValue::null();

        // Should match pattern1 (services/*/state)
        let handlers1 = registry.get_local_event_subscribers(&topic1).await;
        assert_eq!(handlers1.len(), 1);
        for (_, handler, _) in handlers1 {
            let context = Arc::new(EventContext::new(
                &topic1,
                Arc::new(
                    Node::new(create_node_test_config().expect("Error creating test config"))
                        .await?,
                ),
                true,
                Arc::new(Logger::new_root(Component::Custom("Test"))),
            ));
            handler(context, Some(data.clone())).await?;
        }

        // Should match pattern1 (services/*/state)
        let handlers2 = registry.get_local_event_subscribers(&topic2).await;
        assert_eq!(handlers2.len(), 1);
        for (_, handler, _) in handlers2 {
            let context = Arc::new(EventContext::new(
                &topic2,
                Arc::new(
                    Node::new(create_node_test_config().expect("Error creating test config"))
                        .await?,
                ),
                true,
                Arc::new(Logger::new_root(Component::Custom("Test"))),
            ));
            handler(context, Some(data.clone())).await?;
        }

        // Should match pattern2 (events/>)
        let handlers3 = registry.get_local_event_subscribers(&topic3).await;
        assert_eq!(handlers3.len(), 1);
        for (_, handler, _) in handlers3 {
            let context = Arc::new(EventContext::new(
                &topic3,
                Arc::new(
                    Node::new(create_node_test_config().expect("Error creating test config"))
                        .await?,
                ),
                true,
                Arc::new(Logger::new_root(Component::Custom("Test"))),
            ));
            handler(context, Some(data.clone())).await?;
        }

        // Should match pattern2 (events/>)
        let handlers4 = registry.get_local_event_subscribers(&topic4).await;
        assert_eq!(handlers4.len(), 1);
        for (_, handler, _) in handlers4 {
            let context = Arc::new(EventContext::new(
                &topic4,
                Arc::new(
                    Node::new(create_node_test_config().expect("Error creating test config"))
                        .await?,
                ),
                true,
                Arc::new(Logger::new_root(Component::Custom("Test"))),
            ));
            handler(context, Some(data.clone())).await?;
        }

        // Should match specific_path (services/math/add)
        let handlers5 = registry.get_local_event_subscribers(&topic5).await;
        assert_eq!(handlers5.len(), 1);
        for (_, handler, _) in handlers5 {
            let context = Arc::new(EventContext::new(
                &topic5,
                Arc::new(
                    Node::new(create_node_test_config().expect("Error creating test config"))
                        .await?,
                ),
                true,
                Arc::new(Logger::new_root(Component::Custom("Test"))),
            ));
            handler(context, Some(data.clone())).await?;
        }

        // Should not match any patterns
        let handlers6 = registry.get_local_event_subscribers(&topic6).await;
        assert_eq!(handlers6.len(), 0);

        // Check that the counter was incremented the correct number of times
        let final_count = *counter.lock().await;
        assert_eq!(final_count, 5); // 5 matching topics

        Ok(())
    }

    /// Test that wildcards can be unsubscribed properly
    #[tokio::test]
    async fn test_wildcard_unsubscription() -> Result<()> {
        // Create service registry
        let registry = ServiceRegistry::new(Arc::new(Logger::new_root(Component::Custom("Test"))));

        // Create a callback
        let callback = Arc::new(move |_ctx: Arc<EventContext>, _data: Option<ArcValue>| {
            Box::pin(async move { Ok(()) }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        });

        // Subscribe to a pattern with a wildcard
        let pattern = TopicPath::new("main:services/*/state", "default").expect("Valid pattern");
        let sub_id = registry
            .register_local_event_subscription(
                &pattern,
                callback.clone(),
                &EventRegistrationOptions::default(),
            )
            .await?;

        // Publish to a matching topic
        let topic = TopicPath::new("main:services/auth/state", "default").expect("Valid path");
        let handlers_before = registry.get_local_event_subscribers(&topic).await;
        assert_eq!(handlers_before.len(), 1);

        // Unsubscribe using the subscription ID
        registry.unsubscribe_local(&sub_id).await?;

        // Publish again, should not receive the event
        let handlers_after = registry.get_local_event_subscribers(&topic).await;
        assert_eq!(handlers_after.len(), 0);

        Ok(())
    }

    /// Minimal test to isolate PathTrie wildcard duplication issue
    #[tokio::test]
    async fn test_path_trie_wildcard_duplication() -> Result<()> {
        let registry = ServiceRegistry::new(Arc::new(Logger::new_root(Component::Custom("Test"))));

        // Create a callback
        let callback = Arc::new(move |_ctx: Arc<EventContext>, _data: Option<ArcValue>| {
            Box::pin(async move { Ok(()) }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        });

        // Register two handlers to the same wildcard pattern
        let pattern = TopicPath::new("main:events/>", "default").expect("Valid pattern");

        // Add first handler
        let sub_id1 = registry
            .register_local_event_subscription(
                &pattern,
                callback.clone(),
                &EventRegistrationOptions::default(),
            )
            .await?;

        // Add second handler to the same pattern
        let sub_id2 = registry
            .register_local_event_subscription(
                &pattern,
                callback.clone(),
                &EventRegistrationOptions::default(),
            )
            .await?;

        // Now test what happens when we search for a matching topic
        let search_topic =
            TopicPath::new("main:events/user/updated", "default").expect("Valid path");
        let handlers = registry.get_local_event_subscribers(&search_topic).await;

        // The issue: we should have exactly 2 handlers, but we're getting more
        assert_eq!(
            handlers.len(),
            2,
            "Should have exactly 2 handlers, found {}",
            handlers.len()
        );

        // Verify we have the expected subscription IDs
        let handler_ids: Vec<String> = handlers.iter().map(|(id, _, _)| id.clone()).collect();
        assert!(
            handler_ids.contains(&sub_id1),
            "First subscription ID not found"
        );
        assert!(
            handler_ids.contains(&sub_id2),
            "Second subscription ID not found"
        );

        Ok(())
    }

    /// Test that multiple wildcard handlers can be registered and receive events
    #[tokio::test]
    async fn test_multiple_wildcard_handlers() -> Result<()> {
        let registry = ServiceRegistry::new(Arc::new(Logger::new_root(Component::Custom("Test"))));
        let counter1 = Arc::new(Mutex::new(0));
        let counter2 = Arc::new(Mutex::new(0));

        // Callback 1
        let counter1_clone = counter1.clone();
        let callback1 = Arc::new(move |_ctx: Arc<EventContext>, _data: Option<ArcValue>| {
            let counter = counter1_clone.clone();
            Box::pin(async move {
                let mut lock = counter.lock().await;
                *lock += 1;
                Ok(())
            }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        });

        // Callback 2
        let counter2_clone = counter2.clone();
        let callback2 = Arc::new(move |_ctx: Arc<EventContext>, _data: Option<ArcValue>| {
            let counter = counter2_clone.clone();
            Box::pin(async move {
                let mut lock = counter.lock().await;
                *lock += 1;
                Ok(())
            }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        });

        // Subscribe both callbacks to the same wildcard pattern
        let pattern = TopicPath::new("main:events/>", "default").expect("Valid pattern");
        let _sub_id1 = registry
            .register_local_event_subscription(
                &pattern,
                callback1,
                &EventRegistrationOptions::default(),
            )
            .await?;
        let _sub_id2 = registry
            .register_local_event_subscription(
                &pattern,
                callback2,
                &EventRegistrationOptions::default(),
            )
            .await?;

        // Publish to a matching topic
        let topic = TopicPath::new("main:events/user/updated", "default").expect("Valid path");
        let data = ArcValue::null();

        // Get handlers and call them
        let handlers = registry.get_local_event_subscribers(&topic).await;
        assert_eq!(handlers.len(), 2); // Should now be exactly 2 handlers, no duplicates

        for (_, handler, _) in handlers {
            let context = Arc::new(EventContext::new(
                &topic,
                Arc::new(
                    Node::new(create_node_test_config().expect("Error creating test config"))
                        .await?,
                ),
                true,
                Arc::new(Logger::new_root(Component::Custom("Test"))),
            ));
            handler(context, Some(data.clone())).await?;
        }

        // Check counters
        let count1 = *counter1.lock().await;
        let count2 = *counter2.lock().await;
        assert_eq!(count1, 1); // Each callback should be called exactly once
        assert_eq!(count2, 1);

        Ok(())
    }
}
