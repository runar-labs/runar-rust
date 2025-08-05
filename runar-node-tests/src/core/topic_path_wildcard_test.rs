use anyhow::Result;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

use runar_common::logging::{Component, Logger};
use runar_node::routing::TopicPath;
use runar_node::services::EventContext;
use runar_node::ServiceRegistry;
use runar_serializer::ArcValue;

/// INTENTION: Test comprehensive scenarios for wildcard pattern matching in TopicPath
#[cfg(test)]
mod topic_path_wildcard_tests {
    use super::*;

    #[test]
    fn test_is_pattern() {
        // Test without wildcards
        let path1 = TopicPath::new("main:services/auth/login", "default").expect("Valid path");
        assert!(!path1.is_pattern());

        // Test with single-segment wildcard
        let pattern1 = TopicPath::new("main:services/*/login", "default").expect("Valid pattern");
        assert!(pattern1.is_pattern());

        // Test with multi-segment wildcard
        let pattern2 = TopicPath::new("main:services/>", "default").expect("Valid pattern");
        assert!(pattern2.is_pattern());
        assert!(pattern2.has_multi_wildcard());
    }

    #[test]
    fn test_single_wildcard_matching() {
        // Create pattern with single-segment wildcard
        let pattern = TopicPath::new("main:services/*/state", "default").expect("Valid pattern");

        // Test successful matches
        let path1 = TopicPath::new("main:services/auth/state", "default").expect("Valid path");
        let path2 = TopicPath::new("main:services/math/state", "default").expect("Valid path");

        assert!(pattern.matches(&path1));
        assert!(pattern.matches(&path2));

        // Test non-matches
        let non_match1 = TopicPath::new("main:services/auth/login", "default").expect("Valid path");
        let non_match2 =
            TopicPath::new("main:services/auth/state/active", "default").expect("Valid path");
        let non_match3 = TopicPath::new("main:events/user/created", "default").expect("Valid path");

        assert!(!pattern.matches(&non_match1)); // Different last segment
        assert!(!pattern.matches(&non_match2)); // Too many segments
        assert!(!pattern.matches(&non_match3)); // Different service path
    }

    #[test]
    fn test_multi_wildcard_matching() {
        // Create pattern with multi-segment wildcard
        let pattern = TopicPath::new("main:services/>", "default").expect("Valid pattern");

        // Test successful matches (should match any path that starts with "services")
        let path1 = TopicPath::new("main:services/auth", "default").expect("Valid path");
        let path2 = TopicPath::new("main:services/auth/login", "default").expect("Valid path");
        let path3 =
            TopicPath::new("main:services/math/add/numbers", "default").expect("Valid path");

        assert!(pattern.matches(&path1));
        assert!(pattern.matches(&path2));
        assert!(pattern.matches(&path3));

        // Test non-matches
        let non_match1 = TopicPath::new("main:events/user/created", "default").expect("Valid path");

        assert!(!pattern.matches(&non_match1)); // Different service path
    }

    #[test]
    fn test_multi_wildcard_position() {
        // Multi-wildcard must be the last segment
        let invalid_pattern = TopicPath::new("main:services/>/state", "default");
        assert!(invalid_pattern.is_err());

        // But can be in the middle of a pattern as long as it's the last segment
        let valid_pattern = TopicPath::new("main:services/>", "default").expect("Valid pattern");
        assert!(valid_pattern.is_pattern());
        assert!(valid_pattern.has_multi_wildcard());
    }

    #[test]
    fn test_complex_patterns() {
        // Pattern with both types of wildcards
        let pattern = TopicPath::new("main:services/*/events/>", "default").expect("Valid pattern");

        // Test successful matches
        let path1 =
            TopicPath::new("main:services/auth/events/user/login", "default").expect("Valid path");
        let path2 = TopicPath::new("main:services/math/events/calculation/completed", "default")
            .expect("Valid path");

        assert!(pattern.matches(&path1));
        assert!(pattern.matches(&path2));

        // Test non-matches
        let non_match1 = TopicPath::new("main:services/auth/state", "default").expect("Valid path");
        let non_match2 =
            TopicPath::new("main:services/auth/logs/error", "default").expect("Valid path");

        assert!(!pattern.matches(&non_match1)); // Different segment after service
        assert!(!pattern.matches(&non_match2)); // "logs" instead of "events"
    }

    #[test]
    fn test_wildcard_at_beginning() {
        // Pattern with wildcard at beginning
        let pattern = TopicPath::new("main:*/state", "default").expect("Valid pattern");

        // Test successful matches (should match any service with "state" action)
        let path1 = TopicPath::new("main:auth/state", "default").expect("Valid path");
        let path2 = TopicPath::new("main:math/state", "default").expect("Valid path");

        assert!(pattern.matches(&path1));
        assert!(pattern.matches(&path2));

        // Test non-matches
        let non_match1 = TopicPath::new("main:auth/login", "default").expect("Valid path");

        assert!(!pattern.matches(&non_match1)); // Different action
    }

    #[test]
    fn test_network_isolation() {
        // Patterns should only match within the same network
        let pattern = TopicPath::new("main:services/*/state", "default").expect("Valid pattern");
        let path1 = TopicPath::new("main:services/auth/state", "default").expect("Valid path");
        let path2 = TopicPath::new("other:services/auth/state", "default").expect("Valid path");

        assert!(pattern.matches(&path1)); // Same network
        assert!(!pattern.matches(&path2)); // Different network
    }

    #[test]
    fn test_efficient_template_pattern_lookup() {
        use runar_node::routing::TopicPath;
        use std::collections::HashMap;

        // Create a HashMap to store handlers by path pattern
        let mut handlers = HashMap::new();
        let network_id = "main";

        // Store handlers with template patterns
        let template1 = TopicPath::new("services/{service_path}/actions/{action}", network_id)
            .expect("Valid template path");
        let template2 =
            TopicPath::new("services/*/state", network_id).expect("Valid wildcard path");

        handlers.insert(template1.to_string(), "TEMPLATE_HANDLER_1");
        handlers.insert(template2.to_string(), "WILDCARD_HANDLER");

        // Create a concrete path to look up
        let concrete_path =
            TopicPath::new("services/math/actions/add", network_id).expect("Valid concrete path");

        // Generate possible template patterns from the concrete path
        // This is the key insight - we can pre-compute all possible template patterns
        // that might match our concrete path, then look them up directly
        let possible_templates = generate_possible_templates(&concrete_path);

        // Look up each possible template pattern
        for template in possible_templates {
            if let Some(handler) = handlers.get(&template) {
                println!("Found handler for template: {template}");
                println!("Handler: {handler}");
                // Found a matching handler, use it
                return;
            }
        }

        // No matching template found
        panic!("No matching template found for {concrete_path}");
    }

    /// Generate all possible template patterns that could match a concrete path
    fn generate_possible_templates(path: &TopicPath) -> Vec<String> {
        // For this example, we'll manually create the patterns we know should match
        // In a real implementation, we would generate these systematically

        let concrete_path = path.to_string();
        let mut templates = Vec::new();

        // Add the concrete path itself (for exact matching)
        templates.push(concrete_path.clone());

        // Extract segments (network_id:path/to/resource)
        if let Some(path_part) = concrete_path.split(':').nth(1) {
            let segments: Vec<&str> = path_part.split('/').collect();

            // Create specific template patterns based on the segments
            if segments.len() >= 4 && segments[0] == "services" && segments[2] == "actions" {
                // Create services/{service_path}/actions/{action} pattern
                let network_id = concrete_path.split(':').next().unwrap_or("main");
                let template = format!("{network_id}:services/{{service_path}}/actions/{{action}}");
                templates.push(template);
            }

            if segments.len() >= 3 && segments[0] == "services" {
                // Create services/*/state pattern (wildcard)
                let network_id = concrete_path.split(':').next().unwrap_or("main");
                let template = format!("{network_id}:services/*/state");
                templates.push(template);
            }
        }

        templates
    }

    #[test]
    fn test_efficient_wildcard_pattern_lookup() {
        use runar_node::routing::TopicPath;
        use std::collections::HashMap;

        // Create a HashMap to store handlers by path pattern
        let mut handlers = HashMap::new();
        let network_id = "main";

        // Store handlers with wildcard patterns
        let wildcard1 =
            TopicPath::new("services/*/events", network_id).expect("Valid wildcard path");
        let wildcard2 =
            TopicPath::new("services/>", network_id).expect("Valid multi-wildcard path");

        handlers.insert(wildcard1.to_string(), "SINGLE_WILDCARD_HANDLER");
        handlers.insert(wildcard2.to_string(), "MULTI_WILDCARD_HANDLER");

        // Create a concrete path to look up
        let concrete_path =
            TopicPath::new("services/math/events", network_id).expect("Valid concrete path");

        // Generate possible wildcard patterns from the concrete path
        let possible_patterns = generate_wildcard_patterns(&concrete_path);

        // Look up each possible pattern
        let mut found_handler = false;
        for pattern in possible_patterns {
            if let Some(handler) = handlers.get(&pattern) {
                println!("Found handler for wildcard pattern: {pattern}");
                println!("Handler: {handler}");
                found_handler = true;
                break;
            }
        }

        assert!(
            found_handler,
            "No matching wildcard handler found for {concrete_path}",
        );
    }

    /// Generate possible wildcard patterns that could match a concrete path
    fn generate_wildcard_patterns(path: &TopicPath) -> Vec<String> {
        let concrete_path = path.to_string();
        let mut patterns = Vec::new();

        // Add the concrete path itself
        patterns.push(concrete_path.clone());

        // Extract segments (network_id:path/to/resource)
        if let Some(network_prefix) = concrete_path.split(':').next() {
            if let Some(path_part) = concrete_path.split(':').nth(1) {
                let segments: Vec<&str> = path_part.split('/').collect();

                // Generate wildcards based on structure
                if segments.len() >= 3 && segments[0] == "services" {
                    // Replace the middle segment with a * wildcard
                    let wildcard_middle =
                        format!("{}:services/*/{}", network_prefix, segments[2..].join("/"));
                    patterns.push(wildcard_middle);

                    // Add a multi-segment wildcard pattern
                    patterns.push(format!("{network_prefix}:services/>"));
                }
            }
        }

        patterns
    }
}

/// INTENTION: Test wildcard pattern matching with the service registry for event subscriptions
#[cfg(test)]
mod service_registry_wildcard_tests {
    use super::*;
    use runar_node::{services::EventRegistrationOptions, Node};
    use runar_test_utils::create_node_test_config;

    /// Test event handler for wildcard subscriptions
    #[tokio::test]
    async fn test_wildcard_event_subscriptions() -> Result<()> {
        // Create service registry
        let registry = ServiceRegistry::new(Arc::new(Logger::new_root(Component::Service, "test")));

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
            .register_local_event_subscription(&pattern1, callback.clone(), EventRegistrationOptions::default())
            .await?;

        // Subscribe to a pattern with a multi-level wildcard
        let pattern2 = TopicPath::new("main:events/>", "default").expect("Valid pattern");
        let _sub_id2 = registry
            .register_local_event_subscription(&pattern2, callback.clone(), EventRegistrationOptions::default())
            .await?;

        // Subscribe to a specific path to compare
        let specific_path =
            TopicPath::new("main:services/math/add", "default").expect("Valid path");
        let _sub_id3 = registry
            .register_local_event_subscription(&specific_path, callback.clone(), EventRegistrationOptions::default())
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
                Arc::new(Logger::new_root(Component::Service, "test")),
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
                Arc::new(Logger::new_root(Component::Service, "test")),
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
                Arc::new(Logger::new_root(Component::Service, "test")),
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
                Arc::new(Logger::new_root(Component::Service, "test")),
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
                Arc::new(Logger::new_root(Component::Service, "test")),
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
        let registry = ServiceRegistry::new(Arc::new(Logger::new_root(Component::Service, "test")));

        // Create a callback
        let callback = Arc::new(move |_ctx: Arc<EventContext>, _data: Option<ArcValue>| {
            Box::pin(async move { Ok(()) }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        });

        // Subscribe to a pattern with a wildcard
        let pattern = TopicPath::new("main:services/*/state", "default").expect("Valid pattern");
        let sub_id = registry
            .register_local_event_subscription(&pattern, callback.clone(), EventRegistrationOptions::default())
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
        let registry = ServiceRegistry::new(Arc::new(Logger::new_root(Component::Service, "test")));
        
        // Create a callback
        let callback = Arc::new(move |_ctx: Arc<EventContext>, _data: Option<ArcValue>| {
            Box::pin(async move { Ok(()) }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        });

        // Register two handlers to the same wildcard pattern
        let pattern = TopicPath::new("main:events/>", "default").expect("Valid pattern");
        
        // Add first handler
        let sub_id1 = registry
            .register_local_event_subscription(&pattern, callback.clone(), EventRegistrationOptions::default())
            .await?;
        
        // Add second handler to the same pattern
        let sub_id2 = registry
            .register_local_event_subscription(&pattern, callback.clone(), EventRegistrationOptions::default())
            .await?;
        
        // Now test what happens when we search for a matching topic
        let search_topic = TopicPath::new("main:events/user/updated", "default").expect("Valid path");
        let handlers = registry.get_local_event_subscribers(&search_topic).await;
        
        // The issue: we should have exactly 2 handlers, but we're getting more
        assert_eq!(handlers.len(), 2, "Should have exactly 2 handlers, found {}", handlers.len());
        
        // Verify we have the expected subscription IDs
        let handler_ids: Vec<String> = handlers.iter().map(|(id, _, _)| id.clone()).collect();
        assert!(handler_ids.contains(&sub_id1), "First subscription ID not found");
        assert!(handler_ids.contains(&sub_id2), "Second subscription ID not found");
        
        Ok(())
    }

    /// Test that multiple wildcard handlers can be registered and receive events
    #[tokio::test]
    async fn test_multiple_wildcard_handlers() -> Result<()> {
        let registry = ServiceRegistry::new(Arc::new(Logger::new_root(Component::Service, "test")));
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
            .register_local_event_subscription(&pattern, callback1, EventRegistrationOptions::default())
            .await?;
        let _sub_id2 = registry
            .register_local_event_subscription(&pattern, callback2, EventRegistrationOptions::default())
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
                Arc::new(Logger::new_root(Component::Service, "test")),
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
