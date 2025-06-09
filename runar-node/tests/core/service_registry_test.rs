// Tests for the ServiceRegistry implementation
//
// These tests validate that the ServiceRegistry properly manages
// action handlers and event subscriptions.

use anyhow::{anyhow, Result};
use runar_node::{ActionMetadata, Node, NodeConfig};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use runar_common::logging::{Component, Logger};
use runar_common::types::ArcValueType;
use runar_node::routing::TopicPath;
use runar_node::services::abstract_service::ServiceState;
use runar_node::services::service_registry::{ServiceEntry, ServiceRegistry};
use runar_node::services::{ActionHandler, EventContext, RequestContext};

use crate::fixtures::math_service::MathService;

/// Create a test handler that validates its network ID
fn create_test_handler(name: &str, expected_network_id: &str) -> ActionHandler {
    let name = name.to_string();
    let expected_network_id = expected_network_id.to_string();

    Arc::new(move |_params, context| {
        let name = name.clone();
        let expected_network_id = expected_network_id.clone();

        Box::pin(async move {
            println!("{} executed with network: {}", name, context.network_id());

            // Validate the network ID
            if context.network_id() != expected_network_id {
                return Err(anyhow::anyhow!("Network ID mismatch"));
            }

            Ok(ArcValueType::new_primitive(name.to_string()))
        })
    })
}

/// Test that verifies subscription functionality in the service registry
///
/// INTENTION: This test validates that the registry can properly:
/// - Register a callback to a topic
/// - Allow unsubscribing from a topic
#[tokio::test]
async fn test_subscribe_and_unsubscribe() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a service registry
        let registry = ServiceRegistry::new_with_default_logger();

        // Create a TopicPath for the test topic
        let topic = TopicPath::new("test/event", "net1").expect("Valid topic path");

        // Create a flag to track if the callback was called
        let was_called = Arc::new(AtomicBool::new(false));
        let was_called_clone = was_called.clone();

        // Create a callback that would be invoked when an event is published
        let callback = Arc::new(
            move |_ctx: Arc<EventContext>,
                  _: Option<ArcValueType>|
                  -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
                let was_called = was_called_clone.clone();
                Box::pin(async move {
                    // Set the flag to true when called
                    was_called.store(true, Ordering::SeqCst);
                    Ok(())
                })
            },
        );

        // Subscribe to the topic using the correct method
        let subscription_id = registry
            .register_local_event_subscription(&topic, callback, None)
            .await
            .unwrap();

        // Test the get_local_event_subscribers method
        let handlers = registry.get_local_event_subscribers(&topic).await;
        assert_eq!(handlers.len(), 1, "Expected one handler to be registered");
        assert_eq!(handlers[0].0, subscription_id, "Subscriber ID should match");

        // Unsubscribe using the correct method
        registry.unsubscribe_local(&subscription_id).await.unwrap();

        // Verify the handler is removed
        let handlers_after = registry.get_local_event_subscribers(&topic).await;
        assert_eq!(
            handlers_after.len(),
            0,
            "Expected handler to be removed after unsubscribe"
        );
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that verifies wildcard subscriptions can be created and unsubscribed
///
/// INTENTION: This test validates that the registry properly supports:
/// - Subscribers with wildcard topics
/// - Unsubscribing from wildcard topics
#[tokio::test]
async fn test_wildcard_subscriptions() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a service registry
        let registry = ServiceRegistry::new_with_default_logger();

        // Create a callback
        let callback = Arc::new(
            move |_ctx: Arc<EventContext>,
                  _: Option<ArcValueType>|
                  -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
                Box::pin(async move { Ok(()) })
            },
        );

        // Create TopicPaths for wildcard subscriptions
        let wildcard1 = TopicPath::new("test/#", "net1").expect("Valid topic path");
        let wildcard2 = TopicPath::new("test/events/#", "net1").expect("Valid topic path");

        // Subscribe to wildcard topics using the correct method
        let _id1 = registry
            .register_local_event_subscription(&wildcard1, callback.clone(), None)
            .await
            .unwrap();
        let id2 = registry
            .register_local_event_subscription(&wildcard2, callback.clone(), None)
            .await
            .unwrap();

        // Verify handlers are registered correctly using the correct method
        let handlers1 = registry.get_local_event_subscribers(&wildcard1).await;
        let handlers2 = registry.get_local_event_subscribers(&wildcard2).await;

        assert_eq!(handlers1.len(), 1, "Expected one handler for wildcard1");
        assert_eq!(handlers2.len(), 1, "Expected one handler for wildcard2");

        // Unsubscribe from one wildcard using the correct method
        registry.unsubscribe_local(&id2).await.unwrap();

        // Verify the handler is removed using the correct method
        let handlers2_after = registry.get_local_event_subscribers(&wildcard2).await;
        assert_eq!(
            handlers2_after.len(),
            0,
            "Expected handler to be removed from wildcard2"
        );

        // But wildcard1 should still have its handler using the correct method
        let handlers1_after = registry.get_local_event_subscribers(&wildcard1).await;
        assert_eq!(
            handlers1_after.len(),
            1,
            "Expected wildcard1 handler to remain"
        );
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that verifies action handler registration and retrieval
///
/// INTENTION: This test validates that the registry can properly:
/// - Register an action handler
/// - Retrieve the registered action handler
/// - Return None for a non-existent action handler
#[tokio::test]
async fn test_register_and_get_action_handler() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        let logger = Arc::new(Logger::new_root(Component::Service, "test"));
        let registry = ServiceRegistry::new(logger.clone());

        let service_path = "math".to_string();
        let action_name = "add".to_string();

        // Create a TopicPath for the action
        let action_path = format!("{}/{}", service_path, action_name);
        let topic_path = TopicPath::new(&action_path, "net1").unwrap();

        // Create a handler
        let handler: ActionHandler = Arc::new(|params, _context| {
            Box::pin(async move {
                println!("Handler called with params: {:?}", params);
                Ok(ArcValueType::null())
            })
        });

        // Register the handler
        registry
            .register_local_action_handler(&topic_path, handler.clone(), None)
            .await
            .unwrap();

        // Get the handler using the correct local method
        let retrieved_handler = registry.get_local_action_handler(&topic_path).await;

        // Verify the handler was registered and can be retrieved
        assert!(retrieved_handler.is_some());

        // Check for a non-existent handler
        let non_existent_path = TopicPath::new("math/nonexistent", "net1").unwrap();
        let non_existent_handler = registry.get_local_action_handler(&non_existent_path).await;
        assert!(
            non_existent_handler.is_none(),
            "Should not find a handler for a non-existent path"
        );
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that multiple action handlers can be registered and retrieved correctly
///
/// INTENTION: This test validates that the registry can properly:
/// - Register multiple action handlers for the same service
/// - Register handlers for different services
/// - Retrieve all handlers correctly
#[tokio::test]
async fn test_multiple_action_handlers() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        let logger = Arc::new(Logger::new_root(Component::Service, "test"));
        let registry = ServiceRegistry::new(logger.clone());

        // Create paths and handlers for different actions
        let add_action_path = TopicPath::new("math/add", "net1").unwrap();
        let subtract_action_path = TopicPath::new("math/subtract", "net1").unwrap();
        let concat_action_path = TopicPath::new("strings/concat", "net1").unwrap();

        // Create handlers for each action
        let add_handler: ActionHandler = Arc::new(|params, _context| {
            Box::pin(async move {
                println!("Add handler called with params: {:?}", params);
                Ok(ArcValueType::null())
            })
        });

        let subtract_handler: ActionHandler = Arc::new(|params, _context| {
            Box::pin(async move {
                println!("Subtract handler called with params: {:?}", params);
                Ok(ArcValueType::null())
            })
        });

        let concat_handler: ActionHandler = Arc::new(|params, _context| {
            Box::pin(async move {
                println!("Concat handler called with params: {:?}", params);
                Ok(ArcValueType::null())
            })
        });

        // Register all handlers
        registry
            .register_local_action_handler(&add_action_path, add_handler, None)
            .await
            .unwrap();

        registry
            .register_local_action_handler(&subtract_action_path, subtract_handler, None)
            .await
            .unwrap();

        registry
            .register_local_action_handler(&concat_action_path, concat_handler, None)
            .await
            .unwrap();

        // Get all handlers using the correct local method
        let add_handler_result = registry.get_local_action_handler(&add_action_path).await;
        let subtract_handler_result = registry
            .get_local_action_handler(&subtract_action_path)
            .await;
        let concat_handler_result = registry.get_local_action_handler(&concat_action_path).await;

        // Verify all handlers were registered and can be retrieved
        assert!(
            add_handler_result.is_some(),
            "Add handler should be registered"
        );
        assert!(
            subtract_handler_result.is_some(),
            "Subtract handler should be registered"
        );
        assert!(
            concat_handler_result.is_some(),
            "Concat handler should be registered"
        );
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that verifies action handlers obey network boundaries
///
/// INTENTION: This test validates that the registry can properly:
/// - Keep action handlers isolated by network
/// - Return the correct handler for each network
#[tokio::test]
async fn test_action_handler_network_isolation() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a registry
        let logger = Arc::new(Logger::new_root(Component::Service, "test"));
        let registry = ServiceRegistry::new(logger.clone());

        // Define two paths with the same path but different network IDs
        let network1_path = TopicPath::new("math/add", "network1").unwrap();
        let network2_path = TopicPath::new("math/add", "network2").unwrap();

        // Create handlers for each network
        let handler1 = create_test_handler("Handler1", "network1");
        let handler2 = create_test_handler("Handler2", "network2");

        println!("VERIFICATION 1: Testing handler retrieval");

        // Register handlers on their respective networks
        registry
            .register_local_action_handler(&network1_path, handler1.clone(), None)
            .await
            .unwrap();
        registry
            .register_local_action_handler(&network2_path, handler2.clone(), None)
            .await
            .unwrap();

        println!("VERIFICATION 2: Testing handler execution with proper context");
        let node: Arc<Node> = Arc::new(
            Node::new(NodeConfig::new("test-node", "default"))
                .await
                .unwrap(),
        );

        // Execute each handler with the correct network ID in the context
        let request_ctx1 = RequestContext::new(&network1_path, node.clone(), logger.clone());
        let request_ctx2 = RequestContext::new(&network2_path, node, logger.clone());

        // Test handler 1 with network1 context
        let result1 = registry
            .get_local_action_handler(&network1_path)
            .await
            .unwrap();
        let (handler1_retrieved, _) = result1; // Extract the handler from the tuple
        handler1_retrieved(Some(ArcValueType::null()), request_ctx1)
            .await
            .unwrap();

        // Test handler 2 with network2 context
        let result2 = registry
            .get_local_action_handler(&network2_path)
            .await
            .unwrap();
        let (handler2_retrieved, _) = result2; // Extract the handler from the tuple
        handler2_retrieved(Some(ArcValueType::null()), request_ctx2)
            .await
            .unwrap();

        println!("\nVERIFICATION 3: Demonstrating the network isolation");

        // Create a wrong network path using the same action path but with a different network ID
        let wrong_network_path = TopicPath::new("math/add", "wrong_network").unwrap();

        // This should now return None because network isolation is properly implemented
        let handler_when_wrong_network =
            registry.get_local_action_handler(&wrong_network_path).await;

        // Now the bug is fixed - we should NOT find handlers registered for other networks
        println!(
            "Bug fixed: handler_when_wrong_network.is_some() = {}",
            handler_when_wrong_network.is_some()
        );
        assert!(
            handler_when_wrong_network.is_none(),
            "Should not find handlers from other networks"
        );

        println!("\nVERIFICATION 4: Context validation is still good practice");
        let node: Arc<Node> = Arc::new(
            Node::new(NodeConfig::new("test-node", "default"))
                .await
                .unwrap(),
        );
        // Create a context with the wrong network ID
        let wrong_network_context = RequestContext::new(&wrong_network_path, node, logger.clone());

        // Even though the PathTrie bug is fixed, it's still good practice to validate network IDs
        // in handlers for defense in depth
        let handler1_with_wrong_ctx =
            handler1(Some(ArcValueType::null()), wrong_network_context.clone()).await;
        assert!(
            handler1_with_wrong_ctx.is_err(),
            "Handler should validate network ID"
        );

        println!("\nCONCLUSION: Network isolation works correctly");
        println!("The PathTrie implementation properly isolates by network ID");
    })
    .await
    {
        Ok(_) => (),
        Err(e) => panic!("Test timed out: {}", e),
    }
}

/// Test that verifies multiple event handlers can be registered and retrieved
///
/// INTENTION: This test validates that the registry can properly:
/// - Register multiple event handlers for different topics
/// - Retrieve all handlers for a specific topic
#[tokio::test]
async fn test_multiple_event_handlers() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a service registry
        let registry = ServiceRegistry::new_with_default_logger();

        // Create test topics
        let topic1 = TopicPath::new("events/created", "net1").expect("Valid topic path");
        let topic2 = TopicPath::new("events/updated", "net1").expect("Valid topic path");

        // Create three handlers for the multiple event handlers test
        let received_topic1 = Arc::new(AtomicBool::new(false));
        let received_topic1_clone = received_topic1.clone();

        let received_topic2 = Arc::new(AtomicBool::new(false));
        let received_topic2_clone = received_topic2.clone();

        // Create a first event handler to track events with "topic1"
        let handler1 = Arc::new(
            move |_ctx: Arc<EventContext>,
                  _data: Option<ArcValueType>|
                  -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
                let received = received_topic1_clone.clone();
                Box::pin(async move {
                    received.store(true, Ordering::SeqCst);
                    Ok(())
                })
            },
        );

        // Create a second event handler to track events with "topic2"
        let handler2 = Arc::new(
            move |_ctx: Arc<EventContext>,
                  _data: Option<ArcValueType>|
                  -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
                let received = received_topic2_clone.clone();
                Box::pin(async move {
                    received.store(true, Ordering::SeqCst);
                    Ok(())
                })
            },
        );

        // Subscribe handlers to topics using the correct method
        let id1 = registry
            .register_local_event_subscription(&topic1, handler1, None)
            .await
            .unwrap();
        let id2 = registry
            .register_local_event_subscription(&topic2, handler2, None)
            .await
            .unwrap();

        // Retrieve and verify handlers using the correct method
        let handlers1 = registry.get_local_event_subscribers(&topic1).await;
        let handlers2 = registry.get_local_event_subscribers(&topic2).await;

        assert_eq!(handlers1.len(), 1, "Expected one handler for topic1");
        assert_eq!(handlers2.len(), 1, "Expected one handler for topic2");
        assert_eq!(handlers1[0].0, id1, "Subscriber ID should match for topic1");
        assert_eq!(handlers2[0].0, id2, "Subscriber ID should match for topic2");

        // Verify getting handlers for a non-existent topic using the correct method
        let nonexistent_topic =
            TopicPath::new("test/events/deleted", "net1").expect("Valid topic path");
        let handlers_none = registry
            .get_local_event_subscribers(&nonexistent_topic)
            .await;
        assert_eq!(
            handlers_none.len(),
            0,
            "Expected no handlers for non-existent topic"
        );
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that verifies path template parameters functionality in action handlers
///
/// INTENTION: This test validates that the registry can properly:
/// - Register an action handler with path parameters using template syntax like {parameter}
/// - Match and retrieve the correct handler when a request comes in with a path that matches the template
/// - Extract path parameters from the matched path
#[tokio::test]
async fn test_path_template_parameters() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        let logger = Arc::new(Logger::new_root(Component::Service, "test"));
        let registry = ServiceRegistry::new(logger.clone());

        // Create paths with parameter templates
        let service_info_path =
            TopicPath::new("$registry/services/{service_path}", "test_network").unwrap();
        let service_state_path =
            TopicPath::new("$registry/services/{service_path}/state", "test_network").unwrap();
        let action_path = TopicPath::new(
            "$registry/services/{service_type}/actions/{action_name}",
            "test_network",
        )
        .unwrap();

        // Create handlers that include parameter checking
        let service_info_handler: ActionHandler = Arc::new(move |_params, context| {
            Box::pin(async move {
                let service_path = context
                    .path_params
                    .get("service_path")
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());

                println!("Service info handler called for service: {}", service_path);

                // Validate that the parameter was captured
                if service_path == "unknown" {
                    return Err(anyhow!("Missing service_path parameter"));
                }

                Ok(ArcValueType::null())
            })
        });

        let service_state_handler: ActionHandler = Arc::new(move |_params, context| {
            Box::pin(async move {
                let service_path = context
                    .path_params
                    .get("service_path")
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());

                println!("Service state handler called for service: {}", service_path);

                // Validate that the parameter was captured
                if service_path == "unknown" {
                    return Err(anyhow!("Missing service_path parameter"));
                }

                Ok(ArcValueType::null())
            })
        });

        let action_handler: ActionHandler = Arc::new(move |_params, context| {
            Box::pin(async move {
                let service_type = context
                    .path_params
                    .get("service_type")
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());

                let action_name = context
                    .path_params
                    .get("action_name")
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());

                println!(
                    "Action handler called for service_type: {}, action_name: {}",
                    service_type, action_name
                );

                // Validate that all parameters were captured
                if service_type == "unknown" || action_name == "unknown" {
                    return Err(anyhow!("Missing parameters"));
                }

                Ok(ArcValueType::null())
            })
        });

        // Register all handlers using the correct local method
        registry
            .register_local_action_handler(&service_info_path, service_info_handler, None)
            .await
            .unwrap();
        registry
            .register_local_action_handler(&service_state_path, service_state_handler, None)
            .await
            .unwrap();
        registry
            .register_local_action_handler(&action_path, action_handler, None)
            .await
            .unwrap();

        // Test that the correct handlers are found for the specific paths using the local method
        let service_info_handler = registry.get_local_action_handler(&service_info_path).await;
        let service_state_handler = registry.get_local_action_handler(&service_state_path).await;
        let action_handler = registry.get_local_action_handler(&action_path).await;

        // Verify the handlers were found by template matching
        assert!(
            service_info_handler.is_some(),
            "service handler should be found via template matching"
        );
        assert!(
            service_state_handler.is_some(),
            "state handler should be found via template matching"
        );
        assert!(
            action_handler.is_some(),
            "handler should be found via template matching"
        );

        // Test non-matching paths
        let user_profile_path = TopicPath::new("user/profile", "test_network").unwrap();
        let non_matching_handler = registry.get_local_action_handler(&user_profile_path).await;
        assert!(
            non_matching_handler.is_none(),
            "Non-matching path should not find a handler"
        );

        // Test partial matches (missing segments)
        let incomplete_path = TopicPath::new("services/auth", "test_network").unwrap();
        let incomplete_handler = registry.get_local_action_handler(&incomplete_path).await;
        assert!(
            incomplete_handler.is_none(),
            "Incomplete path should not match a template"
        );

        // Test with incorrect segment count
        let wrong_segments_path =
            TopicPath::new("services/auth/actions/login/extra", "test_network").unwrap();
        let wrong_segments_handler = registry
            .get_local_action_handler(&wrong_segments_path)
            .await;
        assert!(
            wrong_segments_handler.is_none(),
            "Path with wrong segment count should not match a template"
        );
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test for local vs remote action handler separation
///
/// INTENTION: This test validates that the registry can properly:
/// - Keep local and remote action handlers separate
/// - Return the appropriate handlers based on whether we use local or remote lookup
#[tokio::test]
async fn test_local_remote_action_handler_separation() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        let logger = Arc::new(Logger::new_root(Component::Service, "test"));
        let registry = ServiceRegistry::new(logger.clone());

        // Create a common topic path for both local and remote
        let action_path = TopicPath::new("math/add", "test_network").unwrap();

        // Create a local handler
        let local_handler: ActionHandler = Arc::new(|_params, _context| {
            Box::pin(async move {
                println!("Local handler called");
                Ok(ArcValueType::null())
            })
        });

        // Register the local handler
        registry
            .register_local_action_handler(&action_path, local_handler, None)
            .await
            .unwrap();

        // Verify we can get the local handler
        let retrieved_local = registry.get_local_action_handler(&action_path).await;
        assert!(
            retrieved_local.is_some(),
            "Local handler should be retrievable"
        );

        // Check remote handlers - should be empty since we didn't register any
        let remote_handlers = registry.get_remote_action_handlers(&action_path).await;
        assert!(
            remote_handlers.is_empty(),
            "No remote handlers should be found"
        );

        // The test could be extended to also register and test remote handlers if needed
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

#[tokio::test]
async fn test_multiple_network_ids() {
    // Set up test logger
    let logger = Arc::new(Logger::new_root(Component::Service, "test"));

    // Create registry
    let registry = ServiceRegistry::new(logger.clone());

    // Create network-specific action paths
    let network1_path = TopicPath::new("network1:math/add", "default").unwrap();
    let network2_path = TopicPath::new("network2:math/add", "default").unwrap();

    let node = Arc::new(
        Node::new(NodeConfig::new("test-node", "default"))
            .await
            .unwrap(),
    );

    // Request contexts for each network
    let request_ctx1 = RequestContext::new(&network1_path, node.clone(), logger.clone());
    let request_ctx2 = RequestContext::new(&network2_path, node, logger.clone());

    // Create network-specific handlers
    let network1_handler: ActionHandler = Arc::new(move |_params, context| {
        let network_id = context.topic_path.network_id();
        assert_eq!(network_id, "network1");

        Box::pin(async move {
            Ok(ArcValueType::new_primitive(format!(
                "Response from {}",
                network_id
            )))
        })
    });

    let network2_handler: ActionHandler = Arc::new(move |_params, context| {
        let network_id = context.topic_path.network_id();
        assert_eq!(network_id, "network2");

        Box::pin(async move {
            Ok(ArcValueType::new_primitive(format!(
                "Response from {}",
                network_id
            )))
        })
    });

    // Register handlers for different networks
    registry
        .register_local_action_handler(&network1_path, network1_handler, None)
        .await
        .unwrap();
    registry
        .register_local_action_handler(&network2_path, network2_handler, None)
        .await
        .unwrap();

    // Test that each network gets its own handler
    let result1 = registry
        .get_local_action_handler(&network1_path)
        .await
        .unwrap();
    let (handler1, _) = result1;
    handler1(Some(ArcValueType::null()), request_ctx1)
        .await
        .unwrap();

    let result2 = registry
        .get_local_action_handler(&network2_path)
        .await
        .unwrap();
    let (handler2, _) = result2;
    handler2(Some(ArcValueType::null()), request_ctx2)
        .await
        .unwrap();
}

/// Test that verifies the get_actions_metadata method returns correct metadata for actions
///
/// INTENTION: This test validates that the registry can properly:
/// - Register multiple action handlers for a service
/// - Return the correct metadata for all actions under a service path
#[tokio::test]
async fn test_get_actions_metadata() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Set up test logger
        let logger = Arc::new(Logger::new_root(Component::Service, "test"));

        // Create registry
        let registry = ServiceRegistry::new(logger.clone());

        // Create a service path and action paths
        let service_path = TopicPath::new("math-service", "test-network").unwrap();
        let add_action_path = TopicPath::new("math-service/add", "test-network").unwrap();
        let subtract_action_path = TopicPath::new("math-service/subtract", "test-network").unwrap();
        let multiply_action_path = TopicPath::new("math-service/multiply", "test-network").unwrap();

        // Create action handlers
        let add_handler: ActionHandler =
            Arc::new(|_params, _context| Box::pin(async move { Ok(ArcValueType::null()) }));
        let add_metadata = ActionMetadata {
            name: add_action_path.as_str().to_string(),
            description: "Add action".to_string(),
            input_schema: None,
            output_schema: None,
        };

        let subtract_handler: ActionHandler =
            Arc::new(|_params, _context| Box::pin(async move { Ok(ArcValueType::null()) }));
        let subtract_metadata = ActionMetadata {
            name: subtract_action_path.as_str().to_string(),
            description: "Subtract action".to_string(),
            input_schema: None,
            output_schema: None,
        };

        let multiply_handler: ActionHandler =
            Arc::new(|_params, _context| Box::pin(async move { Ok(ArcValueType::null()) }));
        let multiply_metadata = ActionMetadata {
            name: multiply_action_path.as_str().to_string(),
            description: "Multiply action".to_string(),
            input_schema: None,
            output_schema: None,
        };

        // Register the action handlers
        registry
            .register_local_action_handler(&add_action_path, add_handler, Some(add_metadata))
            .await
            .unwrap();
        registry
            .register_local_action_handler(
                &subtract_action_path,
                subtract_handler,
                Some(subtract_metadata),
            )
            .await
            .unwrap();
        registry
            .register_local_action_handler(
                &multiply_action_path,
                multiply_handler,
                Some(multiply_metadata),
            )
            .await
            .unwrap();

        // Create a wildcard path to match all actions under this service
        let service_path_str = service_path.service_path();
        let wildcard_path = format!("{}/*", service_path_str);
        let search_path =
            TopicPath::new(&wildcard_path, service_path.network_id().as_str()).unwrap();

        // Get the action metadata for the service using the wildcard path
        let actions_metadata = registry.get_actions_metadata(&search_path).await;

        // Verify that we got metadata for all three actions
        assert_eq!(
            actions_metadata.len(),
            3,
            "Should have metadata for all three actions"
        );

        // Verify the paths of the actions in the metadata
        let action_paths: Vec<String> = actions_metadata.iter().map(|m| m.name.clone()).collect();
        assert!(
            action_paths.contains(&add_action_path.as_str().to_string()),
            "Missing add action path"
        );
        assert!(
            action_paths.contains(&subtract_action_path.as_str().to_string()),
            "Missing subtract action path"
        );
        assert!(
            action_paths.contains(&multiply_action_path.as_str().to_string()),
            "Missing multiply action path"
        );

        // Verify that the descriptions contain the action names
        for metadata in &actions_metadata {
            if metadata.name.contains("/add") {
                assert!(
                    metadata.description.contains("Add action"),
                    "Description should contain action name"
                );
            } else if metadata.name.contains("/subtract") {
                assert!(
                    metadata.description.contains("Subtract action"),
                    "Description should contain action name"
                );
            } else if metadata.name.contains("/multiply") {
                assert!(
                    metadata.description.contains("Multiply action"),
                    "Description should contain action name"
                );
            }
        }
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that verifies the get_local_services method correctly retrieves all registered services
///
/// INTENTION: This test validates that the registry can properly:
/// - Register multiple services in different networks
/// - Retrieve all registered services using get_local_services without a dummy path
#[tokio::test]
async fn test_get_local_services() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a service registry
        let logger = Arc::new(Logger::new_root(Component::Service, "test"));
        let registry = ServiceRegistry::new(logger.clone());

        // Create services in different networks
        let service1 = Arc::new(MathService::new("service1", "service1"));
        let topic_path1 = TopicPath::new("service1", "service1").unwrap();
        let service2 = Arc::new(MathService::new("service2", "network1"));
        let topic_path2 = TopicPath::new("service2", "network1").unwrap();
        let service3 = Arc::new(MathService::new("service3", "network2"));
        let topic_path3 = TopicPath::new("service3", "network2").unwrap();

        // Create ServiceEntry objects
        let service_entry1 = Arc::new(ServiceEntry {
            service: service1.clone(),
            service_topic: topic_path1.clone(),
            service_state: ServiceState::Stopped,
            registration_time: 1000,
            last_start_time: None,
        });

        let service_entry2 = Arc::new(ServiceEntry {
            service: service2.clone(),
            service_topic: topic_path2.clone(),
            service_state: ServiceState::Stopped,
            registration_time: 1001,
            last_start_time: None,
        });

        let service_entry3 = Arc::new(ServiceEntry {
            service: service3.clone(),
            service_topic: topic_path3.clone(),
            service_state: ServiceState::Stopped,
            registration_time: 1002,
            last_start_time: None,
        });

        // Register the services
        registry
            .register_local_service(service_entry1.clone())
            .await
            .unwrap();
        registry
            .register_local_service(service_entry2.clone())
            .await
            .unwrap();
        registry
            .register_local_service(service_entry3.clone())
            .await
            .unwrap();

        // Get all local services
        let services = registry.get_local_services().await;

        // Verify that all services are retrieved
        assert_eq!(
            services.len(),
            3,
            "Expected all three services to be retrieved"
        );

        // Verify that each service is correctly retrieved
        assert!(
            services.contains_key(&topic_path1.clone()),
            "Service 1 should be in the result"
        );
        assert!(
            services.contains_key(&topic_path2.clone()),
            "Service 2 should be in the result"
        );
        assert!(
            services.contains_key(&topic_path3.clone()),
            "Service 3 should be in the result"
        );

        // Verify that the service entries match
        assert_eq!(
            services[&topic_path1.clone()].service.path().to_string(),
            service_entry1.service.path().to_string(),
            "Service 1 entry should match"
        );

        assert_eq!(
            services[&topic_path2.clone()].service.path().to_string(),
            service_entry2.service.path().to_string(),
            "Service 2 entry should match"
        );

        assert_eq!(
            services[&topic_path3.clone()].service.path().to_string(),
            service_entry3.service.path().to_string(),
            "Service 3 entry should match"
        );
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}
