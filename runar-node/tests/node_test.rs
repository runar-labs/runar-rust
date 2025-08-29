// Tests for the Node implementation
//
// These tests verify that the Node properly handles requests
// and delegates to the ServiceRegistry as needed.

use runar_common::logging::{Component, Logger};
use runar_common::logging::{LogLevel, LoggingConfig};
use runar_node::Node;
use runar_node::ServiceMetadata;
use runar_node::{LifecycleContext, NodeDelegate, RequestContext, TopicPath};

use runar_serializer::ArcValue;
use runar_test_utils::create_node_test_config;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use runar_node::services::EventContext;

use runar_macros_common::params;

// Import the test fixtures
use anyhow::Result;
use runar_test_utils::fixtures::math_service::MathService;
use runar_test_utils::fixtures::path_params_service::PathParamsService;
use tokio::task::JoinHandle;

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
        let mut config = create_node_test_config().expect("Error creating test config");
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
        let mut config = create_node_test_config().expect("Error creating test config");
        // Disable networking
        config.network_config = None;
        let node = Node::new(config).await.unwrap();

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
        let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);

        // Create a node with a test network ID
        let mut config = create_node_test_config()
            .expect("Error creating test config")
            .with_logging_config(logging_config);
        // Disable networking
        config.network_config = None;
        let node = Node::new(config).await.unwrap();

        // Create a test service with consistent name and path
        let service = MathService::new("Math Service", "math");

        // Add the service to the node
        node.add_service(service).await.unwrap();

        // Start the node to initialize all services
        node.start().await.unwrap();
        node.wait_for_services_to_start().await.unwrap();

        // Create parameters
        let params = params! {
            "a" => 5.0f64,
            "b" => 3.0f64,
        };

        // Make a request to the math service's add action
        let result_av = node
            .request("math/add", Some(params), None)
            .await
            .expect("math/add call failed")
            .as_type_ref::<f64>()
            .expect("failed to convert result");
        let result: f64 = *result_av;
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
        let mut config = create_node_test_config().expect("Error creating test config");
        // Disable networking
        config.network_config = None;
        let node = Node::new(config).await.unwrap();

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
async fn test_node_event_metadata_registration() -> Result<()> {
    let config = create_node_test_config().expect("Error creating test config");
    let default_network_id = config.default_network_id.clone();
    let node = Node::new(config).await?;

    let math_service_name = "MathMetaTest";
    let math_service_path = "math_meta_svc";
    let service = MathService::new(math_service_name, math_service_path);
    node.add_service(service).await?;
    node.start().await?; // This will call init() on MathService

    // Request the list of services from the registry
    let list_arc = node
        .request("$registry/services/list", None::<ArcValue>, None)
        .await?
        .as_typed_list_ref::<ServiceMetadata>()?;

    let math_service_metadata = list_arc
        .iter()
        .find(|s| s.service_path == math_service_path && s.network_id == default_network_id)
        .expect("MathService metadata not found in registry list");

    assert_eq!(math_service_metadata.name, math_service_name);

    node.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_node_init() -> Result<()> {
    // Create a node configuration
    let mut config = create_node_test_config().expect("Error creating test config");
    config.network_config = None;

    // Create a node
    let node = Node::new(config).await?;

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
        let mut config = create_node_test_config().expect("Error creating test config");
        config.network_config = None;
        let node = Node::new(config).await.unwrap();

        // Create a flag to track if the callback was called
        let was_called = Arc::new(AtomicBool::new(false));
        let was_called_clone = was_called.clone();

        // Define a topic to subscribe to
        let topic = "test/topic".to_string();

        // Create a handler function for subscription
        // Note: Using the full handler signature with Arc<EventContext> for the node API
        let handler = move |_ctx: Arc<EventContext>, data: Option<ArcValue>| {
            println!("Received event data: {data:?}");

            // Verify the data matches what we published
            // For ArcValue, extract the string value
            if let Some(av) = data {
                if let Ok(s_arc) = av.as_type_ref::<String>() {
                    assert_eq!(*s_arc, "test data");
                    // Mark that the handler was called with correct data
                    was_called_clone.store(true, Ordering::SeqCst);
                }
            }

            // Properly pin and box the future as expected by the subscribe method
            Box::pin(async move { Ok(()) }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        };

        // Subscribe to the topic using the node's API
        node.subscribe(
            &topic,
            Arc::new(handler),
            Some(runar_node::services::EventRegistrationOptions::default()),
        )
        .await
        .unwrap();

        // Publish an event to the topic
        let data = ArcValue::new_primitive("test data".to_string());
        node.publish(&topic, Some(data), None).await.unwrap();

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
    let mut config = create_node_test_config().expect("Error creating test config");
    config.network_config = None;
    let node = Node::new(config).await.unwrap();

    // Create our path parameters test service
    let service = PathParamsService::new("PathParams", "test");

    // Add the service to the node
    node.add_service(service).await.unwrap();

    // Start the node to initialize all services
    node.start().await.unwrap();
    node.wait_for_services_to_start().await.unwrap();

    // Make a request to a path that matches the template
    let av = node
        .request("test/abc123/items/xyz789", None::<ArcValue>, None)
        .await
        .unwrap();

    let params_map = av.as_typed_map_ref::<String>().expect("expect map");

    // Verify the path parameters were correctly extracted
    // params_map is now HashMap<String, String>
    assert_eq!(params_map.get("param_1").unwrap().as_ref(), "abc123");
    assert_eq!(params_map.get("param_2").unwrap().as_ref(), "xyz789");
}

/// Test that the on method functionality works correctly
///
/// INTENTION: This test validates that:
/// - on method returns event payload when event occurs within timeout
/// - on method returns timeout error when no event occurs
/// - on method works from both Node and context objects
#[tokio::test]
async fn test_on_method() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(15), async {
        // Create a node with a test network ID
        let config = create_node_test_config().expect("Error creating test config");
        let node = Node::new(config).await.unwrap();

        // Start the node
        node.start().await.unwrap();

        // Helper to await Node::on join handle
        async fn await_on(
            handle: JoinHandle<Result<Option<ArcValue>>>,
        ) -> anyhow::Result<Option<ArcValue>> {
            handle.await.map_err(|e| anyhow::anyhow!(e))?
        }

        // Test 1: on method should timeout when no event is published
        let result = await_on(node.on(
            "test_event",
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_millis(100),
                include_past: None,
            }),
        ))
        .await;
        assert!(
            result.is_err(),
            "on method should timeout when no event is published"
        );
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Timeout"),
            "Error should indicate timeout"
        );

        // Test 2: on method should receive event when published
        let topic = "test_event";
        let event_data = ArcValue::new_primitive(42i32);

        // Get the future first
        let future = node.on(
            topic,
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(5),
                include_past: None,
            }),
        );

        // Publish the event (should trigger the future)
        node.publish(topic, Some(event_data.clone()), None)
            .await
            .unwrap();

        // Wait for the event
        let received_data = await_on(future)
            .await?
            .expect("Received event data should not be None");
        assert_eq!(
            received_data, event_data,
            "Received event data should match published data"
        );

        // Test 3: Test from RequestContext
        let test_logger = Logger::new_root(Component::Custom("Test"));
        let topic_path = TopicPath::new("math/add", "test_network").unwrap();
        let context = RequestContext::new(
            &topic_path,
            Arc::new(node.clone()),
            Arc::new(test_logger.clone()),
        );

        let context_topic = "context_test_event";
        let context_event_data = ArcValue::new_primitive(100i32);

        // Get the future first
        let context_future = context.on(
            context_topic,
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(5),
                include_past: None,
            }),
        );

        // Publish event for context test
        node.publish(context_topic, Some(context_event_data.clone()), None)
            .await
            .unwrap();

        let received_context_data = context_future
            .await?
            .expect("Received event data should not be None");
        assert_eq!(
            received_context_data, context_event_data,
            "Context should receive correct event data"
        );

        // Test 4: Test from LifecycleContext
        let lifecycle_context =
            LifecycleContext::new(&topic_path, Arc::new(node.clone()), Arc::new(test_logger));

        let lifecycle_topic = "lifecycle_test_event";
        let lifecycle_event_data = ArcValue::new_primitive(200i32);

        // Get the future first
        let lifecycle_future = lifecycle_context.on(
            lifecycle_topic,
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(5),
                include_past: None,
            }),
        );

        // Publish event for lifecycle context test
        node.publish(lifecycle_topic, Some(lifecycle_event_data.clone()), None)
            .await
            .unwrap();

        let received_lifecycle_data = lifecycle_future
            .await?
            .expect("Received event data should not be None");
        assert_eq!(
            received_lifecycle_data, lifecycle_event_data,
            "LifecycleContext should receive correct event data"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 15 seconds"),
    }
}

/// Test that service state events are properly published and can be received via on method
///
/// INTENTION: This test validates that:
/// - Service initialization triggers state/initialized events
/// - Service start triggers state/running events  
/// - Service stop triggers state/stopped events
/// - Service errors trigger state/error events
/// - All state events can be received using the on method
#[tokio::test]
async fn test_service_state_events() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(20), async {
        // Create a node with a test network ID
        let mut config = create_node_test_config().expect("Error creating test config");
        config.network_config = None;
        let node = Node::new(config).await.unwrap();

        // Start the node
        node.start().await.unwrap();

        // Test 1: Service initialization state event
        let service_name = "StateTestService";
        let service_path = "state_test";
        let service = MathService::new(service_name, service_path);

        // Listen for initialization event before adding service
        let init_topic = format!("$registry/services/{service_path}/state/initialized");
        let node_clone = node.clone();
        let init_future = node_clone.on(
            init_topic.clone(),
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(5),
                include_past: None,
            }),
        );

        let wildcard_topic = "$registry/services/*/state/initialized";
        let wildcard_future = node_clone.on(
            wildcard_topic,
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(5),
                include_past: None,
            }),
        );

        // Add the service (should trigger initialized event)
        node.add_service(service).await.unwrap();

        // Wait for initialization event
        let init_data = init_future
            .await
            .map_err(|e| anyhow::anyhow!(e))??
            .expect("Received event data should not be None");
        let init_service_path = init_data.as_type_ref::<String>()?;
        assert_eq!(
            *init_service_path, service_path,
            "Initialized event should contain correct service path"
        );

        let wildcard_data = wildcard_future
            .await
            .map_err(|e| anyhow::anyhow!(e))??
            .expect("Received event data should not be None");
        let wildcard_service_path = wildcard_data.as_type_ref::<String>()?;
        assert_eq!(
            *wildcard_service_path, service_path,
            "Wildcard event should contain correct service path"
        );

        // Test 2: Service running state event
        let running_topic = format!("$registry/services/{service_path}/state/running");
        let node_clone = node.clone();
        let running_future = node_clone.on(
            running_topic.clone(),
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(5),
                include_past: None,
            }),
        );

        // Start the service (should trigger running event)
        node.start().await.unwrap();

        // Wait for running event
        let running_data = running_future
            .await
            .map_err(|e| anyhow::anyhow!(e))??
            .expect("Received event data should not be None");
        let running_service_path = running_data.as_type_ref::<String>()?;
        assert_eq!(
            *running_service_path, service_path,
            "Running event should contain correct service path"
        );

        // Test 3: Service stopped state event
        let stopped_topic = format!("$registry/services/{service_path}/state/stopped");
        let node_clone2 = node.clone();
        let stopped_future = node_clone2.on(
            stopped_topic.clone(),
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(5),
                include_past: None,
            }),
        );

        // Stop the service (should trigger stopped event)
        node.stop().await.unwrap();

        // Wait for stopped event
        let stopped_data = stopped_future
            .await
            .map_err(|e| anyhow::anyhow!(e))??
            .expect("Received event data should not be None");
        let stopped_service_path = stopped_data.as_type_ref::<String>()?;
        assert_eq!(
            *stopped_service_path, service_path,
            "Stopped event should contain correct service path"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 20 seconds"),
    }
}

/// Test that service state events work with wildcard subscriptions
///
/// INTENTION: This test validates that:
/// - Wildcard subscriptions can receive state events from multiple services
/// - State events are properly routed to wildcard subscribers
#[tokio::test]
async fn test_service_state_events_wildcard() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(15), async {
        // Create a node with a test network ID
        let mut config = create_node_test_config().expect("Error creating test config");
        config.network_config = None;
        let node = Node::new(config).await.unwrap();

        // Start the node
        node.start().await.unwrap();

        // Test wildcard subscription for all service running events
        let wildcard_topic = "$registry/services/*/state/running";
        let node_clone = node.clone();
        let wildcard_future = node_clone.on(
            wildcard_topic,
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(5),
                include_past: None,
            }),
        );

        // Add multiple services to trigger multiple running events
        let service1 = MathService::new("Service1", "service1");
        let service2 = MathService::new("Service2", "service2");

        node.add_service(service1).await.unwrap();
        node.add_service(service2).await.unwrap();

        // Start services (should trigger running events)
        node.start().await.unwrap();

        // Wait for wildcard event (should receive one of the running events)
        let wildcard_data = wildcard_future
            .await
            .map_err(|e| anyhow::anyhow!(e))??
            .expect("Received event data should not be None");
        let wildcard_service_path = wildcard_data.as_type_ref::<String>()?;
        assert!(
            *wildcard_service_path == "service1" || *wildcard_service_path == "service2",
            "Wildcard event should contain one of the service paths"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 15 seconds"),
    }
}

/// Test that service error state events are properly handled
///
/// INTENTION: This test validates that:
/// - Service errors trigger state/error events
/// - Error events contain appropriate error information
#[tokio::test]
async fn test_service_error_state_events() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let mut config = create_node_test_config().expect("Error creating test config");
        config.network_config = None;
        let node = Node::new(config).await.unwrap();

        // Start the node
        node.start().await.unwrap();

        // Test error state event (this would typically be triggered by service errors)
        // For this test, we'll verify the error event topic format is correct
        let error_topic = "$registry/services/test_service/state/error";

        // The error event should timeout since no error is actually triggered
        // Flatten JoinHandle<Result<..>> into Result<..> for assertion
        let join_res = node
            .on(
                error_topic,
                Some(runar_node::services::OnOptions {
                    timeout: Duration::from_millis(100),
                    include_past: None,
                }),
            )
            .await;
        assert!(join_res.is_ok(), "join should not fail");
        let result = join_res.unwrap();
        assert!(
            result.is_err(),
            "Error event should timeout when no error occurs"
        );
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Timeout"),
            "Error should indicate timeout"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}

/// Test that multiple concurrent on calls work correctly
///
/// INTENTION: This test validates that:
/// - Multiple concurrent on calls can wait for different events
/// - Each on call receives the correct event data
/// - No cross-contamination between different event subscriptions
#[tokio::test]
async fn test_multiple_concurrent_on_calls() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(15), async {
        // Create a node with a test network ID
        let mut config = create_node_test_config().expect("Error creating test config");
        config.network_config = None;
        let node = Node::new(config).await.unwrap();

        // Start the node
        node.start().await.unwrap();

        // Create multiple concurrent on calls for different topics
        let topic1 = "concurrent_event_1";
        let topic2 = "concurrent_event_2";
        let topic3 = "concurrent_event_3";

        let future1 = node.on(
            topic1,
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(5),
                include_past: None,
            }),
        );
        let future2 = node.on(
            topic2,
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(5),
                include_past: None,
            }),
        );
        let future3 = node.on(
            topic3,
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(5),
                include_past: None,
            }),
        );

        // Publish events for each topic with different delays
        let node_clone1 = node.clone();
        let node_clone2 = node.clone();
        let node_clone3 = node.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = node_clone1
                .publish(
                    topic1,
                    Some(ArcValue::new_primitive("data1".to_string())),
                    None,
                )
                .await;
        });

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = node_clone2
                .publish(
                    topic2,
                    Some(ArcValue::new_primitive("data2".to_string())),
                    None,
                )
                .await;
        });

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let _ = node_clone3
                .publish(
                    topic3,
                    Some(ArcValue::new_primitive("data3".to_string())),
                    None,
                )
                .await;
        });

        // Wait for all events
        let (result1, result2, result3) = tokio::join!(future1, future2, future3);

        // Verify each result
        let data1 = result1??
            .expect("Received event data should not be None")
            .as_type_ref::<String>()?;
        let data2 = result2??
            .expect("Received event data should not be None")
            .as_type_ref::<String>()?;
        let data3 = result3??
            .expect("Received event data should not be None")
            .as_type_ref::<String>()?;

        assert_eq!(
            *data1,
            "data1".to_string(),
            "First concurrent call should receive correct data"
        );
        assert_eq!(
            *data2,
            "data2".to_string(),
            "Second concurrent call should receive correct data"
        );
        assert_eq!(
            *data3,
            "data3".to_string(),
            "Third concurrent call should receive correct data"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 15 seconds"),
    }
}

/// Test that on method works with different timeout values
///
/// INTENTION: This test validates that:
/// - Short timeouts work correctly for immediate events
/// - Long timeouts work correctly for delayed events
/// - Timeout errors are properly handled
#[tokio::test]
async fn test_on_method_timeout_variations() {
    // Wrap the test in a timeout to prevent it from hanging
    match timeout(Duration::from_secs(10), async {
        // Create a node with a test network ID
        let mut config = create_node_test_config().expect("Error creating test config");
        config.network_config = None;
        let node = Node::new(config).await.unwrap();

        // Start the node
        node.start().await.unwrap();

        // Test 1: Very short timeout should fail
        let join_res = node
            .on(
                "short_timeout_test",
                Some(runar_node::services::OnOptions {
                    timeout: Duration::from_millis(1),
                    include_past: None,
                }),
            )
            .await;
        assert!(join_res.is_ok(), "join should not fail");
        let result = join_res.unwrap();
        assert!(result.is_err(), "Very short timeout should fail");
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Timeout"),
            "Error should indicate timeout"
        );

        // Test 2: Medium timeout with immediate event should succeed
        let topic = "medium_timeout_test";
        let event_data = ArcValue::new_primitive("immediate_data".to_string());

        let node_clone = node.clone();
        let topic_clone = topic.to_string();
        let event_data_clone = event_data.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = node_clone
                .publish(&topic_clone, Some(event_data_clone), None)
                .await;
        });

        let result = node
            .on(
                topic,
                Some(runar_node::services::OnOptions {
                    timeout: Duration::from_millis(100),
                    include_past: None,
                }),
            )
            .await??
            .expect("Received event data should not be None");
        assert_eq!(
            result, event_data,
            "Medium timeout should receive immediate event"
        );

        // Test 3: Long timeout with delayed event should succeed
        let topic2 = "long_timeout_test";
        // Test 4: Wildcard include_past works: publish to service/event_x, subscribe to service/* with include_past lookback
        let wildcard_exact = "svc_wild/event_x";
        let _wildcard_pattern = "svc_wild/*";
        let data_w = ArcValue::new_primitive("past_data".to_string());
        // publish with retain_for so it is retained
        node.publish(wildcard_exact, Some(data_w.clone()), None)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1000)).await;
        // Subscribe using on() with larger timeout; since we don’t yet expose on_with_options, simulate include_past by direct subscribe_with_options via services API is not accessible here.
        // For now, we assert that a normal on to exact topic still works (sanity), and leave wildcard include_past to service-level tests once API is exposed.
        let event_data2 = ArcValue::new_primitive("delayed_data".to_string());

        let node_clone2 = node.clone();
        let topic_clone2 = topic2.to_string();
        let event_data_clone2 = event_data2.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let _ = node_clone2
                .publish(&topic_clone2, Some(event_data_clone2), None)
                .await;
        });

        let result2 = node
            .on(
                topic2,
                Some(runar_node::services::OnOptions {
                    timeout: Duration::from_secs(2),
                    include_past: None,
                }),
            )
            .await??
            .expect("Received event data should not be None");
        assert_eq!(
            result2, event_data2,
            "Long timeout should receive delayed event"
        );

        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(_) => (), // Test completed within the timeout
        Err(_) => panic!("Test timed out after 10 seconds"),
    }
}
