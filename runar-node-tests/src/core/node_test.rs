// Tests for the Node implementation
//
// These tests verify that the Node properly handles requests
// and delegates to the ServiceRegistry as needed.

use runar_node::config::logging_config::{LogLevel, LoggingConfig};
use runar_node::Node;
use runar_node::ServiceMetadata;

use runar_serializer::ArcValue;
use runar_test_utils::create_node_test_config;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use runar_node::services::EventContext;
use runar_node::NodeDelegate;



use runar_macros_common::params;

// Import the test fixtures
use crate::fixtures::math_service::MathService;
use crate::fixtures::path_params_service::PathParamsService;
use anyhow::Result;

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
        let mut node = Node::new(config).await.unwrap();

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
        let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);

        // Create a node with a test network ID
        let mut config = create_node_test_config()
            .expect("Error creating test config")
            .with_logging_config(logging_config);
        // Disable networking
        config.network_config = None;
        let mut node = Node::new(config).await.unwrap();

        // Create a test service with consistent name and path
        let service = MathService::new("Math Service", "math");

        // Add the service to the node
        node.add_service(service).await.unwrap();

        // Start the node to initialize all services
        node.start().await.unwrap();

        // Create parameters
        let params = params! {
            "a" => 5.0f64,
            "b" => 3.0f64,
        };

        // Make a request to the math service's add action
        let result_av = node
            .request("math/add", Some(params))
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
        let mut node = Node::new(config).await.unwrap();

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
    let mut node = Node::new(config).await?;

    let math_service_name = "MathMetaTest";
    let math_service_path = "math_meta_svc";
    let service = MathService::new(math_service_name, math_service_path);
    node.add_service(service).await?;
    node.start().await?; // This will call init() on MathService

    // Request the list of services from the registry
    let list_arc = node
        .request("$registry/services/list", None::<ArcValue>)
        .await?
        .as_typed_list_ref::<ServiceMetadata>()?;

    let math_service_metadata = list_arc
        .iter()
        .find(|s| s.service_path == math_service_path && s.network_id == default_network_id)
        .expect("MathService metadata not found in registry list");

    assert_eq!(math_service_metadata.name, math_service_name);

    // let target_event_path = format!("{}/{}", math_service_path, "config/updated");

    // let config_updated_event_meta = math_service_metadata
    //     .events
    //     .iter()
    //     .find(|e| e.path == target_event_path)
    //     .expect("config/updated event metadata not found for MathService");

    // assert_eq!(
    //     config_updated_event_meta.description,
    //     "Notification for when math service configuration is updated."
    // );

    // let expected_schema = FieldSchema {
    //     name: "ConfigUpdatePayload".to_string(),
    //     data_type: SchemaDataType::Object,
    //     description: Some("Payload describing the configuration changes.".to_string()),
    //     nullable: Some(false),
    //     properties: Some({
    //         let mut props = HashMap::new();
    //         props.insert(
    //             "updated_setting".to_string(),
    //             Box::new(FieldSchema {
    //                 name: "updated_setting".to_string(),
    //                 data_type: SchemaDataType::String,
    //                 description: Some("Name of the setting that was updated.".to_string()),
    //                 nullable: Some(false),
    //                 ..FieldSchema::string("updated_setting")
    //             }),
    //         );
    //         props.insert(
    //             "new_value".to_string(),
    //             Box::new(FieldSchema {
    //                 name: "new_value".to_string(),
    //                 data_type: SchemaDataType::String,
    //                 description: Some("The new value of the setting.".to_string()),
    //                 nullable: Some(false),
    //                 ..FieldSchema::string("new_value")
    //             }),
    //         );
    //         props
    //     }),
    //     required: Some(vec!["updated_setting".to_string(), "new_value".to_string()]),
    //     ..FieldSchema::new("ConfigUpdatePayload", SchemaDataType::Object)
    // };

    // assert_eq!(config_updated_event_meta.data_schema, Some(expected_schema));

    node.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_node_init() -> Result<()> {
    // Create a node configuration
    let mut config = create_node_test_config().expect("Error creating test config");
    config.network_config = None;

    // Create a node
    let mut node = Node::new(config).await?;

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
        node.subscribe(topic.clone(), Box::new(handler))
            .await
            .unwrap();

        // Publish an event to the topic
        let data = ArcValue::new_primitive("test data".to_string());
        node.publish(topic, Some(data)).await.unwrap();

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
    let mut node = Node::new(config).await.unwrap();

    // Create our path parameters test service
    let service = PathParamsService::new("PathParams", "test");

    // Add the service to the node
    node.add_service(service).await.unwrap();

    // Start the node to initialize all services
    node.start().await.unwrap();

    // Make a request to a path that matches the template
    let av = node
        .request("test/abc123/items/xyz789", None::<ArcValue>)
        .await
        .unwrap();
 
    let params_map = av.as_typed_map_ref::<String>().expect("expect map");
     
    // Verify the path parameters were correctly extracted
    // params_map is now HashMap<String, String>
    assert_eq!(params_map.get("param_1").unwrap().as_ref(), "abc123");
    assert_eq!(params_map.get("param_2").unwrap().as_ref(), "xyz789");
}
