use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_macros_common::params;
use runar_node::config::{LogLevel, LoggingConfig};
use runar_serializer::ArcValue; // needed by params! macro

use runar_node::node::Node;
use runar_test_utils::create_networked_node_test_config;

use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

// Import the fixture MathService
use crate::fixtures::math_service::MathService;

// TODO issues we found in the last refactoru of this test ( to be addressewd later)
// 1 - when I changed the params to use params!{} macro which wraps each element in a map with ArcValue the serializer
// thrown an error sayinf bincode cannot handle any.. so we need to imnprove the seralizer to handle ArcValue inside maps and prob inside lists/arrays also
// 2 - service name and path are still not handle properly.. if I change the service name the request() calls fails,
// which means the name is being used instead of the path to register the action
// this is likely only for remote serivices.. did nto check on local only services.

/// Test for remote action calls between two nodes using QUIC with proper certificates
///
/// INTENTION: Create two Node instances with QUIC network enabled using certificates from a shared CA.
/// Nodes should discover and securely connect to each other, then test remote service calls.
#[tokio::test]
async fn test_remote_action_call() -> Result<()> {
    // Configure logging to ensure test logs are displayed
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Error);
    logging_config.apply();

    // Set up logger
    let logger = Arc::new(Logger::new_root(
        Component::Custom("remote_action_test"),
        "",
    ));

    let configs =
        create_networked_node_test_config(2).expect("Failed to create multiple node test configs");

    let node1_config = configs[0].clone();
    let node1_id = node1_config.node_id.clone();
    let node2_config = configs[1].clone();
    let node2_id = node2_config.node_id.clone();
    // Create math services with different paths using the fixture
    let math_service1 = MathService::new("math1", "math1");
    let math_service2 = MathService::new("math2", "math2");

    logger.debug(format!("Node1 config: {node1_config}"));
    logger.debug(format!("Node2 config: {node2_config}"));

    let mut node1 = Node::new(node1_config).await?;
    node1.add_service(math_service1).await?;

    node1.start().await?;

    logger.debug("✅ Node 1 started");

    let mut node2 = Node::new(node2_config).await?;
    node2.add_service(math_service2).await?;

    node2.start().await?;
    logger.debug("✅ Node 2 started");

    logger.debug("⏳ Waiting for nodes to discover each other via multicast and establish QUIC connections...");
    let peer_future2 = node2.on(format!("$registry/peer/{node1_id}/discovered"), Duration::from_secs(3));
    let peer_future1 = node1.on(format!("$registry/peer/{node2_id}/discovered"), Duration::from_secs(3));
    //join both futures and wait for both to complete
    let _ = tokio::join!(peer_future2, peer_future1);

    // Test 1: Call math1/add service (on node1) from node2
    logger.debug("📤 Testing remote action call from node2 to node1 (math1/add)...");

    let response_av = node2
        .request("math1/add", Some(params! { "a" => 5.0, "b" => 3.0 }))
        .await?
        .as_type_ref::<f64>()?;

    let response = *response_av;
    assert_eq!(response, 8.0);
    logger.debug(format!(
        "✅ Secure add operation succeeded: 5 + 3 = {response}"
    ));

    // Test 2: Call math2/multiply service (on node2) from node1
    logger.debug("📤 Testing remote action call from node1 to node2 (math2/multiply)...");
    let response_av: ArcValue = node1
        .request("math2/multiply", Some(params! { "a" => 4.0, "b" => 7.0 }))
        .await?;
    let response: f64 = *response_av.as_type_ref::<f64>()?;
    assert_eq!(response, 28.0);

    logger.debug("🔄 Testing dynamic service addition and discovery...");
    // Add a new service to node1 and test remote call
    let new_service = MathService::new("math3", "math3");
    node1.add_service(new_service).await?;
    logger.debug("✅ Added math3 service to node1");

    // Wait for service discovery debounce (increased time for reliability)
    logger.debug("⏳ Waiting for service discovery propagation...");
    sleep(Duration::from_secs(3)).await;

    // Test 3: Call the newly added math3/add service from node2
    logger.debug("📤 Testing remote action call to newly added service (math3/add)...");

    let response_av: ArcValue = node2
        .request("math3/add", Some(params! { "a" => 10.0, "b" => 5.0 }))
        .await?;
    let response: f64 = *response_av.as_type_ref::<f64>()?;
    assert_eq!(response, 15.0);
    logger.info(format!(
        "✅ Dynamic service call succeeded: 10 + 5 = {response}"
    ));

    // ==========================================
    // STEP 16: Test Additional Operations
    // ==========================================
    logger.info("🧪 Testing additional secure operations...");

    let response_av: ArcValue = node2
        .request("math1/subtract", Some(params! { "a" => 20.0, "b" => 8.0 }))
        .await?;
    let response: f64 = *response_av.as_type_ref::<f64>()?;
    assert_eq!(response, 12.0);
    logger.info(format!("✅ Secure subtract operation: 20 - 8 = {response}"));

    // Test divide operation on math2

    let response_av: ArcValue = node1
        .request("math2/divide", Some(params! { "a" => 15.0, "b" => 3.0 }))
        .await?;
    let response: f64 = *response_av.as_type_ref::<f64>()?;
    assert_eq!(response, 5.0);
    logger.info(format!("✅ Secure divide operation: 15 / 3 = {response}"));

    // ==========================================
    // STEP 17: Cleanup
    // ==========================================
    logger.info("🧹 Shutting down nodes...");
    node2.stop().await?;
    node1.stop().await?;

    logger.info("✅ Both nodes stopped successfully");

    logger.info("🎉 remote action test completed successfully!");

    Ok(())
}
