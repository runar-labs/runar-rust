use anyhow::{anyhow, Result};
use runar_common::logging::{Component, Logger};
use runar_macros_common::params;
use runar_node::config::{LogLevel, LoggingConfig};
use runar_serializer::ArcValue; // needed by params! macro

use runar_node::node::Node;
use runar_test_utils::create_networked_node_test_config;

use serial_test::serial;
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
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
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

    // Start the subscription in the background (hold join handle)
    let node1_arc = Arc::new(node1.clone());
    let node1_arc_clone = node1_arc.clone();
    let on_added_future_2 = node1_arc_clone.on(
        "math1/math/added",
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(10),
            include_past: None,
        }),
    );

    node1.start().await?;

    logger.debug("✅ Node 1 started");

    let mut node2 = Node::new(node2_config).await?;
    node2.add_service(math_service2).await?;

    node2.start().await?;
    logger.debug("✅ Node 2 started");

    logger.debug("⏳ Waiting for nodes to discover each other via multicast and establish QUIC connections...");
    let peer_future2 = node2.on(
        format!("$registry/peer/{node1_id}/discovered"),
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(3),
            include_past: None,
        }),
    );
    let peer_future1 = node1.on(
        format!("$registry/peer/{node2_id}/discovered"),
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(3),
            include_past: None,
        }),
    );
    //join both futures and wait for both to complete
    let _ = tokio::join!(peer_future2, peer_future1);

    // Create subscription for math1/math/added BEFORE calling the math operation
    logger.debug("📥 Setting up subscription for math1/math/added event on node1...");

    // Start the subscription in the background (hold join handle)
    let node1_arc_clone = node1_arc.clone();
    let on_added_future = node1_arc_clone.on(
        "math1/math/added",
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(10),
            include_past: None,
        }),
    );

    // Give sufficient time for subscription to be fully registered in the unified store
    logger.debug("⏳ Waiting for subscription to be fully registered...");
    tokio::time::sleep(Duration::from_millis(500)).await;
    logger.debug("✅ Subscription registration delay complete");

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

    let on_added_result = on_added_future.await??;

    match on_added_result {
        Some(event_data) => {
            let event_value: f64 = *event_data.as_type_ref()?;
            logger.debug(format!(
                "✅ Received math/added event with value: {event_value}"
            ));

            // Verify the event contains the expected result
            assert_eq!(event_value, 8.0, "Expected math/added event with value 8.0");
        }
        None => {
            panic!("❌ Expected some event data, but got None");
        }
    }

    let on_added_future_2_result = on_added_future_2.await??;
    match on_added_future_2_result {
        Some(event_data) => {
            let event_value: f64 = *event_data.as_type_ref()?;
            logger.debug(format!(
                "✅ Received math/added event with value: {event_value}"
            ));
            assert_eq!(event_value, 8.0, "Expected math/added event with value 8.0");
        }
        None => {
            panic!("❌ Expected some event data, but got None");
        }
    }

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

    let node2_arc = Arc::new(node2.clone());
    let on_added_math3_future = node2_arc.on(
        "math3/math/added",
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(10),
            include_past: None,
        }),
    );

    // Wait for service discovery debounce (increased time for reliability)
    logger.debug("⏳ Waiting for service discovery propagation...");
    sleep(Duration::from_secs(5)).await;

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

    //check event on_added_math3_future
    let on_added_math3_result = on_added_math3_future.await??;
    match on_added_math3_result {
        Some(event_data) => {
            let event_value: f64 = *event_data.as_type_ref()?;
            logger.debug(format!(
                "✅ Received math/added event with value: {event_value}"
            ));
            assert_eq!(
                event_value, 15.0,
                "Expected math/added event with value 15.0"
            );
        }
        None => {
            panic!("❌ Expected some event data, but got None");
        }
    }

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

/// Test for node stop/restart/reconnection scenario
///
/// INTENTION: Test that a node can properly stop, restart, and reconnect to the network
/// and resume remote service calls. This isolates the reconnection logic from replication.
#[tokio::test]
#[serial]
async fn test_node_stop_restart_reconnection() -> Result<()> {
    // Hard timeout to prevent hangs in CI
    tokio::time::timeout(Duration::from_secs(40), async {
        // Configure logging to ensure test logs are displayed
        let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
        logging_config.apply();

        // Set up logger
        let logger = Arc::new(Logger::new_root(Component::Custom("stop_restart_test"), ""));

        let configs = create_networked_node_test_config(2)
            .expect("Failed to create multiple node test configs");

        let node1_config = configs[0].clone();
        let node1_id = node1_config.node_id.clone();
        let node2_config = configs[1].clone();
        let node2_id = node2_config.node_id.clone();

        // Create math services with different paths using the fixture
        let math_service1 = MathService::new("math1", "math1");
        let math_service2 = MathService::new("math2", "math2");

        logger.debug(format!("Node1 config: {node1_config}"));
        logger.debug(format!("Node2 config: {node2_config}"));

        let mut node1 = Node::new(node1_config.clone()).await?;
        node1.add_service(math_service1.clone()).await?;
        node1.start().await?;
        logger.debug("✅ Node 1 started");

        let mut node2 = Node::new(node2_config).await?;
        node2.add_service(math_service2).await?;
        node2.start().await?;
        logger.debug("✅ Node 2 started");

        // Wait for nodes to discover each other
        logger.debug("⏳ Waiting for nodes to discover each other...");
        let peer_future2 = node2.on(
            format!("$registry/peer/{node1_id}/discovered"),
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(3),
                include_past: None,
            }),
        );
        let peer_future1 = node1.on(
            format!("$registry/peer/{node2_id}/discovered"),
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(3),
                include_past: None,
            }),
        );
        let _ = tokio::join!(peer_future2, peer_future1);
        logger.debug("✅ Nodes discovered each other");

        // ==========================================
        // STEP 2: Test initial remote call from node2 to node1
        // ==========================================
        logger.info("🧪 Testing initial remote call from node2 to node1...");

        // Wait for services to start before making remote calls
        logger.info("⏳ Waiting for services to start...");
        node1.wait_for_services_to_start().await?;
        node2.wait_for_services_to_start().await?;
        logger.debug("✅ Services started");

        let response_av = node2
            .request("math1/add", Some(params! { "a" => 10.0, "b" => 5.0 }))
            .await?
            .as_type_ref::<f64>()?;

        let response = *response_av;
        assert_eq!(response, 15.0);
        logger.debug(format!(
            "✅ Initial remote call succeeded: 10 + 5 = {response}"
        ));

        // ==========================================
        // STEP 3: Stop Node 1
        // ==========================================
        logger.info("🛑 Stopping Node 1...");
        node1.stop().await?;
        logger.debug("✅ Node 1 stopped");

        // Wait for the stop to complete and cleanup to finish
        // In a real scenario, a node would stay down for a meaningful period
        sleep(Duration::from_secs(1)).await;

        // ==========================================
        // STEP 4: Verify Node 1 is unreachable
        // ==========================================
        logger.info("🧪 Verifying Node 1 is unreachable...");

        let remote_call_result = node2
            .request("math1/add", Some(params! { "a" => 1.0, "b" => 1.0 }))
            .await;

        assert!(
            remote_call_result.is_err(),
            "Node 1 should be unreachable after stop"
        );
        logger.debug("✅ Node 1 correctly unreachable after stop");

        // ==========================================
        // STEP 5: Restart Node 1 (new instance, same config)
        // ==========================================
        logger.info("🔄 Restarting Node 1 (new instance with same config)...");

        // Drop old instance completely to simulate real process restart
        drop(node1);

        // Allow OS to fully release previous UDP socket before rebinding same port
        //sleep(Duration::from_millis(1000)).await;

        // Create a fresh node using the same config (preserves node_id, keys, etc.)
        let mut node1 = Node::new(node1_config.clone()).await?;
        node1.add_service(math_service1.clone()).await?;
        node1.start().await?;
        // Ensure background service start completion before remote requests
        node1.wait_for_services_to_start().await?;
        logger.debug("✅ Node 1 restarted (new instance)");

        // Wait for nodes to discover each other again - same as initial setup
        logger.debug("⏳ Waiting for nodes to rediscover each other...");
        let on_node1_found = node2.on(
            format!("$registry/peer/{node1_id}/discovered"),
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(10),
                include_past: None,
            }),
        );
        let on_node2_found = node1.on(
            format!("$registry/peer/{node2_id}/discovered"),
            Some(runar_node::services::OnOptions {
                timeout: Duration::from_secs(10),
                include_past: None,
            }),
        );
        let _ = tokio::join!(on_node1_found, on_node2_found);
        logger.debug("✅ Nodes rediscovered each other");

        // ==========================================
        // STEP 7: Test remote call after restart
        // ==========================================
        logger.info("🧪 Testing remote call after Node 1 restart...");

        let response_av = node2
            .request("math1/add", Some(params! { "a" => 20.0, "b" => 10.0 }))
            .await?
            .as_type_ref::<f64>()?;

        let response = *response_av;
        assert_eq!(response, 30.0);
        logger.debug(format!(
            "✅ Remote call after restart succeeded: 20 + 10 = {response}"
        ));

        // ==========================================
        // STEP 8: Test bidirectional communication
        // ==========================================
        logger.info("🧪 Testing bidirectional communication after restart...");

        // Test call from restarted Node 1 to Node 2
        let response_av = node1
            .request("math2/multiply", Some(params! { "a" => 6.0, "b" => 7.0 }))
            .await?
            .as_type_ref::<f64>()?;

        let response = *response_av;
        assert_eq!(response, 42.0);
        logger.debug(format!(
            "✅ Bidirectional call succeeded: 6 * 7 = {response}"
        ));

        // ==========================================
        // STEP 9: Cleanup
        // ==========================================
        logger.info("🧹 Shutting down nodes...");
        node2.stop().await?;
        node1.stop().await?;

        logger.info("✅ Both nodes stopped successfully");
        logger.info("🎉 Node stop/restart/reconnection test completed successfully!");

        Ok(())
    })
    .await
    .map_err(|_| anyhow!("test_node_stop_restart_reconnection timed out"))?
}
