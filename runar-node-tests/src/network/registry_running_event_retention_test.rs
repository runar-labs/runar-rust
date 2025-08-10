use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_node::config::{LogLevel, LoggingConfig};
use runar_node::node::Node;
use runar_test_utils::create_networked_node_test_config;
use std::sync::Arc;
use std::time::Duration;

use crate::fixtures::math_service::MathService;

#[tokio::test]
async fn test_remote_service_running_event_include_past() -> Result<()> {
    // Configure logging to ensure visibility if it fails
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);
    logging_config.apply();

    // Unique multicast group per run to avoid test cross-talk
    let mut configs = create_networked_node_test_config(2)?;
    let unique_port: u16 = 48000 + (rand::random::<u16>() % 1000);
    let unique_group = format!("239.255.42.98:{unique_port}");
    if let Some(net) = &mut configs[0].network_config {
        net.discovery_options = Some(runar_node::network::discovery::DiscoveryOptions {
            multicast_group: unique_group.clone(),
            ..Default::default()
        });
    }
    if let Some(net) = &mut configs[1].network_config {
        net.discovery_options = Some(runar_node::network::discovery::DiscoveryOptions {
            multicast_group: unique_group,
            ..Default::default()
        });
    }

    let node1_config = configs[0].clone();
    let node2_config = configs[1].clone();

    let logger = Arc::new(Logger::new_root(Component::Custom("registry_running_retention"), ""));

    // Node 1 with a service
    let mut node1 = Node::new(node1_config.clone()).await?;
    node1.add_service(MathService::new("math1", "math1")).await?;
    node1.start().await?;
    node1.wait_for_services_to_start().await?;

    // Node 2 without that service
    let mut node2 = Node::new(node2_config.clone()).await?;
    node2.start().await?;

    // Wait for nodes to discover each other
    let on1 = node2.on(
        format!("$registry/peer/{}/discovered", node1_config.node_id),
        Some(runar_node::services::OnOptions { timeout: Duration::from_secs(10), include_past: None }),
    );
    let on2 = node1.on(
        format!("$registry/peer/{}/discovered", node2_config.node_id),
        Some(runar_node::services::OnOptions { timeout: Duration::from_secs(10), include_past: None }),
    );
    let _ = tokio::join!(on1, on2);

    // Give a short moment for Node 2 to register the remote service and publish retained running
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Now subscribe with include_past on Node 2 for the remote service running event
    let running_future = node2.on(
        "$registry/services/math1/state/running",
        Some(runar_node::services::OnOptions {
            timeout: Duration::from_secs(3),
            include_past: Some(Duration::from_secs(30)),
        }),
    );
    let join_res = running_future.await;
    assert!(join_res.is_ok(), "join should not fail: {join_res:?}");
    let res = join_res.unwrap();
    assert!(res.is_ok(), "on() should not fail: {res:?}");
    match res.unwrap() {
        Some(data) => {
            let s_ref = data.as_type_ref::<String>()?;
            assert!(s_ref.ends_with(":math1"), "Expected payload to end with ':math1', got: {s_ref}");
        }
        None => panic!("Expected retained running event"),
    }

    Ok(())
}


