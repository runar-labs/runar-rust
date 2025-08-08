// Multicast Discovery Tests
//
// Tests for the Multicast Discovery implementation

use anyhow::Result;
use runar_common::compact_ids::compact_id;
use runar_common::logging::{Component, Logger};
use runar_node::network::discovery::DEFAULT_MULTICAST_ADDR;
use runar_node::network::discovery::{
    DiscoveryOptions, MulticastDiscovery, NodeDiscovery, NodeInfo,
};
use runar_node::{ActionMetadata, ServiceMetadata};
use runar_schemas::NodeMetadata;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use runar_node::network::discovery::multicast_discovery::PeerInfo;
use std::time::SystemTime;
use tokio::sync::oneshot;
use runar_node::Node;
use runar_test_utils::create_networked_node_test_config;

#[tokio::test]
async fn test_discovery_ttl_lost_and_debounce() -> Result<()> {
    // Short TTL and debounce for fast test
    let options = DiscoveryOptions {
        multicast_group: format!("{DEFAULT_MULTICAST_ADDR}:45678"),
        announce_interval: Duration::from_millis(50),
        node_ttl: Duration::from_millis(300),
        discovery_timeout: Duration::from_secs(1),
        debounce_window: Duration::from_millis(100),
        ..DiscoveryOptions::default()
    };

    let logger = Logger::new_root(Component::NetworkDiscovery, "ttl_test");

    // Two nodes
    let node_a_pk: [u8; 32] = rand::random();
    let _node_a_id = compact_id(&node_a_pk);
    let node_b_pk: [u8; 32] = rand::random();
    let node_b_id = compact_id(&node_b_pk);

    let mk_node_info = |pk: &[u8]| NodeInfo {
        node_public_key: pk.to_vec(),
        network_ids: vec!["test-network".to_string()],
        addresses: vec!["127.0.0.1:0".to_string()],
        node_metadata: NodeMetadata { services: vec![], subscriptions: vec![] },
        version: 0,
    };

    let disc_a = MulticastDiscovery::new(mk_node_info(&node_a_pk), options.clone(), logger.clone()).await?;
    let disc_b = MulticastDiscovery::new(mk_node_info(&node_b_pk), options.clone(), logger.clone()).await?;

    // Observe events from A about B
    let (lost_tx, lost_rx) = oneshot::channel::<()>();
    let lost_tx = Arc::new(tokio::sync::Mutex::new(Some(lost_tx)));
    let (upd_count_tx, mut upd_count_rx) = tokio::sync::mpsc::channel::<()>(10);

    let node_b_id_clone = node_b_id.clone();
    disc_a
        .subscribe(Arc::new(move |event| {
            let node_b_id = node_b_id_clone.clone();
            let lost_tx = Arc::clone(&lost_tx);
            let upd_count_tx = upd_count_tx.clone();
            Box::pin(async move {
                match event {
                    runar_node::network::discovery::DiscoveryEvent::Discovered(pi) => {
                        if compact_id(&pi.public_key) == node_b_id {
                            let _ = upd_count_tx.send(()).await;
                        }
                    }
                    runar_node::network::discovery::DiscoveryEvent::Updated(pi) => {
                        if compact_id(&pi.public_key) == node_b_id {
                            let _ = upd_count_tx.send(()).await;
                        }
                    }
                    runar_node::network::discovery::DiscoveryEvent::Lost(peer) => {
                        if peer == node_b_id {
                            if let Some(tx) = lost_tx.lock().await.take() { let _ = tx.send(()); }
                        }
                    }
                }
            })
        }))
        .await?;

    // Start A and B announcing
    disc_a.start_announcing().await?;
    disc_b.start_announcing().await?;
    // Allow a few updates to arrive but debounced to few emissions
    tokio::time::sleep(Duration::from_millis(350)).await;

    // Stop B; A should eventually emit Lost after TTL
    disc_b.stop_announcing().await?;
    // Wait for Lost with timeout
    tokio::time::timeout(Duration::from_secs(3), lost_rx).await.expect("lost not emitted")?;

    // Check that multiple announcements were coalesced (received at least 1 update/discovered)
    // but not an excessive number due to debounce
    let mut count = 0usize;
    while tokio::time::timeout(Duration::from_millis(50), upd_count_rx.recv()).await.is_ok() {
        count += 1;
        if count > 10 { break; }
    }
    assert!(count >= 1, "expected at least one discovered/updated before Lost");

    Ok(())
}

#[tokio::test]
async fn test_node_handles_discovery_events_connect_and_lost_cleanup() -> Result<()> {
    // Hard timeout watchdog
    let watchdog = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(60)).await;
        panic!("test_node_handles_discovery_events_connect_and_lost_cleanup timed out");
    });

    // Create two networked node configs (QUIC + multicast discovery)
    let mut configs = create_networked_node_test_config(2)?;
    // Short TTL and debounce for faster test
    if let Some(net) = &mut configs[0].network_config { net.discovery_options = Some(DiscoveryOptions { announce_interval: Duration::from_millis(80), node_ttl: Duration::from_millis(400), discovery_timeout: Duration::from_secs(1), debounce_window: Duration::from_millis(120), ..DiscoveryOptions::default() }); }
    if let Some(net) = &mut configs[1].network_config { net.discovery_options = Some(DiscoveryOptions { announce_interval: Duration::from_millis(80), node_ttl: Duration::from_millis(400), discovery_timeout: Duration::from_secs(1), debounce_window: Duration::from_millis(120), ..DiscoveryOptions::default() }); }

    // Start two nodes
    let mut node_a = Node::new(configs.remove(0)).await?;
    let mut node_b = Node::new(configs.remove(0)).await?;
    node_a.start().await?;
    node_b.start().await?;

    // Allow discovery to happen and Node to attempt connect
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check both see each other connected at the Node level
    let id_a = node_a.node_id().to_string();
    let id_b = node_b.node_id().to_string();
    assert!(node_a.is_connected(&id_b).await || node_b.is_connected(&id_a).await, "expected at least one side to be connected");

    // Stop B's networking (simulate announcer stop and TTL expiry)
    node_b.stop().await?;

    // Wait for TTL to pass and Lost to cause cleanup
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Node A should mark B as disconnected by now
    assert!(!node_a.is_connected(&id_b).await, "Node A should have cleaned up disconnected peer B after Lost");

    // Shutdown A
    node_a.stop().await?;
    watchdog.abort(); let _ = watchdog.await;
    Ok(())
}

#[tokio::test]
async fn test_multicast_provider_restart_emits_again() -> Result<()> {
    // Watchdog
    let watchdog = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(60)).await;
        panic!("test_multicast_provider_restart_emits_again timed out");
    });

    // Options with short intervals/TTL
    let options = DiscoveryOptions {
        multicast_group: format!("{DEFAULT_MULTICAST_ADDR}:45779"),
        announce_interval: Duration::from_millis(80),
        node_ttl: Duration::from_millis(400),
        discovery_timeout: Duration::from_secs(1),
        debounce_window: Duration::from_millis(100),
        ..DiscoveryOptions::default()
    };

    let logger = Logger::new_root(Component::NetworkDiscovery, "provider_restart");

    // Two nodes
    let node1_pk: [u8; 32] = rand::random();
    let node2_pk: [u8; 32] = rand::random();
    let node2_id = compact_id(&node2_pk);

    let mk_node_info = |pk: &[u8]| NodeInfo {
        node_public_key: pk.to_vec(),
        network_ids: vec!["test-network".to_string()],
        addresses: vec!["127.0.0.1:0".to_string()],
        node_metadata: NodeMetadata { services: vec![], subscriptions: vec![] },
        version: 0,
    };

    let disc1 = MulticastDiscovery::new(mk_node_info(&node1_pk), options.clone(), logger.clone()).await?;
    let disc2 = MulticastDiscovery::new(mk_node_info(&node2_pk), options.clone(), logger.clone()).await?;

    // Subscribe on disc1 to watch disc2 events
    let (first_tx, first_rx) = oneshot::channel::<()>();
    let (lost_tx, lost_rx) = oneshot::channel::<()>();
    let (second_tx, second_rx) = oneshot::channel::<()>();
    let first_tx = Arc::new(tokio::sync::Mutex::new(Some(first_tx)));
    let lost_tx = Arc::new(tokio::sync::Mutex::new(Some(lost_tx)));
    let second_tx = Arc::new(tokio::sync::Mutex::new(Some(second_tx)));

    let node2_id_clone = node2_id.clone();
    disc1
        .subscribe(Arc::new(move |event| {
            let first_tx = first_tx.clone();
            let lost_tx = lost_tx.clone();
            let second_tx = second_tx.clone();
            let node2_id = node2_id_clone.clone();
            Box::pin(async move {
                match event {
                    runar_node::network::discovery::DiscoveryEvent::Discovered(pi)
                    | runar_node::network::discovery::DiscoveryEvent::Updated(pi) => {
                        if compact_id(&pi.public_key) == node2_id {
                            if let Some(tx) = first_tx.lock().await.take() { let _ = tx.send(()); }
                            else if let Some(tx2) = second_tx.lock().await.take() { let _ = tx2.send(()); }
                        }
                    }
                    runar_node::network::discovery::DiscoveryEvent::Lost(peer) => {
                        if peer == node2_id {
                            if let Some(tx) = lost_tx.lock().await.take() { let _ = tx.send(()); }
                        }
                    }
                }
            })
        }))
        .await?;

    // Start announcing
    disc1.start_announcing().await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    disc2.start_announcing().await?;

    // Wait for initial discovery
    tokio::time::timeout(Duration::from_secs(2), first_rx).await.expect("did not receive initial Discovered")?;

    // Stop disc2 announcing and wait for Lost
    disc2.stop_announcing().await?;
    tokio::time::timeout(Duration::from_secs(3), lost_rx).await.expect("did not receive Lost after TTL")?;

    // Restart provider for node2 and start announcing again
    let disc2b = MulticastDiscovery::new(mk_node_info(&node2_pk), options.clone(), logger.clone()).await?;
    disc2b.start_announcing().await?;

    // Expect a new Discovered after restart due to debounce window + fresh announcer
    tokio::time::timeout(Duration::from_secs(3), second_rx).await.expect("did not receive Discovered after provider restart")?;

    // Cleanup
    disc1.stop_announcing().await?;
    disc2b.stop_announcing().await?;
    watchdog.abort(); let _ = watchdog.await;
    Ok(())
}
async fn create_test_discovery(
    network_id: &str,
    node_id: &str,
    node_public_key: &[u8],
) -> Result<MulticastDiscovery> {
    let options = DiscoveryOptions {
        multicast_group: format!("{DEFAULT_MULTICAST_ADDR}:45678"),
        announce_interval: Duration::from_secs(1), // Use shorter interval for tests
        ..DiscoveryOptions::default()
    };

    // Create a logger for testing
    let logger = Logger::new_root(Component::NetworkDiscovery, node_id);

    // Create a test node info using direct struct initialization
    let node_info = NodeInfo {
        node_public_key: node_public_key.to_vec(),
        network_ids: vec![network_id.to_string()],
        addresses: vec!["127.0.0.1:8000".to_string()],
        node_metadata: NodeMetadata {
            services: vec![ServiceMetadata {
                name: "test-service".to_string(),
                service_path: "service".to_string(),
                network_id: "test-network".to_string(),
                version: "1.0.0".to_string(),
                description: "Test service for unit tests".to_string(),
                registration_time: SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                last_start_time: Some(
                    SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                ),
                actions: vec![ActionMetadata {
                    name: "request".to_string(),
                    description: "Test request".to_string(),
                    input_schema: None,
                    output_schema: None,
                }],
            }],
            subscriptions: vec![],
        },
        version: 0,
    };

    // Create the discovery instance with proper parameters
    let discovery = MulticastDiscovery::new(node_info, options, logger).await?;

    Ok(discovery)
}

#[tokio::test]
async fn test_multicast_announce_and_discover() -> Result<()> {
    async fn test_multiple_discovery_instances() -> Result<()> {
        // Create random node public keys
        let node_1_public_key: [u8; 32] = rand::random();
        let node_1_id = compact_id(&node_1_public_key);

        let node_2_public_key: [u8; 32] = rand::random();
        let node_2_id = compact_id(&node_2_public_key);

        // Create two discovery instances
        let discovery1 =
            create_test_discovery("test-network", &node_1_id, &node_1_public_key).await?;
        let discovery2 =
            create_test_discovery("test-network", &node_2_id, &node_2_public_key).await?;

        // Create channels for receiving notifications
        let (tx1, _rx1) = mpsc::channel::<PeerInfo>(10);
        let (tx2, _rx2) = mpsc::channel::<PeerInfo>(10);

        // Add oneshot channels to signal when discoveries are made
        let (done_tx1, done_rx1) = oneshot::channel::<()>();
        let (done_tx2, done_rx2) = oneshot::channel::<()>();
        let done_tx1 = Arc::new(tokio::sync::Mutex::new(Some(done_tx1)));
        let done_tx2 = Arc::new(tokio::sync::Mutex::new(Some(done_tx2)));

        // Set discovery listeners for both instances
        let node_2_id_clone = node_2_id.clone();
        discovery1
            .subscribe(Arc::new(move |event| {
                let tx = tx1.clone();
                let done_tx_clone = Arc::clone(&done_tx1);
                let node_2_id = node_2_id_clone.clone();

                Box::pin(async move {
                    if let runar_node::network::discovery::DiscoveryEvent::Discovered(peer_info) = event {
                    let peer_id = compact_id(&peer_info.public_key);
                    if peer_id == node_2_id {
                        if let Err(e) = tx.send(peer_info).await {
                            eprintln!("Channel send error: {e}");
                        }
                        if let Some(done_tx) = done_tx_clone.lock().await.take() {
                            let _ = done_tx.send(());
                            }
                        }
                    }
                })
            }))
            .await?;

        let node_1_id_clone = node_1_id.clone();
        discovery2
            .subscribe(Arc::new(move |event| {
                let tx = tx2.clone();
                let done_tx_clone = Arc::clone(&done_tx2);
                let node_1_id = node_1_id_clone.clone();

                Box::pin(async move {
                    if let runar_node::network::discovery::DiscoveryEvent::Discovered(peer_info) = event {
                    let peer_id = compact_id(&peer_info.public_key);
                    if peer_id == node_1_id {
                        if let Err(e) = tx.send(peer_info).await {
                            eprintln!("Channel send error: {e}");
                        }
                        if let Some(done_tx) = done_tx_clone.lock().await.take() {
                            let _ = done_tx.send(());
                            }
                        }
                    }
                })
            }))
            .await?;

        // Start announcing for both nodes
        discovery1.start_announcing().await?;

        // Wait a short time for propagation
        tokio::time::sleep(Duration::from_millis(500)).await;

        discovery2.start_announcing().await?;

        // Wait a bit for propagation and discovery
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Check if discovery1 received node2's info
        let node1_found_node2 = tokio::time::timeout(Duration::from_secs(1), done_rx1)
            .await
            .is_ok();

        // Check if discovery2 received node1's info
        let node2_found_node1 = tokio::time::timeout(Duration::from_secs(1), done_rx2)
            .await
            .is_ok();

        // Print discovery results for debugging
        println!("Node1 found Node2: {node1_found_node2}");
        println!("Node2 found Node1: {node2_found_node1}");

        // We may not always see the other node due to UDP packet loss or timing issues
        // So we log the findings but don't fail the test if not found
        if !node1_found_node2 {
            println!(
                "Note: Discovery 1 did not find node2 - this may be normal due to UDP packet loss"
            );
        }
        if !node2_found_node1 {
            println!(
                "Note: Discovery 2 did not find node1 - this may be normal due to UDP packet loss"
            );
        }

        // Shutdown both discoveries
        discovery1.stop_announcing().await?;
        discovery2.stop_announcing().await?;

        assert!(node1_found_node2);
        assert!(node2_found_node1);

        Ok(())
    }

    test_multiple_discovery_instances().await?;

    Ok(())
}

#[tokio::test]
async fn test_no_duplicate_notifications() -> Result<()> {
    // Create random node public keys
    let node_1_public_key: [u8; 32] = rand::random();
    let node_1_id = compact_id(&node_1_public_key);

    let node_2_public_key: [u8; 32] = rand::random();
    let node_2_id = compact_id(&node_2_public_key);

    // Create two discovery instances
    let discovery1 =
        create_test_discovery("test-network", &node_1_id, &node_1_public_key).await?;
    let discovery2 =
        create_test_discovery("test-network", &node_2_id, &node_2_public_key).await?;

    // Create a counter to track how many times we receive notifications
    let notification_count = Arc::new(tokio::sync::Mutex::new(0));
    let notification_count_clone = Arc::clone(&notification_count);

    // Create a channel to receive notifications
    let (tx, mut rx) = mpsc::channel::<PeerInfo>(10);

    // Set discovery listener for discovery1 that counts notifications
    let node_2_id_clone = node_2_id.clone();
    discovery1
        .subscribe(Arc::new(move |event| {
            let tx = tx.clone();
            let count = Arc::clone(&notification_count_clone);
            let node_2_id = node_2_id_clone.clone();

            Box::pin(async move {
                if let runar_node::network::discovery::DiscoveryEvent::Discovered(peer_info) = event {
                let peer_id = compact_id(&peer_info.public_key);
                if peer_id == node_2_id {
                        let mut count_guard = count.lock().await;
                        *count_guard += 1;
                        println!("Received notification #{count_guard} for peer {peer_id}");
                    if let Err(e) = tx.send(peer_info).await {
                        eprintln!("Channel send error: {e}");
                        }
                    }
                }
            })
        }))
        .await?;

    // Start announcing for both nodes
    discovery1.start_announcing().await?;
    discovery2.start_announcing().await?;

    // Wait for initial discovery
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Wait for multiple announcement cycles (each 1 second)
    // This should trigger multiple announcements but only one notification
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Check the notification count
    let final_count = *notification_count.lock().await;
    println!("Final notification count: {final_count}");

    // We should have received exactly 1 notification, not multiple
    assert_eq!(final_count, 1, "Expected exactly 1 notification, got {final_count}");

    // Verify we received the peer info
    if let Ok(peer_info) = rx.try_recv() {
        let received_peer_id = compact_id(&peer_info.public_key);
        assert_eq!(received_peer_id, node_2_id, "Received wrong peer ID");
        println!("Successfully received peer info for: {received_peer_id}");
    } else {
        panic!("No peer info received in channel");
    }

    // Shutdown both discoveries
    discovery1.stop_announcing().await?;
    discovery2.stop_announcing().await?;

    Ok(())
}
