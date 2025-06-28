use anyhow::Result;
use runar_common::hmap;
use runar_common::logging::Logger;
use runar_common::types::ArcValue;
use runar_common::Component;
use runar_node::config::{LogLevel, LoggingConfig};
use runar_node::network::network_config::NetworkConfig;
use runar_node::network::transport::QuicTransportOptions;
use runar_node::node::{Node, NodeConfig};
use runar_keys::{MobileKeyManager, NodeKeyManager};
use rustls;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;

// Import the fixture MathService
use crate::fixtures::math_service::MathService;

/// Test for remote action calls between two nodes
///
/// INTENTION: Create two Node instances with network enabled, they should discover and connect to each other
/// each node should have one math service with different path, so we can call it from each node and test
/// the remote calls
#[tokio::test]
async fn test_remote_action_call() -> Result<()> {
    // Install default crypto provider for rustls 0.23.x if not already installed
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install default crypto provider");
    }

    // Configure logging to ensure test logs are displayed
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);
    logging_config.apply();

    // Set up logger
    let logger = Logger::new_root(Component::Network, "remote_action_test");
    logger.info("Starting remote action call test with proper QUIC certificates");

    // ==============================================
    // SHARED CERTIFICATE AUTHORITY SETUP
    // ==============================================
    logger.info("🔧 Setting up shared User CA for both nodes...");
    
    // Create ONE mobile key manager that will act as the Certificate Authority for both nodes
    let mut mobile_ca = MobileKeyManager::new();
    mobile_ca.generate_seed();

    // Generate user root key and CA
    let _user_root_public_key = mobile_ca
        .generate_user_root_key()
        .expect("Failed to generate user root key");

    let user_ca_public_key = mobile_ca
        .generate_user_ca_key()
        .expect("Failed to generate user CA key");
    
    logger.info(format!("✅ User CA created with public key: {}", hex::encode(user_ca_public_key.bytes())));

    // ==============================================
    // NODE 1 CERTIFICATE SETUP
    // ==============================================
    logger.info("🔧 Setting up Node 1 certificates...");
    
    let mut node1_key_manager = NodeKeyManager::new();
    let setup_token1 = node1_key_manager
        .generate_setup_token()
        .expect("Failed to generate setup token for node1");

    // Mobile CA signs Node 1's certificate
    let cert1 = mobile_ca
        .process_setup_token(&setup_token1)
        .expect("Failed to process setup token for node1");

    let node1_public_key = hex::encode(&setup_token1.node_public_key);
    let encrypted_node1_msg = mobile_ca
        .encrypt_message_for_node(&cert1, &node1_public_key)
        .expect("Failed to encrypt message for node1");

    // Node 1 processes its certificate from the CA
    node1_key_manager
        .process_mobile_message(&encrypted_node1_msg)
        .expect("Failed to process encrypted certificate for node1");

    logger.info(format!("✅ Node 1 certificate issued: {}", cert1.subject));

    // ==============================================
    // NODE 2 CERTIFICATE SETUP  
    // ==============================================
    logger.info("🔧 Setting up Node 2 certificates...");
    
    let mut node2_key_manager = NodeKeyManager::new();
    let setup_token2 = node2_key_manager
        .generate_setup_token()
        .expect("Failed to generate setup token for node2");

    // SAME Mobile CA signs Node 2's certificate
    let cert2 = mobile_ca
        .process_setup_token(&setup_token2)
        .expect("Failed to process setup token for node2");

    let node2_public_key = hex::encode(&setup_token2.node_public_key);
    let encrypted_node2_msg = mobile_ca
        .encrypt_message_for_node(&cert2, &node2_public_key)
        .expect("Failed to encrypt message for node2");

    // Node 2 processes its certificate from the SAME CA
    node2_key_manager
        .process_mobile_message(&encrypted_node2_msg)
        .expect("Failed to process encrypted certificate for node2");

    logger.info(format!("✅ Node 2 certificate issued: {}", cert2.subject));

    // ==============================================
    // QUIC CERTIFICATE EXTRACTION
    // ==============================================
    logger.info("🔧 Extracting QUIC certificates for both nodes...");
    
    // Get QUIC certificates for Node 1
    let (node1_certs, node1_private_key, node1_verifier) = node1_key_manager
        .get_quic_certs()
        .expect("Failed to get QUIC certificates for node1");
    
    // Get QUIC certificates for Node 2  
    let (node2_certs, node2_private_key, node2_verifier) = node2_key_manager
        .get_quic_certs()
        .expect("Failed to get QUIC certificates for node2");

    logger.info("✅ QUIC certificates extracted for both nodes");
    logger.info(format!("   - Node 1: {} certificate(s)", node1_certs.len()));
    logger.info(format!("   - Node 2: {} certificate(s)", node2_certs.len()));

    // ==============================================
    // NODE CONFIGURATION WITH CERTIFICATES
    // ==============================================
    logger.info("🔧 Configuring nodes with QUIC certificates...");

    // Create math services with different paths using the fixture
    let math_service1 = MathService::new("math1", "math1");
    let math_service2 = MathService::new("math2", "math2");

    // Node 1 QUIC options with its certificates
    let options_a = QuicTransportOptions::new()
        .with_certificates(node1_certs)
        .with_private_key(node1_private_key)
        .with_certificate_verifier(node1_verifier)
        .with_keep_alive_interval(Duration::from_secs(1))
        .with_connection_idle_timeout(Duration::from_secs(60))
        .with_stream_idle_timeout(Duration::from_secs(30))
        .with_quinn_log_level(log::LevelFilter::Warn);

    // Serialize Node 1's key state for NodeConfig
    let node1_key_state = node1_key_manager.export_state();
    let node1_key_state_bytes = bincode::serialize(&node1_key_state)
        .expect("Failed to serialize node1 state");

    // Create node configurations with network enabled and certificates
    let node1_config = NodeConfig::new_test_config("node1", "test")
        .with_network_config(NetworkConfig::with_quic(options_a).with_multicast_discovery())
        .with_key_manager_state(node1_key_state_bytes);

    logger.info(format!("Node1 config: {}", node1_config));

    let mut node1 = Node::new(node1_config).await?;
    node1.add_service(math_service1).await?;
    node1.start().await?;

    logger.info("✅ Node 1 started with QUIC certificates");

    // Node 2 QUIC options with its certificates  
    let options_b = QuicTransportOptions::new()
        .with_certificates(node2_certs)
        .with_private_key(node2_private_key)
        .with_certificate_verifier(node2_verifier)
        .with_verify_certificates(true)
        .with_keep_alive_interval(Duration::from_secs(1))
        .with_connection_idle_timeout(Duration::from_secs(60))
        .with_stream_idle_timeout(Duration::from_secs(30))
        .with_quinn_log_level(log::LevelFilter::Warn);

    // Serialize Node 2's key state for NodeConfig
    let node2_key_state = node2_key_manager.export_state();
    let node2_key_state_bytes = bincode::serialize(&node2_key_state)
        .expect("Failed to serialize node2 state");

    let node2_config = NodeConfig::new_test_config("node2", "test")
        .with_network_config(NetworkConfig::with_quic(options_b).with_multicast_discovery())
        .with_key_manager_state(node2_key_state_bytes);

    logger.info(format!("Node2 config: {}", node2_config));

    let mut node2 = Node::new(node2_config).await?;
    node2.add_service(math_service2).await?;

    {
        let mut serializer = node2.serializer.write().await;
        serializer.register::<HashMap<String, f64>>()?;
        // The lock is automatically released here when `serializer` goes out of scope
    }

    {
        let mut serializer = node1.serializer.write().await;
        serializer.register::<HashMap<String, f64>>()?;
        // The lock is automatically released here when `serializer` goes out of scope
    }

    node2.start().await?;
    logger.info("✅ Node 2 started with QUIC certificates");

    // ==============================================
    // CERTIFICATE TRUST VALIDATION
    // ==============================================
    logger.info("🔍 Certificate trust validation:");
    logger.info(format!("   - Both nodes have certificates signed by CA: {}", hex::encode(user_ca_public_key.bytes())));
    logger.info(format!("   - Node 1 certificate subject: {}", cert1.subject));
    logger.info(format!("   - Node 2 certificate subject: {}", cert2.subject));
    logger.info("   - Both nodes should trust each other's certificates via shared CA");

    // Wait for discovery and connection to happen (simple sleep)
    logger.info("⏳ Waiting for nodes to discover each other via multicast...");
    sleep(Duration::from_secs(5)).await; // Increased time for certificate validation

    // ==============================================
    // REMOTE ACTION TESTING
    // ==============================================
    logger.info("🧪 Testing QUIC-secured remote action calls...");
    
    // Test calling math service1 (on node1) from node2
    logger.info("Testing remote action call from node2 to node1...");
    let add_params = ArcValue::new_map(hmap! {
        "a" => 5.0,
        "b" => 3.0
    });

    // Use the proper network path format - with network ID for remote actions
    let response: f64 = node2.request("math1/add", Some(add_params)).await?;
    // response is now directly f64 due to generic deserialization in request()
    assert_eq!(response, 8.0);
    logger.info(format!("✅ Secure add operation succeeded: 5 + 3 = {}", response));

    // Test calling math service2 (on node2) from node1
    logger.info("Testing remote action call from node1 to node2...");
    let multiply_params = ArcValue::new_map(hmap! {
        "a" => 4.0,
        "b" => 7.0
    });

    let response: f64 = node1
        .request("math2/multiply", Some(multiply_params))
        .await?;
    // response is now directly f64 due to generic deserialization in request()
    assert_eq!(response, 28.0);
    logger.info(format!(
        "✅ Secure multiply operation succeeded: 4 * 7 = {}",
        response
    ));

    // add a new service to node1 and test remote call
    let new_service = MathService::new("math3", "math3");
    node1.add_service(new_service).await?;

    //wait over 3 seconds (debounce is 2 seconds)
    sleep(Duration::from_secs(3)).await;

    // Test calling math service3 (on node1) from node2
    logger.info("Testing remote action call from node2 to node1 (new service)...");
    let add_params = ArcValue::new_map(hmap! {
        "a" => 5.0,
        "b" => 3.0
    });

    let response: f64 = node2.request("math3/add", Some(add_params)).await?;
    // response is now directly f64 due to generic deserialization in request()
    assert_eq!(response, 8.0);
    logger.info(format!("✅ Secure add operation succeeded: 5 + 3 = {}", response));

    // Shut down nodes
    node1.stop().await?;
    node2.stop().await?;

    logger.info("🎉 QUIC-secured remote action test completed successfully!");
    logger.info("📋 Validation summary:");
    logger.info("   ✅ Shared User CA certificate authority");
    logger.info("   ✅ Individual node certificates signed by shared CA");
    logger.info("   ✅ QUIC transport with proper certificate validation");
    logger.info("   ✅ Secure remote action calls between nodes");
    logger.info("   ✅ Dynamic service discovery over secure connections");
    
    Ok(())
}
