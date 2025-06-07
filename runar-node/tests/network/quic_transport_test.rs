use rcgen;
use runar_common::logging::{Component, Logger};
use rustls;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use tokio::sync::mpsc;

use runar_node::network::discovery::multicast_discovery::PeerInfo;
use runar_node::network::discovery::NodeInfo;
use runar_node::network::transport::{
    quic_transport::{QuicTransport, QuicTransportOptions},
    NetworkError, NetworkMessage, NetworkMessagePayloadItem, NetworkTransport, PeerId,
};

/// Custom certificate verifier that skips verification for testing
///
/// INTENTION: Allow connections without certificate verification in test environments
struct SkipServerVerification {}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        // Skip verification and return success
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

/// Helper function to generate self-signed certificates for testing
///
/// INTENTION: Provide a consistent way to generate test certificates across test cases
/// using explicit rustls namespaces to avoid type conflicts
pub fn generate_test_certificates() -> (Vec<rustls::Certificate>, rustls::PrivateKey) {
    // Create certificate parameters with default values
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.not_before = rcgen::date_time_ymd(2023, 1, 1);
    params.not_after = rcgen::date_time_ymd(2026, 1, 1);

    // Generate the certificate with default parameters
    let cert = rcgen::Certificate::from_params(params).expect("Failed to generate certificate");

    // Get the DER encoded certificate and private key
    let cert_der = cert
        .serialize_der()
        .expect("Failed to serialize certificate");
    let key_der = cert.serialize_private_key_der();

    // Convert to rustls types with explicit namespace qualification
    // This avoids conflicts between rustls and Quinn's types
    let rustls_cert = rustls::Certificate(cert_der);
    let rustls_key = rustls::PrivateKey(key_der);

    (vec![rustls_cert], rustls_key)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_quic_transport_connection_end_to_end() {
    // Create two transport instances for testing
    let logger_a = Arc::new(Logger::new_root(Component::Network, "transporter-a"));
    let logger_b = Arc::new(Logger::new_root(Component::Network, "transporter-b"));

    // Create node info for both nodes with proper PeerId type
    let node_a_id_str = "node-a".to_string();
    let node_b_id_str = "node-b".to_string();
    let node_a_id = PeerId::new(node_a_id_str.clone());
    let node_b_id = PeerId::new(node_b_id_str.clone());

    // Use different ports for each node to avoid conflicts
    // Use higher port numbers to avoid potential conflicts
    let node_a_addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let node_b_addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();

    // Create capabilities for the nodes
    let capabilities = vec![];

    // Create node info for both nodes
    let node_a_info = NodeInfo {
        peer_id: node_a_id.clone(),
        network_ids: vec!["default".to_string()], // Use "default" to match what QuicTransport uses internally
        addresses: vec![node_a_addr.to_string()],
        services: capabilities.clone(),
        version: 0,
    };

    let node_b_info = NodeInfo {
        peer_id: node_b_id.clone(),
        network_ids: vec!["default".to_string()], // Use "default" to match what QuicTransport uses internally
        addresses: vec![node_b_addr.to_string()],
        services: capabilities.clone(),
        version: 0,
    };

    // Log test setup information
    logger_a.info(format!(
        "Setting up test with Node A (ID: {}, Address: {})",
        node_a_id, node_a_addr
    ));
    logger_b.info(format!(
        "Setting up test with Node B (ID: {}, Address: {})",
        node_b_id, node_b_addr
    ));

    // Create the transport instances with proper Logger type
    // Get a runar_common::Logger for each transport
    // let common_logger_a = Logger::new_root(Component::Network, "node-a");
    // let common_logger_b = Logger::new_root(Component::Network, "node-b");

    // Create peer info for discovery simulation
    let peer_a_info = PeerInfo {
        public_key: node_a_id.public_key.clone(),
        addresses: vec![node_a_addr.to_string()],
    };

    let peer_b_info = PeerInfo {
        public_key: node_b_id.public_key.clone(),
        addresses: vec![node_b_addr.to_string()],
    };

    // Generate test certificates for both nodes
    let (certs_a, key_a) = generate_test_certificates();
    let (certs_b, key_b) = generate_test_certificates();

    // Create transport options with test certificates
    let options_a = QuicTransportOptions::new()
        .with_certificates(certs_a)
        .with_private_key(key_a)
        .with_verify_certificates(false)
        .with_certificate_verifier(Arc::new(SkipServerVerification {}));

    let options_b = QuicTransportOptions::new()
        .with_certificates(certs_b)
        .with_private_key(key_b)
        .with_verify_certificates(false)
        .with_certificate_verifier(Arc::new(SkipServerVerification {}));

    // Setup message channels for receiving messages
    let (tx_a, mut rx_a) = mpsc::channel::<NetworkMessage>(10);
    let (tx_b, mut rx_b) = mpsc::channel::<NetworkMessage>(10);

    let message_handler_a = Box::new({
        let tx = tx_a.clone();
        move |message: NetworkMessage| {
            let tx = tx.clone();
            tokio::spawn(async move {
                tx.send(message).await.unwrap();
            });
            Ok::<(), NetworkError>(())
        }
    });

    let message_handler_b = Box::new({
        let tx = tx_b.clone();
        move |message: NetworkMessage| {
            let tx = tx.clone();
            tokio::spawn(async move {
                tx.send(message).await.unwrap();
            });
            Ok::<(), NetworkError>(())
        }
    });

    // Create transport instances with the new API that takes NodeInfo
    let transport_a = QuicTransport::new(
        node_a_info.clone(),
        node_a_addr,
        message_handler_a,
        options_a,
        logger_a.clone(),
    )
    .expect("Failed to create transport A");

    let transport_b = QuicTransport::new(
        node_b_info.clone(),
        node_b_addr,
        message_handler_b,
        options_b,
        logger_b.clone(),
    )
    .expect("Failed to create transport B");

    // Start the transports
    logger_a.info("Starting transport A");
    transport_a
        .start()
        .await
        .expect("Failed to start transport A");
    logger_b.info("Starting transport B");
    transport_b
        .start()
        .await
        .expect("Failed to start transport B");

    // Give the transports a moment to initialize
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Subscribe to peer node info updates for both transports
    let mut node_info_receiver_a = transport_a.subscribe_to_peer_node_info().await;
    let mut node_info_receiver_b = transport_b.subscribe_to_peer_node_info().await;

    // Attempt to establish connections between the nodes
    let max_retries = 5;
    let mut a_to_b_connected = false;
    let mut b_to_a_connected = false;

    for retry in 1..=max_retries {
        // Try to connect A to B if not already connected
        if !a_to_b_connected {
            println!("Attempting to connect A to B (retry {})", retry);
            // Clone the peer info for each connection attempt
            let peer_b_info_clone = peer_b_info.clone();
            match transport_a.connect_peer(peer_b_info_clone).await {
                Ok::<(), NetworkError>(()) => {
                    a_to_b_connected = true;
                    println!("Successfully connected A to B");

                    // Receive the peer node info from the channel
                    match tokio::time::timeout(Duration::from_secs(5), node_info_receiver_a.recv())
                        .await
                    {
                        Ok(Ok(peer_node_info)) => {
                            // Validate the received peer node info
                            assert_eq!(
                                peer_node_info.peer_id, node_b_id,
                                "Peer ID in received NodeInfo doesn't match expected node B ID"
                            );
                            assert_eq!(
                                peer_node_info.network_ids, node_b_info.network_ids,
                                "Network IDs in received NodeInfo don't match"
                            );
                            assert_eq!(
                                peer_node_info.services, node_b_info.services,
                                "Services in received NodeInfo don't match"
                            );
                            assert!(
                                !peer_node_info.addresses.is_empty(),
                                "Addresses in received NodeInfo should not be empty"
                            );

                            // Validate that the addresses contain the expected address
                            let expected_addr = node_b_addr.to_string();
                            assert!(peer_node_info.addresses.contains(&expected_addr),
                                  "Addresses in received NodeInfo doesn't contain expected address: {}", expected_addr);

                            // Validate version
                            assert!(
                                peer_node_info.version == 0,
                                "Version is not 0: {:?}",
                                peer_node_info.version
                            );

                            println!("Successfully received and validated peer node info for B");
                        }
                        Ok(Err(e)) => println!("Failed to receive peer node info for B: {}", e),
                        Err(_) => println!("Timeout waiting for peer node info for B"),
                    }
                }
                Err(e) => println!("Failed to connect A to B: {}", e),
            }
        }

        // Try to connect B to A if not already connected
        if !b_to_a_connected {
            println!("Attempting to connect B to A (retry {})", retry);
            // Clone the peer info for each connection attempt
            let peer_a_info_clone = peer_a_info.clone();
            match transport_b.connect_peer(peer_a_info_clone).await {
                Ok::<(), NetworkError>(()) => {
                    b_to_a_connected = true;
                    println!("Successfully connected B to A");

                    // Receive the peer node info from the channel
                    match tokio::time::timeout(Duration::from_secs(5), node_info_receiver_b.recv())
                        .await
                    {
                        Ok(Ok(peer_node_info)) => {
                            // Validate the received peer node info
                            assert_eq!(
                                peer_node_info.peer_id, node_a_id,
                                "Peer ID in received NodeInfo doesn't match expected node A ID"
                            );
                            assert_eq!(
                                peer_node_info.network_ids, node_a_info.network_ids,
                                "Network IDs in received NodeInfo don't match"
                            );
                            assert_eq!(
                                peer_node_info.services, node_a_info.services,
                                "Services in received NodeInfo don't match"
                            );
                            assert!(
                                !peer_node_info.addresses.is_empty(),
                                "Addresses in received NodeInfo should not be empty"
                            );

                            // Validate that the addresses contain the expected address
                            let expected_addr = node_a_addr.to_string();
                            assert!(peer_node_info.addresses.contains(&expected_addr),
                                  "Addresses in received NodeInfo doesn't contain expected address: {}", expected_addr);

                            // Validate version
                            assert!(
                                peer_node_info.version == 0,
                                "Version is not 0: {:?}",
                                peer_node_info.version
                            );

                            println!("Successfully received and validated peer node info for A");
                        }
                        Ok(Err(e)) => println!("Failed to receive peer node info for A: {}", e),
                        Err(_) => println!("Timeout waiting for peer node info for A"),
                    }
                }
                Err(e) => println!("Failed to connect B to A: {}", e),
            }
        }

        // If both connections are established, break out of the loop
        if a_to_b_connected && b_to_a_connected {
            println!("Both connections established successfully!");
            break;
        }

        // Sleep for a short time before retrying
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    println!(
        "Final connection status - A->B: {}, B->A: {}",
        a_to_b_connected, b_to_a_connected
    );

    // Verify connections by checking if peers are connected
    let a_connected_to_b = transport_a.is_connected(node_b_id.clone()).await;
    let b_connected_to_a = transport_b.is_connected(node_a_id.clone()).await;

    println!("Transport A connected to B: {}", a_connected_to_b);
    println!("Transport B connected to A: {}", b_connected_to_a);

    // Assert that both connections were established
    assert!(
        a_to_b_connected,
        "Failed to establish connection from A to B after {} retries",
        max_retries
    );
    assert!(
        b_to_a_connected,
        "Failed to establish connection from B to A after {} retries",
        max_retries
    );

    // Assert that peers are registered in each transport
    assert!(a_connected_to_b, "Node B not connected to Node A");
    assert!(b_connected_to_a, "Node A not connected to Node B");

    // Test sending a message from A to B
    println!("Testing message sending from A to B");
    let test_message = NetworkMessage {
        source: node_a_id.clone(),
        destination: node_b_id.clone(),
        payloads: vec![NetworkMessagePayloadItem {
            path: "".to_string(),
            value_bytes: vec![1, 2, 3, 4],
            correlation_id: "test-123".to_string(),
        }],
        message_type: "TEST_MESSAGE".to_string(),
    };

    // Send message from A to B
    transport_a
        .send_message(test_message.clone())
        .await
        .expect("Failed to send message from A to B");

    // Wait for the message to be received with timeout
    let received_message = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
        .await
        .expect("Timeout waiting for message")
        .expect("Failed to receive message");

    // Verify message contents
    assert_eq!(received_message.source, node_a_id);
    assert_eq!(received_message.destination, node_b_id);
    assert_eq!(received_message.payloads.len(), 1);
    assert_eq!(received_message.payloads[0].path, "");

    println!("Message successfully received by B from A");

    // Test sending a message from B to A
    println!("Testing message sending from B to A");
    let test_message_b_to_a = NetworkMessage {
        source: node_b_id.clone(),
        destination: node_a_id.clone(),
        payloads: vec![NetworkMessagePayloadItem {
            path: "".to_string(),
            value_bytes: vec![5, 6, 7, 8],
            correlation_id: "test-456".to_string(),
        }],
        message_type: "TEST_MESSAGE_B_TO_A".to_string(),
    };

    // Send message from B to A
    transport_b
        .send_message(test_message_b_to_a.clone())
        .await
        .expect("Failed to send message from B to A");

    // Wait for the message to be received with timeout
    let received_message_b_to_a = tokio::time::timeout(Duration::from_secs(5), rx_a.recv())
        .await
        .expect("Timeout waiting for message from B to A")
        .expect("Failed to receive message from B to A");

    // Verify message contents
    assert_eq!(received_message_b_to_a.source, node_b_id);
    assert_eq!(received_message_b_to_a.destination, node_a_id);
    assert_eq!(received_message_b_to_a.payloads.len(), 1);
    assert_eq!(received_message_b_to_a.payloads[0].path, "");
    assert_eq!(
        received_message_b_to_a.payloads[0].value_bytes,
        vec![5, 6, 7, 8]
    );
    assert_eq!(
        received_message_b_to_a.payloads[0].correlation_id,
        "test-456"
    );
    assert_eq!(received_message_b_to_a.message_type, "TEST_MESSAGE_B_TO_A");

    println!("Message successfully received by A from B");

    // Clean up
    println!("Stopping transports");
    transport_a
        .stop()
        .await
        .expect("Failed to stop transport A");
    transport_b
        .stop()
        .await
        .expect("Failed to stop transport B");
}
