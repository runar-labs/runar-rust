use runar_common::compact_ids::compact_id;
use runar_common::logging::{Component, Logger};
use runar_node::config::{LogLevel, LoggingConfig};
use runar_node::network::transport::{
    MessageContext, MESSAGE_TYPE_ANNOUNCEMENT, MESSAGE_TYPE_EVENT, MESSAGE_TYPE_HANDSHAKE,
    MESSAGE_TYPE_REQUEST, MESSAGE_TYPE_RESPONSE,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use runar_keys::{MobileKeyManager, NodeKeyManager};
use runar_node::network::discovery::multicast_discovery::PeerInfo;
use runar_node::network::discovery::NodeInfo;
use runar_node::network::transport::{
    quic_transport::{QuicTransport, QuicTransportOptions},
    MessageHandler, NetworkMessage, NetworkMessagePayloadItem, NetworkTransport,
};
use runar_node::routing::TopicPath;
use runar_node::{ActionMetadata, EventMetadata, ServiceMetadata};
use runar_serializer::traits::{ConfigurableLabelResolver, KeyMappingConfig, LabelResolver};
use runar_serializer::ArcValue;
use std::collections::HashMap;
use std::time::Duration;

// Dummy crypto that performs no-op encryption for tests
struct NoCrypto;

impl runar_serializer::traits::EnvelopeCrypto for NoCrypto {
    fn encrypt_with_envelope(
        &self,
        data: &[u8],
        _network_id: Option<&String>,
        _profile_public_keys: Vec<Vec<u8>>,
    ) -> runar_keys::Result<runar_keys::mobile::EnvelopeEncryptedData> {
        Ok(runar_keys::mobile::EnvelopeEncryptedData {
            encrypted_data: data.to_vec(),
            network_id: Some("test-network".to_string()),
            network_encrypted_key: Vec::new(),
            profile_encrypted_keys: std::collections::HashMap::new(),
        })
    }

    fn decrypt_envelope_data(
        &self,
        env: &runar_keys::mobile::EnvelopeEncryptedData,
    ) -> runar_keys::Result<Vec<u8>> {
        Ok(env.encrypted_data.clone())
    }
}

/// This test ensures the transport layer properly handles:
/// 1. Bidirectional streams for request-response patterns
/// 2. Unidirectional streams for handshakes and announcements
/// 3. Message callbacks and routing
/// 4. Connection lifecycle management
/// 5. Certificate-based security
#[tokio::test]
async fn test_quic_transport() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);
    logging_config.apply();

    let logger = Arc::new(Logger::new_root(Component::Custom("quic_test"), ""));

    logger.debug("QUIC Test function started");

    // ==================================================
    // STEP 1: Initialize Certificate Infrastructure
    // ==================================================

    // Create ONE mobile key manager that acts as the CA for both nodes
    let mut mobile_ca = MobileKeyManager::new(logger.clone())?;

    // Generate user root key and CA key (mobile acts as CA)
    let _user_root_public_key = mobile_ca
        .initialize_user_root_key()
        .expect("Failed to initialize user root key");

    let _user_ca_public_key = mobile_ca.get_ca_public_key();

    logger.debug("Created mobile CA with user root and CA keys");

    // ==================================================
    // STEP 2: Setup Node 1 Certificate
    // ==================================================

    // Create node 1 key manager and generate setup token
    let mut node_key_manager_1 = NodeKeyManager::new(logger.clone())?;
    let setup_token_1 = node_key_manager_1
        .generate_csr()
        .expect("Failed to generate setup token for node 1");

    // Mobile CA processes setup token and signs certificate
    let cert_1 = mobile_ca
        .process_setup_token(&setup_token_1)
        .expect("Failed to process setup token for node 1");

    // Node 1 installs the certificate directly
    node_key_manager_1
        .install_certificate(cert_1)
        .expect("Failed to install certificate for node 1");

    // ==================================================
    // STEP 3: Setup Node 2 Certificate
    // ==================================================

    // Create node 2 key manager and generate setup token
    let mut node_key_manager_2 = NodeKeyManager::new(logger.clone())?;
    let setup_token_2 = node_key_manager_2
        .generate_csr()
        .expect("Failed to generate setup token for node 2");

    // Mobile CA processes setup token and signs certificate
    let cert_2 = mobile_ca
        .process_setup_token(&setup_token_2)
        .expect("Failed to process setup token for node 2");

    // Node 2 installs the certificate directly
    node_key_manager_2
        .install_certificate(cert_2)
        .expect("Failed to install certificate for node 2");

    // ==================================================
    // STEP 4: Get QUIC Certificates
    // ==================================================

    logger.debug("🛡️ Retrieving QUIC certificates...");

    // NOW both nodes can get QUIC certificates because they have valid certificates
    let node1_cert_config = node_key_manager_1.get_quic_certificate_config()?;
    let node2_cert_config = node_key_manager_2.get_quic_certificate_config()?;

    // Get the CA certificate to use as root certificate for validation
    let ca_certificate = mobile_ca.get_ca_certificate().to_rustls_certificate();

    // ==================================================
    // STEP 5: Get Real Node Public Keys for Proper Peer Identification
    // ==================================================

    // Get the actual node public keys (not hardcoded values)
    let node1_public_key_bytes = node_key_manager_1.get_node_public_key();
    let node1_id = compact_id(&node1_public_key_bytes);

    let node2_public_key_bytes = node_key_manager_2.get_node_public_key();
    let node2_id = compact_id(&node2_public_key_bytes);

    logger.debug(format!("Node 1 node1_id: {node1_id}"));
    logger.debug(format!("Node 2 node2_id: {node2_id}"));

    // ==================================================
    // STEP 6: Create Message Tracking for Validation
    // ==================================================

    let node1_messages = Arc::new(Mutex::new(Vec::new()));
    let node2_messages = Arc::new(Mutex::new(Vec::new()));

    let node1_messages_clone = Arc::clone(&node1_messages);
    let node2_messages_clone = Arc::clone(&node2_messages);

    let logger_1 = logger.clone();
    let logger_2 = logger.clone();

    // Clone node IDs before moving into closures
    let node1_id_clone = node1_id.clone();
    let node2_id_clone = node2_id.clone();

    // Message handlers that track all received messages and return responses
    let node1_handler: MessageHandler = Box::new(move |message: NetworkMessage| {
        let logger = logger_1.clone();
        let messages = node1_messages_clone.clone();
        let msg_type = message.message_type.clone();
        let source = message.source_node_id.clone();
        let node1_id = node1_id_clone.clone();

        logger.info(format!(
            "📥 [Transport1] Received message: Type={type}, From={source}, Payloads={payloads}",
            type=msg_type,
            source=source,
            payloads=message.payloads.len()
        ));

        let messages_clone = messages.clone();
        Box::pin(async move {
            let mut msgs = messages_clone.lock().await;
            msgs.push(message.clone());

            // Return response for requests
            if message.message_type == MESSAGE_TYPE_REQUEST {
                logger.info("📤 [Transport1] Sending response for request");
                let response = NetworkMessage {
                    source_node_id: node1_id.clone(),
                    destination_node_id: message.source_node_id,
                    message_type: MESSAGE_TYPE_RESPONSE,
                    payloads: message
                        .payloads
                        .iter()
                        .map(|payload| {
                            // Create a proper ArcValue response
                            let response_value = ArcValue::new_primitive(format!(
                                "Response from Node1: {}",
                                payload.path
                            ));
                            NetworkMessagePayloadItem {
                                path: payload.path.clone(),
                                value_bytes: response_value.serialize(None).unwrap_or_default(),
                                correlation_id: payload.correlation_id.clone(),
                                context: payload.context.clone(),
                            }
                        })
                        .collect(),
                };
                Ok(Some(response))
            } else {
                Ok(None)
            }
        })
    });

    let node2_handler: MessageHandler = Box::new(move |message: NetworkMessage| {
        let logger = logger_2.clone();
        let messages = node2_messages_clone.clone();
        let msg_type = message.message_type.clone();
        let source = message.source_node_id.clone();
        let node2_id = node2_id_clone.clone();

        logger.info(format!(
            "📥 [Transport2] Received message: Type={}, From={}, Payloads={}",
            msg_type,
            source,
            message.payloads.len()
        ));

        let messages_clone = messages.clone();
        Box::pin(async move {
            let mut msgs = messages_clone.lock().await;
            msgs.push(message.clone());

            // Return response for requests
            if message.message_type == MESSAGE_TYPE_REQUEST {
                logger.info("📤 [Transport2] Sending response for request");
                let response = NetworkMessage {
                    source_node_id: node2_id.clone(),
                    destination_node_id: message.source_node_id,
                    message_type: MESSAGE_TYPE_RESPONSE,
                    payloads: message
                        .payloads
                        .iter()
                        .map(|payload| {
                            // Create a proper ArcValue response
                            let response_value = ArcValue::new_primitive(format!(
                                "Response from Node2: {}",
                                payload.path
                            ));
                            NetworkMessagePayloadItem {
                                path: payload.path.clone(),
                                value_bytes: response_value.serialize(None).unwrap_or_default(),
                                correlation_id: payload.correlation_id.clone(),
                                context: payload.context.clone(),
                            }
                        })
                        .collect(),
                };
                Ok(Some(response))
            } else {
                Ok(None)
            }
        })
    });

    // ==================================================
    // STEP 7: Initialize QuicTransport Instances
    // ==================================================

    let node1_info = NodeInfo {
        node_public_key: node1_public_key_bytes.clone(),
        network_ids: vec!["test".to_string()],
        addresses: vec!["127.0.0.1:50069".to_string()],
        services: vec![ServiceMetadata {
            network_id: "test".to_string(),
            service_path: "api1".to_string(),
            name: "api1".to_string(),
            version: "1.0.0".to_string(),
            description: "API 1".to_string(),
            actions: vec![
                ActionMetadata {
                    name: "get".to_string(),
                    description: "GET operation".to_string(),
                    input_schema: None,
                    output_schema: None,
                },
                ActionMetadata {
                    name: "post".to_string(),
                    description: "POST operation".to_string(),
                    input_schema: None,
                    output_schema: None,
                },
            ],
            events: vec![EventMetadata {
                path: "data_processed".to_string(),
                description: "Data processing completed".to_string(),
                data_schema: None,
            }],
            registration_time: 0,
            last_start_time: None,
        }],
        version: 1,
    };

    let node2_info = NodeInfo {
        node_public_key: node2_public_key_bytes.clone(),
        network_ids: vec!["test".to_string()],
        addresses: vec!["127.0.0.1:50044".to_string()],
        services: vec![ServiceMetadata {
            network_id: "test".to_string(),
            service_path: "storage1".to_string(),
            name: "storage1".to_string(),
            version: "1.0.0".to_string(),
            description: "Storage 1".to_string(),
            actions: vec![
                ActionMetadata {
                    name: "store".to_string(),
                    description: "Store operation".to_string(),
                    input_schema: None,
                    output_schema: None,
                },
                ActionMetadata {
                    name: "retrieve".to_string(),
                    description: "Retrieve operation".to_string(),
                    input_schema: None,
                    output_schema: None,
                },
            ],
            events: vec![EventMetadata {
                path: "storage_updated".to_string(),
                description: "Storage state changed".to_string(),
                data_schema: None,
            }],
            registration_time: 0,
            last_start_time: None,
        }],
        version: 1,
    };

    let transport1_options = QuicTransportOptions::new()
        .with_certificates(node1_cert_config.certificate_chain)
        .with_private_key(node1_cert_config.private_key)
        .with_root_certificates(vec![ca_certificate.clone()]);

    let transport2_options = QuicTransportOptions::new()
        .with_certificates(node2_cert_config.certificate_chain)
        .with_private_key(node2_cert_config.private_key)
        .with_root_certificates(vec![ca_certificate]);

    let empty_resolver: Arc<dyn LabelResolver> =
        Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
            label_mappings: HashMap::new(),
        }));

    let transport1_options = transport1_options
        .with_local_node_info(node1_info.clone())
        .with_bind_addr("127.0.0.1:50069".parse::<SocketAddr>()?)
        .with_message_handler(node1_handler)
        .with_logger(logger.clone())
        .with_keystore(Arc::new(NoCrypto))
        .with_label_resolver(empty_resolver.clone());

    let transport1 = Arc::new(QuicTransport::new(transport1_options)?);

    let transport2_options = transport2_options
        .with_local_node_info(node2_info.clone())
        .with_bind_addr("127.0.0.1:50044".parse::<SocketAddr>()?)
        .with_message_handler(node2_handler)
        .with_logger(logger.clone())
        .with_keystore(Arc::new(NoCrypto))
        .with_label_resolver(empty_resolver.clone());

    let transport2 = Arc::new(QuicTransport::new(transport2_options)?);

    // ==================================================
    // STEP 8: Start Transport Services
    // ==================================================

    logger.debug("Starting transport services...");
    transport1.clone().start().await?;
    transport2.clone().start().await?;

    logger.debug("Started both transport services");

    // Allow transport services to initialize
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ==================================================
    // STEP 9: Test Transport API - Connection Management
    // ==================================================

    logger.debug("Connecting peers...");

    // Test connection establishment
    let peer_info_1 = PeerInfo::new(node1_public_key_bytes.clone(), node1_info.addresses.clone());
    let peer_info_2 = PeerInfo::new(node2_public_key_bytes.clone(), node2_info.addresses.clone());

    // Force both transports to connect to each other for bidirectional communication
    logger.debug(" Establishing bidirectional connections...");
    transport1.clone().connect_peer(peer_info_2).await?;
    transport2.clone().connect_peer(peer_info_1).await?;

    logger.debug("⏱️  Waiting for connections to establish...");
    // Allow connections to establish
    // tokio::time::sleep(Duration::from_millis(1000)).await;

    // Verify connections
    let t1_connected = transport1.is_connected(node2_id.clone()).await;
    let t2_connected = transport2.is_connected(node1_id.clone()).await;
    logger.debug(format!(
        " Connection status: T1→T2={t1_connected}, T2→T1={t2_connected}"
    ));

    // Both directions should be connected
    assert!(
        t1_connected && t2_connected,
        "Both connections should be established for bidirectional communication"
    );

    logger.debug("Connection management working correctly");

    // ==================================================
    // STEP 10: Test Handshake
    // ==================================================

    logger.info(" Testing handshake...");

    let node1_msgs = match tokio::time::timeout(Duration::from_secs(2), node1_messages.lock()).await
    {
        Ok(guard) => guard,
        Err(_) => {
            logger.error("Timeout acquiring lock on node1_messages");
            panic!("Timeout acquiring lock on node1_messages");
        }
    };
    logger.info(" Acquired lock on node1_messages, about to lock node2_messages...");

    let node2_msgs = match tokio::time::timeout(Duration::from_secs(2), node2_messages.lock()).await
    {
        Ok(guard) => guard,
        Err(_) => {
            logger.error("Timeout acquiring lock on node2_messages");
            panic!("Timeout acquiring lock on node2_messages");
        }
    };

    logger.info(format!(
        "📊 Handshake check - Node1 messages: {}",
        node1_msgs.len()
    ));
    for (i, msg) in node1_msgs.iter().enumerate() {
        logger.info(format!("📊 Node1 message {}: type={}", i, msg.message_type));
    }

    logger.info(format!(
        "📊 Handshake check - Node2 messages: {}",
        node2_msgs.len()
    ));
    for (i, msg) in node2_msgs.iter().enumerate() {
        logger.info(format!("📊 Node2 message {}: type={}", i, msg.message_type));
    }

    let handshake_received = node1_msgs
        .iter()
        .any(|msg| msg.message_type == MESSAGE_TYPE_HANDSHAKE)
        || node2_msgs
            .iter()
            .any(|msg| msg.message_type == MESSAGE_TYPE_HANDSHAKE);

    logger.info(format!("📊 Handshake received: {}", handshake_received));

    assert!(handshake_received, "Handshake messages should be exchanged");
    drop(node1_msgs);
    drop(node2_msgs);

    logger.info("Handshake working correctly");

    // ==================================================
    // STEP 11: Test Request-Response Messaging
    // ==================================================

    // Determine which transport to use for sending (both should be connected now)
    let (sender_transport, sender_info, receiver_info) =
        (transport1.clone(), &node1_info, &node2_info);

    // Create a test request
    let test_data = ArcValue::new_primitive("test_value".to_string());

    let context = MessageContext {
        profile_public_key: sender_info.node_public_key.clone(),
    };

    logger.info(format!(
        "sending request from Sender: {}, to Receiver: {}",
        compact_id(&sender_info.node_public_key),
        compact_id(&receiver_info.node_public_key)
    ));

    // Check message counts before sending
    let node1_count_before = node1_messages.lock().await.len();
    let node2_count_before = node2_messages.lock().await.len();
    logger.info(format!(
        "📊 Message counts before request: Node1={node1_count_before}, Node2={node2_count_before}"
    ));

    // Send request using the transport's request method with timeout
    let response = sender_transport
        .request(
            &TopicPath::new("test:api1/get", "test")?,
            Some(test_data),
            &compact_id(&receiver_info.node_public_key),
            context,
        )
        .await?;

    // Check message counts after sending
    let node1_count_after = node1_messages.lock().await.len();
    let node2_count_after = node2_messages.lock().await.len();
    logger.info(format!(
        "📊 Message counts after request: Node1={node1_count_after}, Node2={node2_count_after}"
    ));

    // Verify we got a response
    assert!(!response.is_null(), "Should receive a response");

    logger.info("Request-response working correctly");

    // ==================================================
    // STEP 12: Test Event Publishing
    // ==================================================

    logger.info("📡 Testing event publishing...");

    let event_data = ArcValue::new_primitive("event_data".to_string());
    let event_message = NetworkMessage {
        source_node_id: compact_id(&sender_info.node_public_key),
        destination_node_id: compact_id(&receiver_info.node_public_key),
        message_type: MESSAGE_TYPE_EVENT,
        payloads: vec![NetworkMessagePayloadItem {
            path: "test:api1/data_processed".to_string(),
            value_bytes: event_data.serialize(None)?,
            correlation_id: format!("event-{}", uuid::Uuid::new_v4()),
            context: None,
        }],
    };

    sender_transport.publish(event_message).await?;

    // Allow message to be processed
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check that event was received
    let receiver_msgs = if t1_connected {
        &node2_messages
    } else {
        &node1_messages
    };
    let event_msgs = receiver_msgs.lock().await;
    let event_received = event_msgs
        .iter()
        .any(|msg| msg.message_type == MESSAGE_TYPE_EVENT);
    assert!(event_received, "Event message should be received");
    drop(event_msgs);

    logger.info("Event publishing working correctly");

    // ==================================================
    // STEP 13: Test Announcement Messages
    // ==================================================

    logger.info("Testing announcement messages...");

    let announcement_message = NetworkMessage {
        source_node_id: compact_id(&sender_info.node_public_key),
        destination_node_id: compact_id(&receiver_info.node_public_key),
        message_type: MESSAGE_TYPE_ANNOUNCEMENT,
        payloads: vec![NetworkMessagePayloadItem {
            path: "".to_string(),
            value_bytes: "Test announcement data".as_bytes().to_vec(),
            correlation_id: "announcement_test".to_string(),
            context: None,
        }],
    };

    sender_transport.publish(announcement_message).await?;

    // Allow message to be processed
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check that announcement was received
    let announcement_msgs = receiver_msgs.lock().await;
    let announcement_received = announcement_msgs
        .iter()
        .any(|msg| msg.message_type == MESSAGE_TYPE_ANNOUNCEMENT);
    assert!(
        announcement_received,
        "Announcement message should be received"
    );
    drop(announcement_msgs);

    logger.info("Announcement messages working correctly");

    // ==================================================
    // STEP 14: Comprehensive Analysis
    // ==================================================

    logger.debug("\n🔍 DATAFLOW ANALYSIS");
    logger.debug(
        "====================================================================================",
    );

    // Analyze message flows
    let node1_msgs = node1_messages.lock().await;
    let node2_msgs = node2_messages.lock().await;

    logger.debug("\nMESSAGE FLOW ANALYSIS:");
    logger.debug(format!(
        "  - Node 1 received {} messages:",
        node1_msgs.len()
    ));
    for msg in node1_msgs.iter() {
        logger.debug(format!(
            "    - {type}: from {source}",
            type=map_message_type_to_string(msg.message_type), source=msg.source_node_id
        ));
    }

    logger.debug(format!(
        "  - Node 2 received {} messages:",
        node2_msgs.len()
    ));
    for msg in node2_msgs.iter() {
        logger.debug(format!(
            "    - {type}: from {source}",
            type=map_message_type_to_string(msg.message_type), source=msg.source_node_id
        ));
    }

    // Check connection status
    let a_connected_to_b = transport1.is_connected(node2_id.clone()).await;
    let b_connected_to_a = transport2.is_connected(node1_id.clone()).await;

    logger.info("\n CONNECTION STATUS:");
    logger.info(format!("  - Node 1 → Node 2: {a_connected_to_b}"));
    logger.info(format!("  - Node 2 → Node 1: {b_connected_to_a}"));

    // ==================================================
    // STEP 15: Validation and Assertions
    // ==================================================

    logger.info("\nDATAFLOW VALIDATION:");

    // Validate connection establishment
    assert!(
        a_connected_to_b || b_connected_to_a,
        "At least one direction should be connected"
    );
    logger.info("QUIC connections established successfully");

    // Validate message reception
    assert!(
        !node1_msgs.is_empty() || !node2_msgs.is_empty(),
        "At least one node should have received messages"
    );
    logger.info("Message callbacks invoked successfully");

    // Validate different message types
    let has_handshake = node1_msgs
        .iter()
        .any(|msg| msg.message_type == MESSAGE_TYPE_HANDSHAKE)
        || node2_msgs
            .iter()
            .any(|msg| msg.message_type == MESSAGE_TYPE_HANDSHAKE);
    let has_request = node1_msgs
        .iter()
        .any(|msg| msg.message_type == MESSAGE_TYPE_REQUEST)
        || node2_msgs
            .iter()
            .any(|msg| msg.message_type == MESSAGE_TYPE_REQUEST);
    let has_response = node1_msgs
        .iter()
        .any(|msg| msg.message_type == MESSAGE_TYPE_RESPONSE)
        || node2_msgs
            .iter()
            .any(|msg| msg.message_type == MESSAGE_TYPE_RESPONSE);
    let has_event = node1_msgs
        .iter()
        .any(|msg| msg.message_type == MESSAGE_TYPE_EVENT)
        || node2_msgs
            .iter()
            .any(|msg| msg.message_type == MESSAGE_TYPE_EVENT);
    let has_announcement = node1_msgs
        .iter()
        .any(|msg| msg.message_type == MESSAGE_TYPE_ANNOUNCEMENT)
        || node2_msgs
            .iter()
            .any(|msg| msg.message_type == MESSAGE_TYPE_ANNOUNCEMENT);

    if has_handshake {
        logger.info("Handshake messages processed successfully");
    }
    if has_request && has_response {
        logger.info("Request and response messages processed successfully");
    }
    if has_event {
        logger.info("Event messages processed successfully");
    }
    if has_announcement {
        logger.info("Announcement messages processed successfully");
    }

    // Clean up
    logger.info("\nCleaning up...");
    transport1.stop().await?;
    transport2.stop().await?;
    logger.info("Transports stopped successfully!");

    Ok(())
}

fn map_message_type_to_string(message_type: u32) -> String {
    match message_type {
        MESSAGE_TYPE_HANDSHAKE => "HANDSHAKE".to_string(),
        MESSAGE_TYPE_REQUEST => "REQUEST".to_string(),
        MESSAGE_TYPE_RESPONSE => "RESPONSE".to_string(),
        MESSAGE_TYPE_EVENT => "EVENT".to_string(),
        MESSAGE_TYPE_ANNOUNCEMENT => "ANNOUNCEMENT".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}
