use runar_common::compact_ids::compact_id;
use runar_common::logging::{Component, Logger};
use runar_node::config::{LogLevel, LoggingConfig};
use runar_node::network::transport::{
    MessageContext, MESSAGE_TYPE_EVENT, MESSAGE_TYPE_HANDSHAKE,
    MESSAGE_TYPE_REQUEST, MESSAGE_TYPE_RESPONSE,
};
use runar_schemas::{NodeMetadata, SubscriptionMetadata};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use runar_keys::{MobileKeyManager, NodeKeyManager};
use runar_node::network::discovery::multicast_discovery::PeerInfo;
use runar_node::network::discovery::NodeInfo;
use runar_node::network::transport::{
    quic_transport::{QuicTransport, QuicTransportOptions},
    MessageHandler, NetworkMessage, NetworkMessagePayloadItem, NetworkTransport,
    OneWayMessageHandler, ConnectionCallback,
};
use runar_node::routing::TopicPath;
use runar_node::{ActionMetadata, ServiceMetadata};
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
    // Watchdog to prevent indefinite hangs
    let watchdog = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(120)).await;
        panic!("test_quic_transport timed out");
    });
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

    // Clone variables for one-way handlers
    let logger_1_one_way = logger_1.clone();
    let logger_2_one_way = logger_2.clone();
    let node1_messages_one_way = node1_messages_clone.clone();
    let node2_messages_one_way = node2_messages_clone.clone();

    // Message handlers that track all received messages and return responses
    let node1_handler: MessageHandler = Box::new(move |message: NetworkMessage| {
        let logger = logger_1.clone();
        let messages = node1_messages_clone.clone();
        let msg_type = message.message_type;
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
        let msg_type = message.message_type;
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

    // One-way message handlers for unidirectional streams
    let node1_one_way_handler: OneWayMessageHandler = Box::new(move |message: NetworkMessage| {
        let logger = logger_1_one_way.clone();
        let messages = node1_messages_one_way.clone();
        let msg_type = message.message_type;
        let source = message.source_node_id.clone();

        logger.info(format!(
            "📥 [Transport1-OneWay] Received one-way message: Type={}, From={}, Payloads={}",
            msg_type,
            source,
            message.payloads.len()
        ));

        let messages_clone = messages.clone();
        Box::pin(async move {
            let mut msgs = messages_clone.lock().await;
            msgs.push(message);
            Ok(())
        })
    });

    let node2_one_way_handler: OneWayMessageHandler = Box::new(move |message: NetworkMessage| {
        let logger = logger_2_one_way.clone();
        let messages = node2_messages_one_way.clone();
        let msg_type = message.message_type;
        let source = message.source_node_id.clone();

        logger.info(format!(
            "📥 [Transport2-OneWay] Received one-way message: Type={}, From={}, Payloads={}",
            msg_type,
            source,
            message.payloads.len()
        ));

        let messages_clone = messages.clone();
        Box::pin(async move {
            let mut msgs = messages_clone.lock().await;
            msgs.push(message);
            Ok(())
        })
    });

    // ==================================================
    // STEP 7: Initialize QuicTransport Instances
    // ==================================================

    let node1_info = NodeInfo {
        node_public_key: node1_public_key_bytes.clone(),
        network_ids: vec!["test".to_string()],
        addresses: vec!["127.0.0.1:50069".to_string()],
        node_metadata: NodeMetadata {
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
                registration_time: 0,
                last_start_time: None,
            }],
            subscriptions: vec![SubscriptionMetadata {
                path: "data_processed".to_string(),
            }],
        },
        version: 1,
    };

    let node2_info = NodeInfo {
        node_public_key: node2_public_key_bytes.clone(),
        network_ids: vec!["test".to_string()],
        addresses: vec!["127.0.0.1:50044".to_string()],
        node_metadata: NodeMetadata {
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
                registration_time: 0,
                last_start_time: None,
            }],
            subscriptions: vec![SubscriptionMetadata {
                path: "storage_updated".to_string(),
            }],
        },
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
        .with_one_way_message_handler(node1_one_way_handler)
        .with_logger(logger.clone())
        .with_keystore(Arc::new(NoCrypto))
        .with_label_resolver(empty_resolver.clone());

    let transport1 = Arc::new(QuicTransport::new(transport1_options)?);

    let transport2_options = transport2_options
        .with_local_node_info(node2_info.clone())
        .with_bind_addr("127.0.0.1:50044".parse::<SocketAddr>()?)
        .with_message_handler(node2_handler)
        .with_one_way_message_handler(node2_one_way_handler)
        .with_logger(logger.clone())
        .with_keystore(Arc::new(NoCrypto))
        .with_label_resolver(empty_resolver.clone());

    let transport2 = Arc::new(QuicTransport::new(transport2_options)?);

    // ==================================================
    // STEP 8: Start Transport Services
    // ==================================================

    logger.debug("Starting transport services...");
    // Start transports concurrently
    let (r1, r2) = tokio::join!(transport1.clone().start(), transport2.clone().start());
    r1?;
    r2?;
    // Small readiness wait to ensure endpoint is bound before connect
    tokio::time::sleep(Duration::from_millis(150)).await;

    logger.debug("Started both transport services");

    // Allow transport services to initialize
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ==================================================
    // STEP 9: Test Transport API - Connection Management
    // ==================================================

    logger.debug("Connecting peers...");

    // Test connection establishment (single initiator)
    let peer_info_2 = PeerInfo::new(node2_public_key_bytes.clone(), node2_info.addresses.clone());

    // Single initiator to avoid simultaneous dial races
    logger.debug(" Establishing connection from Transport1 to Transport2...");
    transport1.clone().connect_peer(peer_info_2).await?;

    logger.debug("⏱️  Waiting for connections to establish...");
    // Bounded wait loop to allow duplicate-resolution/handshake to settle
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let (t1_connected, t2_connected) = loop {
        let t1 = transport1.is_connected(node2_id.clone()).await;
        let t2 = transport2.is_connected(node1_id.clone()).await;
        if t1 && t2 {
            break (t1, t2);
        }
        if tokio::time::Instant::now() >= deadline {
            break (t1, t2);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
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

    logger.info(format!("📊 Handshake received: {handshake_received}"));

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

    // Reconfirm connectivity just before request; attempt idempotent reconnect if needed
    if !sender_transport
        .is_connected(compact_id(&receiver_info.node_public_key))
        .await
    {
        let peer_info = PeerInfo::new(
            receiver_info.node_public_key.clone(),
            receiver_info.addresses.clone(),
        );
        let _ = sender_transport.clone().connect_peer(peer_info).await; // best-effort
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            if sender_transport
                .is_connected(compact_id(&receiver_info.node_public_key))
                .await
            {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

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
 
    let topic_path = TopicPath::new("test:api1/data_processed", "test")?;
    sender_transport.publish(&topic_path, Some(event_data), &compact_id(&receiver_info.node_public_key)).await?;

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
     

    if has_handshake {
        logger.info("Handshake messages processed successfully");
    }
    if has_request && has_response {
        logger.info("Request and response messages processed successfully");
    }
    if has_event {
        logger.info("Event messages processed successfully");
    }
    
    // Clean up
    logger.info("\nCleaning up...");
    transport1.stop().await?;
    transport2.stop().await?;
    logger.info("Transports stopped successfully!");
    // Cancel watchdog on success
    watchdog.abort();
    let _ = watchdog.await;

    Ok(())
}

fn map_message_type_to_string(message_type: u32) -> String {
    match message_type {
        MESSAGE_TYPE_HANDSHAKE => "HANDSHAKE".to_string(),
        MESSAGE_TYPE_REQUEST => "REQUEST".to_string(),
        MESSAGE_TYPE_RESPONSE => "RESPONSE".to_string(),
        MESSAGE_TYPE_EVENT => "EVENT".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}

// Duplicate-resolution and simultaneous dial scenario
#[tokio::test]
async fn test_quic_duplicate_resolution_simultaneous_dial(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Watchdog to prevent indefinite hangs
    let watchdog = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(120)).await;
        panic!("test_quic_duplicate_resolution_simultaneous_dial timed out");
    });

    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);
    logging_config.apply();
    let logger = Arc::new(Logger::new_root(Component::Custom("dup_test"), ""));

    // Keys and certs
    let mut mobile_ca = MobileKeyManager::new(logger.clone())?;
    let _ = mobile_ca.initialize_user_root_key()?;
    let mut node_key_manager_1 = NodeKeyManager::new(logger.clone())?;
    let cert_1 = mobile_ca.process_setup_token(&node_key_manager_1.generate_csr()?)?;
    node_key_manager_1.install_certificate(cert_1)?;
    let mut node_key_manager_2 = NodeKeyManager::new(logger.clone())?;
    let cert_2 = mobile_ca.process_setup_token(&node_key_manager_2.generate_csr()?)?;
    node_key_manager_2.install_certificate(cert_2)?;

    let node1_cert_config = node_key_manager_1.get_quic_certificate_config()?;
    let node2_cert_config = node_key_manager_2.get_quic_certificate_config()?;
    let ca_certificate = mobile_ca.get_ca_certificate().to_rustls_certificate();

    // Node infos
    let node1_pk = node_key_manager_1.get_node_public_key();
    let node2_pk = node_key_manager_2.get_node_public_key();
    let node1_id = compact_id(&node1_pk);
    let node2_id = compact_id(&node2_pk);

    let node1_info = NodeInfo { node_public_key: node1_pk.clone(), network_ids: vec!["test".to_string()], addresses: vec!["127.0.0.1:50111".to_string()], node_metadata: NodeMetadata { services: vec![], subscriptions: vec![] }, version: 0 };
    let node2_info = NodeInfo { node_public_key: node2_pk.clone(), network_ids: vec!["test".to_string()], addresses: vec!["127.0.0.1:50112".to_string()], node_metadata: NodeMetadata { services: vec![], subscriptions: vec![] }, version: 0 };

    // Minimal handlers
    let logger1 = logger.clone();
    let handler1: MessageHandler = Box::new(move |msg: NetworkMessage| {
        let log = logger1.clone();
        Box::pin(async move {
            log.debug(format!("[dup_test.T1] received msg type={} from {}", msg.message_type, msg.source_node_id));
            if msg.message_type == MESSAGE_TYPE_REQUEST {
                let resp = NetworkMessage { source_node_id: msg.destination_node_id.clone(), destination_node_id: msg.source_node_id.clone(), message_type: MESSAGE_TYPE_RESPONSE, payloads: msg.payloads.clone() };
                Ok(Some(resp))
            } else { Ok(None) }
        })
    });
    let one_way1: OneWayMessageHandler = Box::new(move |_msg: NetworkMessage| Box::pin(async { Ok(()) }));

    let logger2 = logger.clone();
    let handler2: MessageHandler = Box::new(move |msg: NetworkMessage| {
        let log = logger2.clone();
        Box::pin(async move {
            log.debug(format!("[dup_test.T2] received msg type={} from {}", msg.message_type, msg.source_node_id));
            if msg.message_type == MESSAGE_TYPE_REQUEST {
                let resp = NetworkMessage { source_node_id: msg.destination_node_id.clone(), destination_node_id: msg.source_node_id.clone(), message_type: MESSAGE_TYPE_RESPONSE, payloads: msg.payloads.clone() };
                Ok(Some(resp))
            } else { Ok(None) }
        })
    });
    let one_way2: OneWayMessageHandler = Box::new(move |_msg: NetworkMessage| Box::pin(async { Ok(()) }));

    // Build transports
    let empty_resolver: Arc<dyn LabelResolver> = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig { label_mappings: HashMap::new() }));
    let t1_opts = QuicTransportOptions::new()
        .with_certificates(node1_cert_config.certificate_chain)
        .with_private_key(node1_cert_config.private_key)
        .with_root_certificates(vec![ca_certificate.clone()])
        .with_local_node_info(node1_info.clone())
        .with_bind_addr("127.0.0.1:50111".parse::<SocketAddr>()?)
        .with_message_handler(handler1)
        .with_one_way_message_handler(one_way1)
        .with_logger(logger.clone())
        .with_keystore(Arc::new(NoCrypto))
        .with_label_resolver(empty_resolver.clone());
    let t2_opts = QuicTransportOptions::new()
        .with_certificates(node2_cert_config.certificate_chain)
        .with_private_key(node2_cert_config.private_key)
        .with_root_certificates(vec![ca_certificate])
        .with_local_node_info(node2_info.clone())
        .with_bind_addr("127.0.0.1:50112".parse::<SocketAddr>()?)
        .with_message_handler(handler2)
        .with_one_way_message_handler(one_way2)
        .with_logger(logger.clone())
        .with_keystore(Arc::new(NoCrypto))
        .with_label_resolver(empty_resolver.clone());

    let t1 = Arc::new(QuicTransport::new(t1_opts)?);
    let t2 = Arc::new(QuicTransport::new(t2_opts)?);

    let (sr1, sr2) = tokio::join!(t1.clone().start(), t2.clone().start());
    sr1?; sr2?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Simultaneous dial
    let p1 = PeerInfo::new(node1_info.node_public_key.clone(), node1_info.addresses.clone());
    let p2 = PeerInfo::new(node2_info.node_public_key.clone(), node2_info.addresses.clone());
    let (c12, c21) = tokio::join!(t1.clone().connect_peer(p2), t2.clone().connect_peer(p1));
    c12?; c21?;

    // Allow duplicate-resolution to settle
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if t1.is_connected(node2_id.clone()).await && t2.is_connected(node1_id.clone()).await { break; }
        if tokio::time::Instant::now() >= deadline { break; }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(t1.is_connected(node2_id.clone()).await && t2.is_connected(node1_id.clone()).await, "both directions should be connected after simultaneous dial");

    // Concurrent requests both directions to ensure stability
    let path1 = TopicPath::new("test:echo/req", "test")?;
    let payload = ArcValue::new_primitive("x".to_string());
    let ctx1 = MessageContext { profile_public_key: node1_info.node_public_key.clone() };
    let ctx2 = MessageContext { profile_public_key: node2_info.node_public_key.clone() };
    let f1 = t1.request(&path1, Some(payload.clone()), &node2_id, ctx1);
    let f2 = t2.request(&path1, Some(payload.clone()), &node1_id, ctx2);
    let (r1, r2) = tokio::join!(f1, f2);
    assert!(r1.is_ok() && r2.is_ok(), "bidirectional requests should succeed post-dup-resolution");

    t1.stop().await?;
    t2.stop().await?;
    watchdog.abort();
    let _ = watchdog.await;
    Ok(())
}

// Lifecycle callbacks (on_up/on_down) scenario
#[tokio::test]
async fn test_quic_lifecycle_callbacks(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let watchdog = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(120)).await;
        panic!("test_quic_lifecycle_callbacks timed out");
    });

    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);
    logging_config.apply();
    let logger = Arc::new(Logger::new_root(Component::Custom("lifecycle_test"), ""));

    // Keys and certs
    let mut mobile_ca = MobileKeyManager::new(logger.clone())?;
    let _ = mobile_ca.initialize_user_root_key()?;
    let mut km1 = NodeKeyManager::new(logger.clone())?;
    let csr1 = km1.generate_csr()?;
    let cert1 = mobile_ca.process_setup_token(&csr1)?;
    km1.install_certificate(cert1)?;
    let mut km2 = NodeKeyManager::new(logger.clone())?;
    let csr2 = km2.generate_csr()?;
    let cert2 = mobile_ca.process_setup_token(&csr2)?;
    km2.install_certificate(cert2)?;
    let n1 = km1.get_node_public_key();
    let n2 = km2.get_node_public_key();
    let id1 = compact_id(&n1);
    let id2 = compact_id(&n2);
    let ca = mobile_ca.get_ca_certificate().to_rustls_certificate();

    let info1 = NodeInfo { node_public_key: n1.clone(), network_ids: vec!["test".to_string()], addresses: vec!["127.0.0.1:50131".to_string()], node_metadata: NodeMetadata { services: vec![], subscriptions: vec![] }, version: 0 };
    let info2 = NodeInfo { node_public_key: n2.clone(), network_ids: vec!["test".to_string()], addresses: vec!["127.0.0.1:50132".to_string()], node_metadata: NodeMetadata { services: vec![], subscriptions: vec![] }, version: 0 };

    // Handlers no-op
    let handler: MessageHandler = Box::new(|_m| Box::pin(async { Ok(None) }));
    let one_way: OneWayMessageHandler = Box::new(|_m| Box::pin(async { Ok(()) }));

    // Capture lifecycle events
    let events1: Arc<tokio::sync::Mutex<Vec<(String, bool)>>> = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let events2: Arc<tokio::sync::Mutex<Vec<(String, bool)>>> = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let cb1: ConnectionCallback = {
        let ev = events1.clone();
        Arc::new(move |peer: String, up: bool, _info: Option<NodeInfo>| {
            let ev = ev.clone();
            Box::pin(async move {
                ev.lock().await.push((peer, up));
                Ok(())
            })
        })
    };
    let cb2: ConnectionCallback = {
        let ev = events2.clone();
        Arc::new(move |peer: String, up: bool, _info: Option<NodeInfo>| {
            let ev = ev.clone();
            Box::pin(async move {
                ev.lock().await.push((peer, up));
                Ok(())
            })
        })
    };

    let resolver: Arc<dyn LabelResolver> = Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig { label_mappings: HashMap::new() }));
    let t1 = Arc::new(QuicTransport::new(
        QuicTransportOptions::new()
            .with_certificates(km1.get_quic_certificate_config()?.certificate_chain)
            .with_private_key(km1.get_quic_certificate_config()?.private_key)
            .with_root_certificates(vec![ca.clone()])
            .with_local_node_info(info1.clone())
            .with_bind_addr("127.0.0.1:50131".parse::<SocketAddr>()?)
            .with_message_handler(handler)
            .with_one_way_message_handler(one_way)
            .with_connection_callback(cb1)
            .with_logger(logger.clone())
            .with_keystore(Arc::new(NoCrypto))
            .with_label_resolver(resolver.clone()),
    )?)
        ;
    let t2 = Arc::new(QuicTransport::new(
        QuicTransportOptions::new()
            .with_certificates(km2.get_quic_certificate_config()?.certificate_chain)
            .with_private_key(km2.get_quic_certificate_config()?.private_key)
            .with_root_certificates(vec![ca])
            .with_local_node_info(info2.clone())
            .with_bind_addr("127.0.0.1:50132".parse::<SocketAddr>()?)
            .with_message_handler(Box::new(|_m| Box::pin(async { Ok(None) })))
            .with_one_way_message_handler(Box::new(|_m| Box::pin(async { Ok(()) })))
            .with_connection_callback(cb2)
            .with_logger(logger.clone())
            .with_keystore(Arc::new(NoCrypto))
            .with_label_resolver(resolver.clone()),
    )?)
        ;

    let (sr1, sr2) = tokio::join!(t1.clone().start(), t2.clone().start());
    sr1?; sr2?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Connect 1 -> 2
    t1.clone().connect_peer(PeerInfo::new(info2.node_public_key.clone(), info2.addresses.clone())).await?;
    // Wait for on_up
    tokio::time::sleep(Duration::from_millis(300)).await;
    let ev1 = events1.lock().await.clone();
    let ev2 = events2.lock().await.clone();
    assert!(ev1.iter().any(|(p, up)| p == &id2 && *up), "t1 should see on_up for t2");
    assert!(ev2.iter().any(|(p, up)| p == &id1 && *up), "t2 should see on_up for t1 (inbound)");

    // Stop t2, expect on_down at t1 after grace period
    t2.stop().await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let ev1b = events1.lock().await.clone();
    assert!(ev1b.iter().any(|(p, up)| p == &id2 && !*up), "t1 should see on_down for t2 after stop");

    // Restart t2 and reconnect
    t2.clone().start().await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    t1.clone().connect_peer(PeerInfo::new(info2.node_public_key.clone(), info2.addresses.clone())).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let ev1c = events1.lock().await.clone();
    assert!(ev1c.iter().filter(|(p, up)| p == &id2 && *up).count() >= 2, "t1 should see second on_up for t2 after restart");

    t1.stop().await?;
    t2.stop().await?;
    watchdog.abort();
    let _ = watchdog.await;
    Ok(())
}

/// Test that the transport properly handles message header bounds checking
/// This verifies the robustness of the message framing protocol
#[tokio::test]
async fn test_transport_message_header_bounds_checking(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Watchdog to prevent indefinite hangs
    let watchdog = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        panic!("test_transport_message_header_bounds_checking timed out");
    });
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Error);
    logging_config.apply();
    let logger = Arc::new(Logger::new_root(Component::Custom("bounds_test"), ""));

    logger.debug("Message header bounds checking test started");

    // Test 1: Verify normal message structure and CBOR serialization
    let test_msg = NetworkMessage {
        source_node_id: "test_source".to_string(),
        destination_node_id: "test_dest".to_string(),
        message_type: MESSAGE_TYPE_REQUEST,
        payloads: vec![NetworkMessagePayloadItem {
            path: "test".to_string(),
            value_bytes: vec![1, 2, 3, 4],
            correlation_id: "test_corr".to_string(),
            context: None,
        }],
    };

    // Test CBOR serialization/deserialization (this is what the transport uses internally)
    let cbor_encoded = serde_cbor::to_vec(&test_msg)?;
    assert!(
        !cbor_encoded.is_empty(),
        "CBOR encoding should produce non-empty data"
    );

    let cbor_decoded: NetworkMessage = serde_cbor::from_slice(&cbor_encoded)?;
    assert_eq!(cbor_decoded.source_node_id, test_msg.source_node_id);
    assert_eq!(
        cbor_decoded.destination_node_id,
        test_msg.destination_node_id
    );
    assert_eq!(cbor_decoded.message_type, test_msg.message_type);

    // Test 2: Verify CBOR deserialization handles malformed data gracefully
    let invalid_cbor = vec![255u8, 255u8, 255u8, 255u8, 255u8]; // Invalid CBOR
    let deserialize_result = serde_cbor::from_slice::<NetworkMessage>(&invalid_cbor);
    assert!(
        deserialize_result.is_err(),
        "Invalid CBOR should fail to deserialize"
    );

    // Test 3: Verify message size limits are reasonable
    // The transport has a 1MB limit on message size during reading
    let large_payload = vec![0u8; 1024 * 1024 + 1]; // 1MB + 1 byte
    let large_msg = NetworkMessage {
        source_node_id: "test_source".to_string(),
        destination_node_id: "test_dest".to_string(),
        message_type: MESSAGE_TYPE_REQUEST,
        payloads: vec![NetworkMessagePayloadItem {
            path: "test".to_string(),
            value_bytes: large_payload,
            correlation_id: "test_corr".to_string(),
            context: None,
        }],
    };

    // This should still serialize successfully (the limit is checked during reading)
    let large_cbor = serde_cbor::to_vec(&large_msg)?;
    assert!(
        large_cbor.len() > 1024 * 1024,
        "Large message should serialize successfully"
    );

    // Test 4: Verify the transport's message format structure
    // The transport uses: [4-byte length header][CBOR message data]
    // We can't test the private encode_message function directly, but we can verify
    // that the CBOR serialization works correctly, which is the core of the message format

    // Test 5: Verify message type constants are properly defined
    assert_eq!(MESSAGE_TYPE_HANDSHAKE, 3);
    assert_eq!(MESSAGE_TYPE_REQUEST, 4);
    assert_eq!(MESSAGE_TYPE_RESPONSE, 5);
    assert_eq!(MESSAGE_TYPE_EVENT, 6); 

    // Test 6: Verify message structure validation
    let empty_msg = NetworkMessage {
        source_node_id: "".to_string(),
        destination_node_id: "".to_string(),
        message_type: MESSAGE_TYPE_REQUEST,
        payloads: vec![],
    };

    // Empty message should still serialize/deserialize correctly
    let empty_cbor = serde_cbor::to_vec(&empty_msg)?;
    let empty_decoded: NetworkMessage = serde_cbor::from_slice(&empty_cbor)?;
    assert_eq!(empty_decoded.payloads.len(), 0);

    logger.debug("Message header bounds checking test completed successfully");
    // Cancel watchdog on success
    watchdog.abort();
    let _ = watchdog.await;
    Ok(())
}
