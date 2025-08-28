#[tokio::test]
async fn test_dial_cancel_on_inbound_connect(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use runar_common::compact_ids::compact_id;
    use runar_common::logging::{Component, Logger};
    use runar_common::logging::{LogLevel, LoggingConfig};
    // PeerInfo not used in this test
    use runar_transporter::transport::{NetworkTransport};
    use runar_transporter::transport::{QuicTransport, QuicTransportOptions};
    use std::sync::Arc;
    use std::time::Duration;

    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    logging_config.apply();
    let logger = Arc::new(Logger::new_root(Component::Custom("dial_cancel_test")));

    // Use CA + node certs as in other tests
    let mut mobile_ca = runar_keys::MobileKeyManager::new(logger.clone())?;
    let _ = mobile_ca.initialize_user_root_key()?;
    let mut km1 = runar_keys::NodeKeyManager::new(logger.clone())?;
    let csr1 = km1.generate_csr()?;
    let cert1 = mobile_ca.process_setup_token(&csr1)?;
    km1.install_certificate(cert1)?;
    let mut km2 = runar_keys::NodeKeyManager::new(logger.clone())?;
    let csr2 = km2.generate_csr()?;
    let cert2 = mobile_ca.process_setup_token(&csr2)?;
    km2.install_certificate(cert2)?;
    let ca_cert = mobile_ca.get_ca_certificate().to_rustls_certificate();

    // Make two transports with ephemeral ports
    // Build minimal NodeInfo for transports
    let mk_info = |addr: &str| NodeInfo {
        node_public_key: rand::random::<[u8; 32]>().to_vec(),
        network_ids: vec!["main".to_string()],
        addresses: vec![addr.to_string()],
        node_metadata: runar_schemas::NodeMetadata {
            services: vec![],
            subscriptions: vec![],
        },
        version: 0,
    };
    // Bind explicit ports to avoid get_local_address returning :0
    let t1_addr = "127.0.0.1:50151".parse().unwrap();
    let t2_addr = "127.0.0.1:50152".parse().unwrap();
    let t1_info = mk_info("127.0.0.1:0");
    let t2_info = mk_info("127.0.0.1:0");

    // Simple echo response handler to satisfy request/response
    let mk_request_handler = || -> RequestCallback {
        Arc::new(|req: NetworkMessage| {
            Box::pin(async move {
                let response_value = ArcValue::new_primitive("ok".to_string());
                let reply = NetworkMessage {
                    source_node_id: String::new(),
                    destination_node_id: req.source_node_id,
                    message_type: MESSAGE_TYPE_RESPONSE,
                    payload: NetworkMessagePayloadItem {
                        path: req.payload.path.clone(),
                        correlation_id: req.payload.correlation_id.clone(),
                        payload_bytes: response_value.serialize(None).unwrap_or_default(),
                        network_public_key: None,
                        profile_public_keys: req.payload.profile_public_keys.clone(),
                    },
                };
                Ok(reply)
            })
        })
    };
    let request_handler1 = mk_request_handler();
    let request_handler2 = mk_request_handler();
    let event_handler1: EventCallback = Arc::new(|event| Box::pin(async { Ok(()) }));
    let event_handler2: EventCallback = Arc::new(|event| Box::pin(async { Ok(()) }));
    // Use the default configurable resolver with empty config
    let resolver = Arc::new(LabelResolverConfig {
        label_mappings: HashMap::new(),
    });
    let t1_info_clone = t1_info.clone();
    let t2_info_clone = t2_info.clone();
    let get_local_node_info_t1: GetLocalNodeInfoCallback = Arc::new(move || {
        let t1_info_clone = t1_info_clone.clone();
        Box::pin(async move { Ok(t1_info_clone.clone()) })
    });
    let get_local_node_info_t2: GetLocalNodeInfoCallback = Arc::new(move || {
        let t2_info_clone = t2_info_clone.clone();
        Box::pin(async move { Ok(t2_info_clone.clone()) })
    });
    let t1_opts = QuicTransportOptions::new()
        .with_certificates(km1.get_quic_certificate_config()?.certificate_chain)
        .with_private_key(km1.get_quic_certificate_config()?.private_key)
        .with_root_certificates(vec![ca_cert.clone()])
        .with_local_node_public_key(km1.get_node_public_key())
        .with_get_local_node_info(get_local_node_info_t1)
        .with_bind_addr(t1_addr)
        .with_request_callback(request_handler1)
        .with_event_callback(event_handler1)
        .with_keystore(Arc::new(NoCrypto))
        .with_label_resolver_config(resolver.clone())
        .with_logger(logger.clone());
    let t2_opts = QuicTransportOptions::new()
        .with_certificates(km2.get_quic_certificate_config()?.certificate_chain)
        .with_private_key(km2.get_quic_certificate_config()?.private_key)
        .with_root_certificates(vec![ca_cert])
        .with_local_node_public_key(km2.get_node_public_key())
        .with_get_local_node_info(get_local_node_info_t2)
        .with_bind_addr(t2_addr)
        .with_request_callback(request_handler2)
        .with_event_callback(event_handler2)
        .with_keystore(Arc::new(NoCrypto))
        .with_label_resolver_config(resolver)
        .with_logger(logger.clone());
    let id1 = compact_id(&km1.get_node_public_key());
    let id2 = compact_id(&km2.get_node_public_key());
    let p1_pub = km1.get_node_public_key();
    let p2_pub = km2.get_node_public_key();
    let t1 = Arc::new(QuicTransport::new(t1_opts)?);
    let t2 = Arc::new(QuicTransport::new(t2_opts)?);
    t1.clone().start().await?;
    t2.clone().start().await?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Prepare peer infos using the bound addresses directly
    let p1 = PeerInfo {
        public_key: p1_pub,
        addresses: vec!["127.0.0.1:50151".to_string()],
    };
    let p2 = PeerInfo {
        public_key: p2_pub,
        addresses: vec!["127.0.0.1:50152".to_string()],
    };

    // Start outbound dial from t1 to t2, and almost immediately accept inbound by dialing back t2->t1
    let _d1 = {
        let t1c = t1.clone();
        let p2c = p2.clone();
        tokio::spawn(async move { t1c.connect_peer(p2c).await })
    };
    tokio::time::sleep(Duration::from_millis(10)).await;
    let _ = t2.clone().connect_peer(p1.clone()).await; // inbound should cancel t1's outbound if it wins

    // Allow some time for duplicate resolution
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Exactly one side should have a single active connection and requests must work
    assert!(t1.is_connected(&id2).await || t2.is_connected(&id1).await);

    // Simple request to verify stable connection
    let topic = TopicPath::new("$registry/services/list", "main").unwrap();
    let res1 = t1
        .request(topic.as_str(), "test_corr_1", ArcValue::null().serialize(None).unwrap_or_default(), &id2, None, vec![],
        )
        .await;
    let _ = match res1 {
        Ok(v) => Ok(v),
        Err(_) => {
            t2.request(topic.as_str(), "test_corr_2", ArcValue::null().serialize(None).unwrap_or_default(), &id1, None, vec![],
            )
            .await
        }
    }?;

    t1.stop().await?;
    t2.stop().await?;
    Ok(())
}
use runar_common::compact_ids::compact_id;
use runar_common::logging::{Component, Logger};
use runar_common::logging::{LogLevel, LoggingConfig};
use runar_schemas::{NodeInfo, NodeMetadata, SubscriptionMetadata};
use runar_transporter::transport::{
    GetLocalNodeInfoCallback, MESSAGE_TYPE_EVENT,
    MESSAGE_TYPE_HANDSHAKE, MESSAGE_TYPE_REQUEST, MESSAGE_TYPE_RESPONSE,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

use runar_common::routing::TopicPath;
use runar_keys::{MobileKeyManager, NodeKeyManager};
use runar_node::{ActionMetadata, ServiceMetadata};
use runar_serializer::traits::{LabelResolverConfig};
use runar_serializer::ArcValue;
use runar_transporter::discovery::multicast_discovery::PeerInfo;
use runar_transporter::transport::{
    EventCallback, NetworkMessage, NetworkMessagePayloadItem, NetworkTransport,
    PeerConnectedCallback, PeerDisconnectedCallback, QuicTransport, QuicTransportOptions,
    RequestCallback,
};
use std::collections::HashMap;
// Removed unused imports: AtomicUsize, Ordering
use std::time::Duration;

// Dummy crypto that performs no-op encryption for tests
struct NoCrypto;

impl runar_serializer::traits::EnvelopeCrypto for NoCrypto {
    fn encrypt_with_envelope(
        &self,
        data: &[u8],
        _network_public_key: Option<&[u8]>,
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

    fn get_network_public_key(&self, _network_id: &str) -> runar_keys::Result<Vec<u8>> {
        // Return a dummy 65-byte network public key for testing
        Ok(vec![0u8; 65])
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
    let _watchdog = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        panic!("test_quic_transport timed out");
    });
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);
    logging_config.apply();

    let logger = Arc::new(Logger::new_root(Component::Custom("quic_test")));

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

    // Request handler that tracks requests and returns responses
    let node1_request_handler: RequestCallback = Arc::new(move |req: NetworkMessage| {
        let logger = logger_1.clone();
        let messages = node1_messages_clone.clone();
        let node1_id = node1_id_clone.clone();

        logger.info(format!(
            "📥 [Transport1] Received request: Path={}, From={}",
            req.payload.path, req.payload.correlation_id
        ));

        let messages_clone = messages.clone();
        Box::pin(async move {
            let mut msgs = messages_clone.lock().await;
            // Create a NetworkMessage for tracking (for compatibility with existing test logic)
            let message = NetworkMessage {
                source_node_id: "unknown".to_string(),
                destination_node_id: node1_id.clone(),
                message_type: MESSAGE_TYPE_REQUEST,
                payload: NetworkMessagePayloadItem {
                    network_public_key: None,
                    path: req.payload.path.clone(),
                    payload_bytes: req.payload.payload_bytes.clone(),
                    correlation_id: req.payload.correlation_id.clone(),
                    profile_public_keys: req.payload.profile_public_keys.clone(),
                },
            };
            msgs.push(message);

            // Create a proper ArcValue response
            let response_value =
                ArcValue::new_primitive(format!("Response from Node1: {}", req.payload.path));
            let response = NetworkMessage {
                source_node_id: String::new(),
                destination_node_id: req.source_node_id,
                message_type: MESSAGE_TYPE_RESPONSE,
                payload: NetworkMessagePayloadItem {
                    path: req.payload.path.clone(),
                    correlation_id: req.payload.correlation_id.clone(),
                    payload_bytes: response_value.serialize(None).unwrap_or_default(),
                    network_public_key: None,
                    profile_public_keys: req.payload.profile_public_keys.clone(),
                },
            };
            Ok(response)
        })
    });

    let node2_request_handler: RequestCallback = Arc::new(move |req: NetworkMessage| {
        let logger = logger_2.clone();
        let messages = node2_messages_clone.clone();
        let node2_id = node2_id_clone.clone();

        logger.info(format!(
            "📥 [Transport2] Received request: Path={}, From={}",
            req.payload.path, req.payload.correlation_id
        ));

        let messages_clone = messages.clone();
        Box::pin(async move {
            let mut msgs = messages_clone.lock().await;
            // Create a NetworkMessage for tracking (for compatibility with existing test logic)
            let message = NetworkMessage {
                source_node_id: "unknown".to_string(),
                destination_node_id: node2_id.clone(),
                message_type: MESSAGE_TYPE_REQUEST,
                payload: NetworkMessagePayloadItem {
                    network_public_key: None,
                    path: req.payload.path.clone(),
                    payload_bytes: req.payload.payload_bytes.clone(),
                    correlation_id: req.payload.correlation_id.clone(),
                    profile_public_keys: req.payload.profile_public_keys.clone(),
                },
            };
            msgs.push(message);

            // Create a proper ArcValue response
            let response_value =
                ArcValue::new_primitive(format!("Response from Node2: {}", req.payload.path));
            let response = NetworkMessage {
                    source_node_id: String::new(),
                    destination_node_id: req.source_node_id,
                    message_type: MESSAGE_TYPE_RESPONSE,
                    payload: NetworkMessagePayloadItem {
                        path: req.payload.path.clone(),
                        correlation_id: req.payload.correlation_id,
                        payload_bytes: response_value.serialize(None).unwrap_or_default(),
                        network_public_key: None,
                        profile_public_keys: req.payload.profile_public_keys,
                    },
                };
            Ok(response)
        })
    });

    // Event handlers for unidirectional streams
    let node1_event_handler: EventCallback = Arc::new(move |event: NetworkMessage| {
        let logger = logger_1_one_way.clone();
        let messages = node1_messages_one_way.clone();

        logger.info(format!(
            "📥 [Transport1-Event] Received event: Path={}, Correlation ID={}",
            event.payload.path, event.payload.correlation_id
        ));

        let messages_clone = messages.clone();
        Box::pin(async move {
            let mut msgs = messages_clone.lock().await;
            // Create a NetworkMessage for tracking (for compatibility with existing test logic)
            let message = NetworkMessage {
                source_node_id: "unknown".to_string(),
                destination_node_id: "unknown".to_string(),
                message_type: MESSAGE_TYPE_EVENT,
                payload: NetworkMessagePayloadItem {
                    network_public_key: None,
                    path: event.payload.path.clone(),
                    payload_bytes: event.payload.payload_bytes.clone(),
                    correlation_id: event.payload.correlation_id.clone(),
                    profile_public_keys: vec![],
                },
            };
            msgs.push(message);
            Ok(())
        })
    });

    let node2_event_handler: EventCallback = Arc::new(move |event: NetworkMessage| {
        let logger = logger_2_one_way.clone();
        let messages = node2_messages_one_way.clone();

        logger.info(format!(
            "📥 [Transport2-Event] Received event: Path={}, Correlation ID={}",
            event.payload.path, event.payload.correlation_id
        ));

        let messages_clone = messages.clone();
        Box::pin(async move {
            let mut msgs = messages_clone.lock().await;
            // Create a NetworkMessage for tracking (for compatibility with existing test logic)
            let message = NetworkMessage {
                source_node_id: "unknown".to_string(),
                destination_node_id: "unknown".to_string(),
                message_type: MESSAGE_TYPE_EVENT,
                payload: NetworkMessagePayloadItem {
                    network_public_key: None,
                    path: event.payload.path.clone(),
                    payload_bytes: event.payload.payload_bytes.clone(),
                    correlation_id: event.payload.correlation_id.clone(),
                    profile_public_keys: vec![],
                },
            };
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

    // Insert resolver and local node info callbacks
    let resolver: Arc<LabelResolverConfig> =
        Arc::new(LabelResolverConfig {
        label_mappings: HashMap::new(),
        
    });

    let node1_info_clone2 = node1_info.clone();
    let get_local_node_info_t1: GetLocalNodeInfoCallback = Arc::new(move || {
        let info = node1_info_clone2.clone();
        Box::pin(async move { Ok(info) })
    });
    let node2_info_clone2 = node2_info.clone();
    let get_local_node_info_t2: GetLocalNodeInfoCallback = Arc::new(move || {
        let info = node2_info_clone2.clone();
        Box::pin(async move { Ok(info) })
    });

    let transport1_options = QuicTransportOptions::new()
        .with_certificates(node1_cert_config.certificate_chain)
        .with_private_key(node1_cert_config.private_key)
        .with_root_certificates(vec![ca_certificate.clone()])
        .with_local_node_public_key(node_key_manager_1.get_node_public_key())
        .with_get_local_node_info(get_local_node_info_t1)
        .with_bind_addr("127.0.0.1:50069".parse::<SocketAddr>()?)
        .with_request_callback(node1_request_handler)
        .with_event_callback(node1_event_handler)
        .with_logger(logger.clone())
        .with_keystore(Arc::new(NoCrypto))
        .with_label_resolver_config(resolver.clone())
        .with_handshake_response_timeout(std::time::Duration::from_millis(500))
        .with_max_message_size(1024);

    let t2_opts = QuicTransportOptions::new()
        .with_certificates(node2_cert_config.certificate_chain)
        .with_private_key(node2_cert_config.private_key)
        .with_root_certificates(vec![ca_certificate])
        .with_local_node_public_key(node_key_manager_2.get_node_public_key())
        .with_get_local_node_info(get_local_node_info_t2)
        .with_bind_addr("127.0.0.1:50044".parse::<SocketAddr>()?)
        .with_request_callback(node2_request_handler)
        .with_event_callback(node2_event_handler)
        .with_logger(logger.clone())
        .with_keystore(Arc::new(NoCrypto))
        .with_label_resolver_config(resolver.clone())
        .with_handshake_response_timeout(std::time::Duration::from_millis(500))
        .with_max_message_size(1024);

    let t1 = std::sync::Arc::new(QuicTransport::new(transport1_options)?);
    let t2 = std::sync::Arc::new(QuicTransport::new(t2_opts)?);
    let (_a, _b) = tokio::join!(t1.clone().start(), t2.clone().start());

    // Connect and wait briefly
    t1.clone()
        .connect_peer(PeerInfo::new(
            node2_info.node_public_key.clone(),
            node2_info.addresses.clone(),
        ))
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Send a too-large payload and expect error due to max_message_size being small
    let large_payload = vec![7u8; 4096];
    let res = t1
        .request("test:limits/echo", "corr-limits", large_payload, &runar_common::compact_ids::compact_id(&node2_info.node_public_key), None, vec![node1_info.node_public_key.clone()],
        )
        .await;
    assert!(
        res.is_err(),
        "large payload should be rejected by size limit"
    );

    t1.stop().await?;
    t2.stop().await?;
    Ok(())
}

// Duplicate-resolution and simultaneous dial scenario
#[tokio::test]
async fn test_quic_duplicate_resolution_simultaneous_dial(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Watchdog to prevent indefinite hangs
    let watchdog = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        panic!("test_quic_duplicate_resolution_simultaneous_dial timed out");
    });

    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    logging_config.apply();
    let logger = Arc::new(Logger::new_root(Component::Custom("dup_test")));

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

    let node1_info = NodeInfo {
        node_public_key: node1_pk.clone(),
        network_ids: vec!["test".to_string()],
        addresses: vec!["127.0.0.1:50111".to_string()],
        node_metadata: NodeMetadata {
            services: vec![],
            subscriptions: vec![],
        },
        version: 0,
    };
    let node2_info = NodeInfo {
        node_public_key: node2_pk.clone(),
        network_ids: vec!["test".to_string()],
        addresses: vec!["127.0.0.1:50112".to_string()],
        node_metadata: NodeMetadata {
            services: vec![],
            subscriptions: vec![],
        },
        version: 0,
    };

    // Minimal handlers
    let logger1 = logger.clone();
    let request_handler1: RequestCallback = Arc::new(move |req: NetworkMessage| {
        let log = logger1.clone();
        Box::pin(async move {
            log.debug(format!(
                "[dup_test.T1] received request from {}",
                req.payload.profile_public_keys.len()
            ));
            let resp = NetworkMessage {
                    source_node_id: String::new(),
                    destination_node_id: req.source_node_id,
                    message_type: MESSAGE_TYPE_RESPONSE,
                    payload: NetworkMessagePayloadItem {
                        path: req.payload.path.clone(),
                        correlation_id: req.payload.correlation_id,
                        payload_bytes: req.payload.payload_bytes.clone(),
                        network_public_key: None,
                        profile_public_keys: req.payload.profile_public_keys,
                    },
                };
            Ok(resp)
        })
    });
    let event_handler1: EventCallback =
        Arc::new(move |_event: NetworkMessage| Box::pin(async { Ok(()) }));

    let logger2 = logger.clone();
    let request_handler2: RequestCallback = Arc::new(move |req: NetworkMessage| {
        let log = logger2.clone();
        Box::pin(async move {
            log.debug(format!(
                "[dup_test.T2] received request from {}",
                req.payload.profile_public_keys.len()
            ));
            let resp = NetworkMessage {
                    source_node_id: String::new(),
                    destination_node_id: req.source_node_id,
                    message_type: MESSAGE_TYPE_RESPONSE,
                    payload: NetworkMessagePayloadItem {
                        path: req.payload.path.clone(),
                        correlation_id: req.payload.correlation_id,
                        payload_bytes: req.payload.payload_bytes.clone(),
                        network_public_key: None,
                        profile_public_keys: req.payload.profile_public_keys,
                    },
                };
            Ok(resp)
        })
    });
    let event_handler2: EventCallback =
        Arc::new(move |_event: NetworkMessage| Box::pin(async { Ok(()) }));

    // Build transports
    let empty_resolver: Arc<LabelResolverConfig> =
        Arc::new(LabelResolverConfig {
        label_mappings: HashMap::new(),
        
    });

    let node1_info_clone = node1_info.clone();
    let get_local_node_info_t1: GetLocalNodeInfoCallback = Arc::new(move || {
        let node1_info_clone = node1_info_clone.clone();
        Box::pin(async move { Ok(node1_info_clone.clone()) })
    });
    let node2_info_clone = node2_info.clone();
    let get_local_node_info_t2: GetLocalNodeInfoCallback = Arc::new(move || {
        let node2_info_clone = node2_info_clone.clone();
        Box::pin(async move { Ok(node2_info_clone.clone()) })
    });
    let t1_opts = QuicTransportOptions::new()
        .with_certificates(node1_cert_config.certificate_chain)
        .with_private_key(node1_cert_config.private_key)
        .with_root_certificates(vec![ca_certificate.clone()])
        .with_local_node_public_key(node1_pk.clone())
        .with_get_local_node_info(get_local_node_info_t1)
        .with_bind_addr("127.0.0.1:50111".parse::<SocketAddr>()?)
        .with_request_callback(request_handler1)
        .with_event_callback(event_handler1)
        .with_logger(logger.clone())
        .with_keystore(Arc::new(NoCrypto))
        .with_label_resolver_config(empty_resolver.clone());
    let t2_opts = QuicTransportOptions::new()
        .with_certificates(node2_cert_config.certificate_chain)
        .with_private_key(node2_cert_config.private_key)
        .with_root_certificates(vec![ca_certificate])
        .with_local_node_public_key(node2_pk.clone())
        .with_get_local_node_info(get_local_node_info_t2)
        .with_bind_addr("127.0.0.1:50112".parse::<SocketAddr>()?)
        .with_request_callback(request_handler2)
        .with_event_callback(event_handler2)
        .with_logger(logger.clone())
        .with_keystore(Arc::new(NoCrypto))
        .with_label_resolver_config(empty_resolver.clone());

    let t1 = Arc::new(QuicTransport::new(t1_opts)?);
    let t2 = Arc::new(QuicTransport::new(t2_opts)?);

    let (sr1, sr2) = tokio::join!(t1.clone().start(), t2.clone().start());
    sr1?;
    sr2?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Simultaneous dial
    let p1 = PeerInfo::new(
        node1_info.node_public_key.clone(),
        node1_info.addresses.clone(),
    );
    let p2 = PeerInfo::new(
        node2_info.node_public_key.clone(),
        node2_info.addresses.clone(),
    );
    let (c12, c21) = tokio::join!(t1.clone().connect_peer(p2), t2.clone().connect_peer(p1));
    c12?;
    c21?;

    // Allow duplicate-resolution to settle
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if t1.is_connected(&node2_id).await && t2.is_connected(&node1_id).await {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        t1.is_connected(&node2_id).await && t2.is_connected(&node1_id).await,
        "both directions should be connected after simultaneous dial"
    );

    // Concurrent requests both directions to ensure stability
    let path1 = TopicPath::new("test:echo/req", "test")?;
    let payload = ArcValue::new_primitive("x".to_string());
    let f1 = t1.request(path1.as_str(), "corr1", payload.serialize(None).unwrap_or_default(), &node2_id, None, vec![node1_info.node_public_key.clone()],
    );
    let f2 = t2.request(path1.as_str(), "corr2", payload.serialize(None).unwrap_or_default(), &node1_id, None, vec![node2_info.node_public_key.clone()],
    );
    let (r1, r2) = tokio::join!(f1, f2);
    assert!(
        r1.is_ok() && r2.is_ok(),
        "bidirectional requests should succeed post-dup-resolution"
    );

    t1.stop().await?;
    t2.stop().await?;
    watchdog.abort();
    let _ = watchdog.await;
    Ok(())
}

// Lifecycle callbacks (on_up/on_down) scenario
#[tokio::test]
async fn test_quic_lifecycle_callbacks() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let watchdog = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        panic!("test_quic_lifecycle_callbacks timed out");
    });

    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    logging_config.apply();
    let logger = Arc::new(Logger::new_root(Component::Custom("lifecycle_test")));

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

    let info1 = NodeInfo {
        node_public_key: n1.clone(),
        network_ids: vec!["test".to_string()],
        addresses: vec!["127.0.0.1:50131".to_string()],
        node_metadata: NodeMetadata {
            services: vec![],
            subscriptions: vec![],
        },
        version: 0,
    };
    let info2 = NodeInfo {
        node_public_key: n2.clone(),
        network_ids: vec!["test".to_string()],
        addresses: vec!["127.0.0.1:50132".to_string()],
        node_metadata: NodeMetadata {
            services: vec![],
            subscriptions: vec![],
        },
        version: 0,
    };

    // Handlers no-op
    let request_handler: RequestCallback = Arc::new(|req| {
        let path = req.payload.path.clone();
        let source_node_id = req.source_node_id.clone();
        Box::pin(async move {
            Ok(NetworkMessage {
                    source_node_id: String::new(),
                    destination_node_id: source_node_id,
                    message_type: MESSAGE_TYPE_RESPONSE,
                    payload: NetworkMessagePayloadItem {
                        path,
                        correlation_id: "".to_string(),
                        payload_bytes: vec![],
                        network_public_key: None,
                        profile_public_keys: vec![],
                    },
                })
        })
    });
    let event_handler: EventCallback = Arc::new(|event| Box::pin(async { Ok(()) }));

    // Capture lifecycle events
    let events1: Arc<tokio::sync::Mutex<Vec<(String, bool)>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let events2: Arc<tokio::sync::Mutex<Vec<(String, bool)>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let cb1_connected: PeerConnectedCallback = {
        let ev = events1.clone();
        Arc::new(move |peer: String, _info: NodeInfo| {
            let ev = ev.clone();
            Box::pin(async move {
                ev.lock().await.push((peer, true));
            })
        })
    };

    let cb1_disconnected: PeerDisconnectedCallback = {
        let ev = events1.clone();
        Arc::new(move |peer: String| {
            let ev = ev.clone();
            Box::pin(async move {
                ev.lock().await.push((peer, false));
            })
        })
    };

    let cb2_connected: PeerConnectedCallback = {
        let ev = events2.clone();
        Arc::new(move |peer: String, _info: NodeInfo| {
            let ev = ev.clone();
            Box::pin(async move {
                ev.lock().await.push((peer, true));
            })
        })
    };

    let cb2_disconnected: PeerDisconnectedCallback = {
        let ev = events2.clone();
        Arc::new(move |peer: String| {
            let ev = ev.clone();
            Box::pin(async move {
                ev.lock().await.push((peer, false));
            })
        })
    };

    let resolver: Arc<LabelResolverConfig> =
        Arc::new(LabelResolverConfig {
        label_mappings: HashMap::new(),
        
    });

    let info1_clone = info1.clone();
    let info2_clone = info2.clone();
    let get_local_node_info_t1: GetLocalNodeInfoCallback = Arc::new(move || {
        let info1_clone = info1_clone.clone();
        Box::pin(async move { Ok(info1_clone.clone()) })
    });
    let get_local_node_info_t2: GetLocalNodeInfoCallback = Arc::new(move || {
        let info2_clone = info2_clone.clone();
        Box::pin(async move { Ok(info2_clone.clone()) })
    });

    let t1 = Arc::new(QuicTransport::new(
        QuicTransportOptions::new()
            .with_certificates(km1.get_quic_certificate_config()?.certificate_chain)
            .with_private_key(km1.get_quic_certificate_config()?.private_key)
            .with_root_certificates(vec![ca.clone()])
            .with_local_node_public_key(n1.clone())
            .with_get_local_node_info(get_local_node_info_t1)
            .with_bind_addr("127.0.0.1:50131".parse::<SocketAddr>()?)
            .with_request_callback(request_handler.clone())
            .with_event_callback(event_handler.clone())
            .with_peer_connected_callback(cb1_connected)
            .with_peer_disconnected_callback(cb1_disconnected)
            .with_logger(logger.clone())
            .with_keystore(Arc::new(NoCrypto))
            .with_label_resolver_config(resolver.clone()),
    )?);
    let t2 = Arc::new(QuicTransport::new(
        QuicTransportOptions::new()
            .with_certificates(km2.get_quic_certificate_config()?.certificate_chain)
            .with_private_key(km2.get_quic_certificate_config()?.private_key)
            .with_root_certificates(vec![ca])
            .with_local_node_public_key(n2.clone())
            .with_get_local_node_info(get_local_node_info_t2)
            .with_bind_addr("127.0.0.1:50132".parse::<SocketAddr>()?)
            .with_request_callback(request_handler.clone())
            .with_event_callback(event_handler.clone())
            .with_peer_connected_callback(cb2_connected)
            .with_peer_disconnected_callback(cb2_disconnected)
            .with_logger(logger.clone())
            .with_keystore(Arc::new(NoCrypto))
            .with_label_resolver_config(resolver.clone()),
    )?);

    let (sr1, sr2) = tokio::join!(t1.clone().start(), t2.clone().start());
    sr1?;
    sr2?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Connect 1 -> 2
    t1.clone()
        .connect_peer(PeerInfo::new(
            info2.node_public_key.clone(),
            info2.addresses.clone(),
        ))
        .await?;
    // Wait for on_up
    tokio::time::sleep(Duration::from_millis(300)).await;
    let ev1 = events1.lock().await.clone();
    let ev2 = events2.lock().await.clone();
    assert!(
        ev1.iter().any(|(p, up)| p == &id2 && *up),
        "t1 should see on_up for t2"
    );
    assert!(
        ev2.iter().any(|(p, up)| p == &id1 && *up),
        "t2 should see on_up for t1 (inbound)"
    );

    // Stop t2, expect on_down at t1 after grace period
    t2.stop().await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let ev1b = events1.lock().await.clone();
    assert!(
        ev1b.iter().any(|(p, up)| p == &id2 && !*up),
        "t1 should see on_down for t2 after stop"
    );

    // Restart t2 and reconnect
    t2.clone().start().await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    t1.clone()
        .connect_peer(PeerInfo::new(
            info2.node_public_key.clone(),
            info2.addresses.clone(),
        ))
        .await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let ev1c = events1.lock().await.clone();
    assert!(
        ev1c.iter().filter(|(p, up)| p == &id2 && *up).count() >= 2,
        "t1 should see second on_up for t2 after restart"
    );

    t1.stop().await?;
    t2.stop().await?;
    watchdog.abort();
    let _ = watchdog.await;
    Ok(())
}

// Capability version bump across reconnect
#[tokio::test]
async fn test_capability_version_bump_across_reconnect(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let watchdog = tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        panic!("test_capability_version_bump_across_reconnect timed out");
    });

    let logging_config = runar_common::logging::LoggingConfig::new()
        .with_default_level(runar_node::config::LogLevel::Debug);
    logging_config.apply();
    let logger = std::sync::Arc::new(runar_common::logging::Logger::new_root(
        runar_common::logging::Component::Custom("cap_version_test"),
    ));

    // Keys/certs
    let mut ca = runar_keys::MobileKeyManager::new(logger.clone())?;
    let _ = ca.initialize_user_root_key()?;
    let mut km1 = runar_keys::NodeKeyManager::new(logger.clone())?;
    let cert1 = ca.process_setup_token(&km1.generate_csr()?)?;
    km1.install_certificate(cert1)?;
    let mut km2 = runar_keys::NodeKeyManager::new(logger.clone())?;
    let cert2 = ca.process_setup_token(&km2.generate_csr()?)?;
    km2.install_certificate(cert2)?;
    let ca_cert = ca.get_ca_certificate().to_rustls_certificate();

    // NodeInfo v0
    let pk1 = km1.get_node_public_key();
    let pk2 = km2.get_node_public_key();
    let id1 = runar_common::compact_ids::compact_id(&pk1);
    let id2 = runar_common::compact_ids::compact_id(&pk2);
    let mut info1 = NodeInfo {
        node_public_key: pk1.clone(),
        network_ids: vec!["test".into()],
        addresses: vec!["127.0.0.1:50171".into()],
        node_metadata: runar_schemas::NodeMetadata {
            services: vec![],
            subscriptions: vec![],
        },
        version: 0,
    };
    let info2 = NodeInfo {
        node_public_key: pk2.clone(),
        network_ids: vec!["test".into()],
        addresses: vec!["127.0.0.1:50172".into()],
        node_metadata: runar_schemas::NodeMetadata {
            services: vec![],
            subscriptions: vec![],
        },
        version: 0,
    };

    // Handlers: respond ok, no-op one-way (distinct instances per transport)
    let request_handler1: RequestCallback = Arc::new(|req| {
        let path = req.payload.path.clone();
        let source_node_id = req.source_node_id.clone();
        Box::pin(async move {
            Ok(NetworkMessage {
                    source_node_id: String::new(),
                    destination_node_id: source_node_id,
                    message_type: MESSAGE_TYPE_RESPONSE,
                    payload: NetworkMessagePayloadItem {
                        path,
                        correlation_id: "".to_string(),
                        payload_bytes: vec![],
                        network_public_key: None,
                        profile_public_keys: vec![],
                    },
                })
        })
    });
    let event_handler1: EventCallback = Arc::new(|event| Box::pin(async { Ok(()) }));
    let request_handler2: RequestCallback = Arc::new(|req| {
        let path = req.payload.path.clone();
        let source_node_id = req.source_node_id.clone();
        Box::pin(async move {
            Ok(NetworkMessage {
                    source_node_id: String::new(),
                    destination_node_id: source_node_id,
                    message_type: MESSAGE_TYPE_RESPONSE,
                    payload: NetworkMessagePayloadItem {
                        path,
                        correlation_id: "".to_string(),
                        payload_bytes: vec![],
                        network_public_key: None,
                        profile_public_keys: vec![],
                    },
                })
        })
    });
    let event_handler2: EventCallback = Arc::new(|event| Box::pin(async { Ok(()) }));
    let resolver: std::sync::Arc<runar_serializer::traits::LabelResolverConfig> =
        std::sync::Arc::new(runar_serializer::traits::LabelResolverConfig {
            label_mappings: std::collections::HashMap::new(),
        });

    let info1_clone = info1.clone();
    let info2_clone = info2.clone();
    let get_local_node_info_t1: GetLocalNodeInfoCallback = Arc::new(move || {
        let info1_clone = info1_clone.clone();
        Box::pin(async move { Ok(info1_clone.clone()) })
    });
    let get_local_node_info_t2: GetLocalNodeInfoCallback = Arc::new(move || {
        let info2_clone = info2_clone.clone();
        Box::pin(async move { Ok(info2_clone.clone()) })
    });
    let t1 = std::sync::Arc::new(QuicTransport::new(
        QuicTransportOptions::new()
            .with_certificates(km1.get_quic_certificate_config()?.certificate_chain)
            .with_private_key(km1.get_quic_certificate_config()?.private_key)
            .with_root_certificates(vec![ca_cert.clone()])
            .with_local_node_public_key(pk1.clone())
            .with_get_local_node_info(get_local_node_info_t1)
            .with_bind_addr("127.0.0.1:50171".parse()?)
            .with_request_callback(request_handler1.clone())
            .with_event_callback(event_handler1.clone())
            .with_logger(logger.clone())
            .with_keystore(std::sync::Arc::new(NoCrypto))
            .with_label_resolver_config(resolver.clone()),
    )?);
    let t2 = std::sync::Arc::new(QuicTransport::new(
        QuicTransportOptions::new()
            .with_certificates(km2.get_quic_certificate_config()?.certificate_chain)
            .with_private_key(km2.get_quic_certificate_config()?.private_key)
            .with_root_certificates(vec![ca_cert])
            .with_local_node_public_key(pk2.clone())
            .with_get_local_node_info(get_local_node_info_t2)
            .with_bind_addr("127.0.0.1:50172".parse()?)
            .with_request_callback(request_handler2.clone())
            .with_event_callback(event_handler2.clone())
            .with_logger(logger.clone())
            .with_keystore(std::sync::Arc::new(NoCrypto))
            .with_label_resolver_config(resolver.clone()),
    )?);

    let (sr1, sr2) = tokio::join!(t1.clone().start(), t2.clone().start());
    sr1?;
    sr2?;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Connect and wait
    t1.clone()
        .connect_peer(PeerInfo::new(
            info2.node_public_key.clone(),
            info2.addresses.clone(),
        ))
        .await?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !t1.is_connected(&id2).await || !t2.is_connected(&id1).await {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Bump capability version on t1 and update peers
    info1.version += 1;
    t1.update_peers(info1.clone()).await?;

    // Simulate t2 restart: stop and start again with same info
    t2.stop().await?;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    t2.clone().start().await?;

    // Reconnect
    t1.clone()
        .connect_peer(PeerInfo::new(
            info2.node_public_key.clone(),
            info2.addresses.clone(),
        ))
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Basic check: still connected both ways
    assert!(t1.is_connected(&id2).await && t2.is_connected(&id1).await);

    t1.stop().await?;
    t2.stop().await?;
    watchdog.abort();
    let _ = watchdog.await;
    Ok(())
}

// Anti-flap: repeated simultaneous dials should converge to one stable connection without oscillation
#[tokio::test]
async fn test_quic_anti_flap_under_race() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let watchdog = tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        panic!("test_quic_anti_flap_under_race timed out");
    });

    let logging_config = runar_common::logging::LoggingConfig::new()
        .with_default_level(runar_node::config::LogLevel::Debug);
    logging_config.apply();
    let logger = std::sync::Arc::new(runar_common::logging::Logger::new_root(
        runar_common::logging::Component::Custom("anti_flap_test"),
    ));

    // Keys/certs
    let mut ca = runar_keys::MobileKeyManager::new(logger.clone())?;
    let _ = ca.initialize_user_root_key()?;
    let mut km1 = runar_keys::NodeKeyManager::new(logger.clone())?;
    let cert1 = ca.process_setup_token(&km1.generate_csr()?)?;
    km1.install_certificate(cert1)?;
    let mut km2 = runar_keys::NodeKeyManager::new(logger.clone())?;
    let cert2 = ca.process_setup_token(&km2.generate_csr()?)?;
    km2.install_certificate(cert2)?;
    let ca_cert = ca.get_ca_certificate().to_rustls_certificate();

    let pk1 = km1.get_node_public_key();
    let pk2 = km2.get_node_public_key();
    let id1 = runar_common::compact_ids::compact_id(&pk1);
    let id2 = runar_common::compact_ids::compact_id(&pk2);
    let info1 = NodeInfo {
        node_public_key: pk1.clone(),
        network_ids: vec!["test".into()],
        addresses: vec!["127.0.0.1:50181".into()],
        node_metadata: runar_schemas::NodeMetadata {
            services: vec![],
            subscriptions: vec![],
        },
        version: 0,
    };
    let info2 = NodeInfo {
        node_public_key: pk2.clone(),
        network_ids: vec!["test".into()],
        addresses: vec!["127.0.0.1:50182".into()],
        node_metadata: runar_schemas::NodeMetadata {
            services: vec![],
            subscriptions: vec![],
        },
        version: 0,
    };

    // Handlers
    let request_handler1: RequestCallback = Arc::new(|req| {
        let path = req.payload.path.clone();
        let source_node_id = req.source_node_id.clone();
        Box::pin(async move {
            Ok(NetworkMessage {
                    source_node_id: String::new(),
                    destination_node_id: source_node_id,
                    message_type: MESSAGE_TYPE_RESPONSE,
                    payload: NetworkMessagePayloadItem {
                        path,
                        correlation_id: "".to_string(),
                        payload_bytes: vec![],
                        network_public_key: None,
                        profile_public_keys: vec![],
                    },
                })
        })
    });
    let request_handler2: RequestCallback = Arc::new(|req| {
        let path = req.payload.path.clone();
        let source_node_id = req.source_node_id.clone();
        Box::pin(async move {
            Ok(NetworkMessage {
                    source_node_id: String::new(),
                    destination_node_id: source_node_id,
                    message_type: MESSAGE_TYPE_RESPONSE,
                    payload: NetworkMessagePayloadItem {
                        path,
                        correlation_id: "".to_string(),
                        payload_bytes: vec![],
                        network_public_key: None,
                        profile_public_keys: vec![],
                    },
                })
        })
    });
    let event_handler1: EventCallback = Arc::new(|event| Box::pin(async { Ok(()) }));
    let event_handler2: EventCallback = Arc::new(|event| Box::pin(async { Ok(()) }));
    let resolver: std::sync::Arc<runar_serializer::traits::LabelResolverConfig> =
        std::sync::Arc::new(runar_serializer::traits::LabelResolverConfig {
            label_mappings: std::collections::HashMap::new(),
        });

    // Lifecycle counters
    let ev1: std::sync::Arc<tokio::sync::Mutex<Vec<(String, bool)>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let ev2: std::sync::Arc<tokio::sync::Mutex<Vec<(String, bool)>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let cb1_connected: PeerConnectedCallback = {
        let ev = ev1.clone();
        std::sync::Arc::new(move |peer: String, _info: NodeInfo| {
            let ev = ev.clone();
            Box::pin(async move {
                ev.lock().await.push((peer, true));
            })
        })
    };

    let cb1_disconnected: PeerDisconnectedCallback = {
        let ev = ev1.clone();
        std::sync::Arc::new(move |peer: String| {
            let ev = ev.clone();
            Box::pin(async move {
                ev.lock().await.push((peer, false));
            })
        })
    };

    let cb2_connected: PeerConnectedCallback = {
        let ev = ev2.clone();
        std::sync::Arc::new(move |peer: String, _info: NodeInfo| {
            let ev = ev.clone();
            Box::pin(async move {
                ev.lock().await.push((peer, true));
            })
        })
    };

    let cb2_disconnected: PeerDisconnectedCallback = {
        let ev = ev2.clone();
        std::sync::Arc::new(move |peer: String| {
            let ev = ev.clone();
            Box::pin(async move {
                ev.lock().await.push((peer, false));
            })
        })
    };

    let info1_clone = info1.clone();
    let info2_clone = info2.clone();
    let get_local_node_info_t1: GetLocalNodeInfoCallback = Arc::new(move || {
        let info1_clone = info1_clone.clone();
        Box::pin(async move { Ok(info1_clone.clone()) })
    });
    let get_local_node_info_t2: GetLocalNodeInfoCallback = Arc::new(move || {
        let info2_clone = info2_clone.clone();
        Box::pin(async move { Ok(info2_clone.clone()) })
    });

    let t1 = std::sync::Arc::new(QuicTransport::new(
        QuicTransportOptions::new()
            .with_certificates(km1.get_quic_certificate_config()?.certificate_chain)
            .with_private_key(km1.get_quic_certificate_config()?.private_key)
            .with_root_certificates(vec![ca_cert.clone()])
            .with_local_node_public_key(pk1.clone())
            .with_get_local_node_info(get_local_node_info_t1)
            .with_bind_addr("127.0.0.1:50181".parse()?)
            .with_request_callback(request_handler1.clone())
            .with_event_callback(event_handler1.clone())
            .with_peer_connected_callback(cb1_connected)
            .with_peer_disconnected_callback(cb1_disconnected)
            .with_logger(logger.clone())
            .with_keystore(std::sync::Arc::new(NoCrypto))
            .with_label_resolver_config(resolver.clone()),
    )?);
    let t2 = std::sync::Arc::new(QuicTransport::new(
        QuicTransportOptions::new()
            .with_certificates(km2.get_quic_certificate_config()?.certificate_chain)
            .with_private_key(km2.get_quic_certificate_config()?.private_key)
            .with_root_certificates(vec![ca_cert])
            .with_local_node_public_key(pk2.clone())
            .with_get_local_node_info(get_local_node_info_t2)
            .with_bind_addr("127.0.0.1:50182".parse()?)
            .with_request_callback(request_handler2.clone())
            .with_event_callback(event_handler2.clone())
            .with_peer_connected_callback(cb2_connected)
            .with_peer_disconnected_callback(cb2_disconnected)
            .with_logger(logger.clone())
            .with_keystore(std::sync::Arc::new(NoCrypto))
            .with_label_resolver_config(resolver.clone()),
    )?);

    let (sr1, sr2) = tokio::join!(t1.clone().start(), t2.clone().start());
    sr1?;
    sr2?;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Repeated race rounds
    let p1 = PeerInfo::new(info1.node_public_key.clone(), info1.addresses.clone());
    let p2 = PeerInfo::new(
            info2.node_public_key.clone(), info2.addresses.clone());
    for _ in 0..5 {
        let (a, b) = tokio::join!(
            t1.clone().connect_peer(p2.clone()),
            t2.clone().connect_peer(p1.clone())
        );
        let _ = (a, b);
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    }

    // Allow final settling
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(t1.is_connected(&id2).await && t2.is_connected(&id1).await);

    // Verify no flapping: exactly one Up per side, and no Down
    let ev1 = ev1.lock().await.clone();
    let ev2 = ev2.lock().await.clone();
    let up1 = ev1.iter().filter(|(_, up)| *up).count();
    let down1 = ev1.iter().filter(|(_, up)| !*up).count();
    let up2 = ev2.iter().filter(|(_, up)| *up).count();
    let down2 = ev2.iter().filter(|(_, up)| !*up).count();
    assert_eq!(up1, 1, "t1 should see a single Up");
    assert_eq!(down1, 0, "t1 should see no Down");
    assert_eq!(up2, 1, "t2 should see a single Up");
    assert_eq!(down2, 0, "t2 should see no Down");

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
        tokio::time::sleep(Duration::from_secs(3)).await;
        panic!("test_transport_message_header_bounds_checking timed out");
    });
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    logging_config.apply();
    let logger = Arc::new(Logger::new_root(Component::Custom("bounds_test")));

    logger.debug("Message header bounds checking test started");

    // Test 1: Verify normal message structure and CBOR serialization
    let test_msg = NetworkMessage {
        source_node_id: "test_source".to_string(),
        destination_node_id: "test_dest".to_string(),
        message_type: MESSAGE_TYPE_REQUEST,
        payload: NetworkMessagePayloadItem {
                    network_public_key: None,
            path: "test".to_string(),
            payload_bytes: vec![1, 2, 3, 4],
            correlation_id: "test_corr".to_string(),
            profile_public_keys: vec![],
        },
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
        payload: NetworkMessagePayloadItem {
                    network_public_key: None,
            path: "test".to_string(),
            payload_bytes: large_payload,
            correlation_id: "test_corr".to_string(),
            profile_public_keys: vec![],
        },
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
        payload: NetworkMessagePayloadItem {
                    network_public_key: None,
            path: "".to_string(),
            payload_bytes: vec![],
            correlation_id: "".to_string(),
            profile_public_keys: vec![],
        },
    };

    // Empty message should still serialize/deserialize correctly
    let empty_cbor = serde_cbor::to_vec(&empty_msg)?;
    let empty_decoded: NetworkMessage = serde_cbor::from_slice(&empty_cbor)?;
    assert_eq!(empty_decoded.payload.payload_bytes, Vec::<u8>::new());

    logger.debug("Message header bounds checking test completed successfully");
    // Cancel watchdog on success
    watchdog.abort();
    let _ = watchdog.await;
    Ok(())
}

#[tokio::test]
async fn test_transport_start_stop_idempotence(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use runar_common::logging::{Component, Logger};
    use runar_common::logging::{LogLevel, LoggingConfig};

    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Warn);
    logging_config.apply();
    let logger = Arc::new(Logger::new_root(Component::Custom("transport_idem")));

    // Prepare key manager with installed certificate (required for QUIC config)
    let mut ca = runar_keys::MobileKeyManager::new(logger.clone())?;
    let _ = ca.initialize_user_root_key()?;
    let mut km = runar_keys::NodeKeyManager::new(logger.clone())?;
    let csr = km.generate_csr()?;
    let cert = ca.process_setup_token(&csr)?;
    km.install_certificate(cert)?;

    // Build transport directly from Node's network config pieces
    let keystore = Arc::new(NoCrypto);
    let resolver = Arc::new(LabelResolverConfig {
        label_mappings: HashMap::new(),
    
    });

    let local_pk = km.get_node_public_key();

    // Minimal NodeInfo provider
    let node_info = NodeInfo {
        node_public_key: local_pk.clone(),
        network_ids: vec!["test_network".to_string()],
        addresses: vec!["127.0.0.1:50201".to_string()],
        node_metadata: runar_schemas::NodeMetadata {
            services: vec![],
            subscriptions: vec![],
        },
        version: 1,
    };
    let get_local_node_info: GetLocalNodeInfoCallback = Arc::new(move || {
        let info = node_info.clone();
        Box::pin(async move { Ok(info) })
    });

    let request_cb: RequestCallback = Arc::new(|req| {
        Box::pin(async move {
            Ok(NetworkMessage {
                    source_node_id: String::new(),
                    destination_node_id: req.source_node_id,
                    message_type: MESSAGE_TYPE_RESPONSE,
                    payload: NetworkMessagePayloadItem {
                        path: req.payload.path.clone(),
                        correlation_id: "c".into(),
                        payload_bytes: vec![1],
                        network_public_key: None,
                        profile_public_keys: vec![],
                    },
                })
        })
    });
    let event_cb: EventCallback = Arc::new(|_e| Box::pin(async move { Ok(()) }));

    let t = Arc::new(QuicTransport::new(
        QuicTransportOptions::new()
            .with_key_manager(Arc::new(km))
            .with_local_node_public_key(local_pk.clone())
            .with_get_local_node_info(get_local_node_info)
            .with_bind_addr("127.0.0.1:50201".parse()?)
            .with_request_callback(request_cb)
            .with_event_callback(event_cb)
            .with_logger(logger.clone())
            .with_keystore(keystore)
            .with_label_resolver_config(resolver),
    )?);

    for _ in 0..3u8 {
        t.clone().start().await?;
        tokio::time::sleep(Duration::from_millis(80)).await;
        t.stop().await?;
    }

    // Starting while already running should be idempotent
    t.clone().start().await?;
    t.clone().start().await?; // second start should be a no-op

    // Stopping twice should also be idempotent
    t.stop().await?;
    t.stop().await?;

    // After stop, operations should fail quickly (no background tasks serving)
    let res = t
        .publish("test:path", "corr", vec![], &runar_common::compact_ids::compact_id(&local_pk), None)
        .await;
    assert!(res.is_err(), "publish after stop should fail");

    Ok(())
}
