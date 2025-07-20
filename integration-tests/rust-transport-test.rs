use runar_common::compact_ids::compact_id;
use runar_common::logging::{Component, Logger};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing_subscriber;

use runar_keys::{MobileKeyManager, NodeKeyManager};
use runar_node::network::discovery::multicast_discovery::PeerInfo;
use runar_node::network::discovery::NodeInfo;
use runar_node::network::transport::{
    quic_transport::{QuicTransport, QuicTransportOptions},
    NetworkError, NetworkMessage, NetworkMessagePayloadItem, NetworkTransport,
};
use runar_node::{ActionMetadata, EventMetadata, ServiceMetadata};
use runar_serializer::traits::{ConfigurableLabelResolver, KeyMappingConfig, LabelResolver};
use runar_serializer::ArcValue;
use std::collections::HashMap;

// Dummy crypto that performs no-op encryption for tests (same as quic_transport_test.rs)
struct NoCrypto;

impl runar_serializer::traits::EnvelopeCrypto for NoCrypto {
    fn encrypt_with_envelope(
        &self,
        data: &[u8],
        _network_id: &str,
        _profile_ids: Vec<String>,
    ) -> runar_keys::Result<runar_keys::mobile::EnvelopeEncryptedData> {
        Ok(runar_keys::mobile::EnvelopeEncryptedData {
            encrypted_data: data.to_vec(),
            network_id: "test-network".to_string(),
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

struct RustTransportTest {
    logger: Arc<Logger>,
    transport: Option<Arc<QuicTransport>>,
    received_messages: Arc<Mutex<Vec<NetworkMessage>>>,
    mobile_ca: MobileKeyManager,
    node_keys_manager: NodeKeyManager,
    bind_addr: String,
    node_id: String,
}

impl RustTransportTest {
    fn new(
        bind_addr: String,
        node_id: String,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let logger = Arc::new(Logger::new_root(Component::Network, "rust-transport-test"));

        Ok(Self {
            logger,
            transport: None,
            received_messages: Arc::new(Mutex::new(Vec::new())),
            mobile_ca: MobileKeyManager::new(logger.clone())?,
            node_keys_manager: NodeKeyManager::new(logger.clone())?,
            bind_addr,
            node_id,
        })
    }

    async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.logger
            .info("🚀 [RustTest] Starting Rust QUIC transport test");
        self.logger.info(format!(
            "📋 [RustTest] Config: {}, Node: {}",
            self.bind_addr, self.node_id
        ));

        // Initialize certificate infrastructure
        self.setup_certificates().await?;

        // Create transport
        self.create_transport().await?;

        // Start transport
        if let Some(transport) = &self.transport {
            transport.start().await?;
            self.logger
                .info("✅ [RustTest] Transport started successfully");

            // Keep running for external connections
            self.logger
                .info("🔄 [RustTest] Transport running, waiting for connections...");
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

            // Log any received messages
            self.log_received_messages().await;

            // Cleanup
            transport.stop().await?;
            self.logger
                .info("✅ [RustTest] Transport stopped successfully");
        }

        Ok(())
    }

    async fn setup_certificates(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.logger
            .info("🔑 [RustTest] Setting up certificate infrastructure...");

        // Generate user root key and CA key
        let _user_root_public_key = self
            .mobile_ca
            .initialize_user_root_key()
            .expect("Failed to initialize user root key");

        let _user_ca_public_key = self.mobile_ca.get_ca_public_key();

        self.logger
            .info("✅ [RustTest] Created mobile CA with user root and CA keys");

        // Generate node certificate
        self.logger
            .info("🔐 [RustTest] Setting up node certificate...");

        // Generate setup token for node
        let setup_token = self.node_keys_manager.generate_csr()?;

        // Process setup token with mobile CA to get certificate
        let cert_message = self.mobile_ca.process_setup_token(setup_token)?;

        // Install certificate in node key manager
        self.node_keys_manager.install_certificate(cert_message)?;

        self.logger
            .info("✅ [RustTest] Node certificate installed successfully");

        Ok(())
    }

    async fn create_transport(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.logger.info("🔧 [RustTest] Creating QUIC transport...");

        // Get certificate configuration from key manager
        let cert_config = self.node_keys_manager.get_quic_certificate_config()?;

        // Create test node info (following quic_transport_test.rs pattern)
        let node_public_key = self.node_keys_manager.get_node_public_key();
        let node_id = compact_id(&node_public_key);

        let node_info = NodeInfo {
            node_public_key,
            network_ids: vec!["test".to_string()],
            addresses: vec![self.bind_addr.clone()],
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

        self.logger
            .info(format!("🔧 [RustTest] Created node info: {}", node_id));

        // Create transport options (following quic_transport_test.rs pattern)
        let transport_options = QuicTransportOptions::new()
            .with_certificates(cert_config.certificate_chain)
            .with_private_key(cert_config.private_key)
            .with_root_certificates(vec![self
                .mobile_ca
                .get_ca_certificate()
                .to_rustls_certificate()]);

        // Create message handler (following quic_transport_test.rs pattern)
        let received_messages = self.received_messages.clone();
        let logger = self.logger.clone();
        let message_handler =
            Box::new(move |message: NetworkMessage| -> Result<(), NetworkError> {
                let logger = logger.clone();
                let messages = received_messages.clone();
                let msg_type = message.message_type.clone();
                let source = message.source_node_id.clone();

                logger.debug(format!(
                    "📥 [RustTest] Received message: Type={}, From={}, Payloads={}",
                    msg_type,
                    source,
                    message.payloads.len()
                ));

                tokio::spawn(async move {
                    let mut msgs = messages.lock().await;
                    msgs.push(message);
                });

                Ok(())
            });

        // Create empty label resolver (following quic_transport_test.rs pattern)
        let empty_resolver: Arc<dyn LabelResolver> =
            Arc::new(ConfigurableLabelResolver::new(KeyMappingConfig {
                label_mappings: HashMap::new(),
            }));

        // Create dummy crypto (following quic_transport_test.rs pattern)
        let crypto = Arc::new(NoCrypto);

        // Create transport (following quic_transport_test.rs pattern)
        let bind_addr: SocketAddr = self.bind_addr.parse()?;
        let transport = QuicTransport::new(
            node_info,
            bind_addr,
            message_handler,
            transport_options,
            self.logger.clone(),
            crypto,
            empty_resolver,
        )?;

        self.transport = Some(Arc::new(transport));
        self.logger
            .info("✅ [RustTest] Created QUIC transport with proper certificate validation");

        Ok(())
    }

    async fn log_received_messages(&self) {
        let messages = self.received_messages.lock().await;
        self.logger.info(format!(
            "📊 [RustTest] Received {} messages",
            messages.len()
        ));

        for (index, message) in messages.iter().enumerate() {
            self.logger.info(format!(
                "📝 [RustTest] Message {}: {} from {}",
                index + 1,
                message.message_type,
                message.source_node_id
            ));
            if let Some(payload) = message.payloads.first() {
                let payload_str = String::from_utf8_lossy(&payload.value_bytes);
                self.logger
                    .info(format!("📦 [RustTest] Payload: {}", payload_str));
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create test instance with default configuration
    let mut test =
        RustTransportTest::new("0.0.0.0:50001".to_string(), "rust-node-001".to_string())?;

    match test.run().await {
        Ok(()) => {
            println!("✅ Rust transport test completed successfully");
            Ok(())
        }
        Err(e) => {
            eprintln!("❌ Rust transport test failed: {}", e);
            std::process::exit(1);
        }
    }
}
