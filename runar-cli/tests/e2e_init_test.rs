//! End-to-End CLI Initialization Test
//!
//! This test simulates the complete CLI initialization flow including:
//! - Node key generation and CSR creation
//! - QR code generation and parsing
//! - Mobile device simulation (key generation, certificate signing)
//! - TCP communication for certificate exchange
//! - Configuration and key storage
//!
//! Note: This test focuses on CLI process flow, not cryptographic validation
//! which is already covered in the runar-keys crate tests.

use anyhow::{Context, Result};

use runar_cli::{InitCommand, NodeConfig};
use runar_common::compact_ids::compact_id;
use runar_keys::{
    mobile::{MobileKeyManager, NodeCertificateMessage, SetupToken},
    NodeKeyManager,
};
use runar_logging::{Component, Logger};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Full setup token that includes server information (same as in init.rs)
#[derive(serde::Serialize, serde::Deserialize)]
struct FullSetupToken {
    setup_token: SetupToken,
    server_address: String,
}

/// Mobile device simulator for CLI testing
struct MobileSimulator {
    key_manager: MobileKeyManager,
    logger: Arc<Logger>,
}

impl MobileSimulator {
    fn new(logger: Arc<Logger>) -> Result<Self> {
        let key_manager =
            MobileKeyManager::new(logger.clone()).context("Failed to create mobile key manager")?;

        Ok(Self {
            key_manager,
            logger,
        })
    }

    /// Initialize mobile device with user root key and CA
    fn initialize_mobile(&mut self) -> Result<Vec<u8>> {
        self.logger
            .info("📱 Mobile: Initializing user root key and CA");

        let user_root_public_key = self
            .key_manager
            .initialize_user_root_key()
            .context("Failed to initialize user root key")?;

        self.logger.info(format!(
            "📱 Mobile: User root key initialized: {}",
            compact_id(&user_root_public_key)
        ));

        Ok(user_root_public_key)
    }

    /// Parse QR code and extract setup token
    fn parse_qr_code(&self, qr_code_string: &str) -> Result<FullSetupToken> {
        self.logger.info("📱 Mobile: Parsing QR code");

        let qr_bytes = hex::decode(qr_code_string).context("Failed to decode QR code string")?;

        let full_setup_token: FullSetupToken = serde_cbor::from_slice(&qr_bytes)
            .context("Failed to deserialize setup token from QR code")?;

        self.logger.info(format!(
            "📱 Mobile: Setup token parsed, server: {}",
            full_setup_token.server_address
        ));

        Ok(full_setup_token)
    }

    /// Process setup token and generate certificate
    fn process_setup_token(&mut self, setup_token: &SetupToken) -> Result<NodeCertificateMessage> {
        self.logger
            .info("📱 Mobile: Processing setup token and generating certificate");

        let certificate_message = self
            .key_manager
            .process_setup_token(setup_token)
            .context("Failed to process setup token")?;

        self.logger.info(format!(
            "📱 Mobile: Certificate generated for node: {}",
            certificate_message.node_certificate.subject()
        ));

        Ok(certificate_message)
    }

    /// Generate network data key
    fn generate_network_data_key(&mut self) -> Result<String> {
        self.logger.info("📱 Mobile: Generating network data key");

        let network_public_key = self
            .key_manager
            .generate_network_data_key()
            .context("Failed to generate network data key")?;
        let network_id = compact_id(&network_public_key);

        self.logger.info(format!(
            "📱 Mobile: Network data key generated: {} bytes",
            network_public_key.len()
        ));
        Ok(network_id)
    }

    /// Create network key message for node
    fn create_network_key_message(
        &self,
        network_public_key: &[u8],
        node_public_key: &[u8],
    ) -> Result<runar_keys::mobile::NetworkKeyMessage> {
        self.logger.info(format!(
            "📱 Mobile: Creating network key message for network: {} bytes",
            network_public_key.len()
        ));

        let network_key_message = self
            .key_manager
            .create_network_key_message(network_public_key, node_public_key)
            .context("Failed to create network key message")?;

        Ok(network_key_message)
    }

    /// Send a message with length prefix
    async fn send_message(&self, stream: &TcpStream, message_bytes: &[u8]) -> Result<()> {
        let length_bytes = (message_bytes.len() as u32).to_be_bytes();

        // Write length bytes - handle partial writes
        let mut length_bytes_written = 0;
        while length_bytes_written < length_bytes.len() {
            stream
                .writable()
                .await
                .context("Failed to wait for stream to be writable")?;

            match stream.try_write(&length_bytes[length_bytes_written..]) {
                Ok(0) => {
                    return Err(anyhow::anyhow!(
                        "Connection closed while writing message length"
                    ));
                }
                Ok(n) => {
                    length_bytes_written += n;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Failed to write message length: {e}"));
                }
            }
        }

        // Write message bytes - handle partial writes
        let mut message_bytes_written = 0;
        while message_bytes_written < message_bytes.len() {
            stream
                .writable()
                .await
                .context("Failed to wait for stream to be writable")?;

            match stream.try_write(&message_bytes[message_bytes_written..]) {
                Ok(0) => {
                    return Err(anyhow::anyhow!("Connection closed while writing message"));
                }
                Ok(n) => {
                    message_bytes_written += n;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Failed to write message: {e}"));
                }
            }
        }

        Ok(())
    }

    async fn send_setup_data_to_node(
        &self,
        server_address: &str,
        certificate_message: NodeCertificateMessage,
        network_key_message: runar_keys::mobile::NetworkKeyMessage,
    ) -> Result<()> {
        self.logger.info(format!(
            "📱 Mobile: Connecting to node setup server at {server_address}"
        ));

        // Connect to the node's setup server
        let stream = TcpStream::connect(server_address)
            .await
            .with_context(|| format!("Failed to connect to setup server at {server_address}"))?;

        self.logger.info("📱 Mobile: Connected to setup server");

        // Serialize the certificate message (CBOR)
        let cert_bytes = serde_cbor::to_vec(&certificate_message)
            .context("Failed to serialize certificate message")?;

        // Serialize the network key message (CBOR)
        let network_bytes = serde_cbor::to_vec(&network_key_message)
            .context("Failed to serialize network key message")?;

        // Send the certificate message first
        self.send_message(&stream, &cert_bytes).await?;

        // Send the network key message second
        self.send_message(&stream, &network_bytes).await?;

        self.logger
            .info("📱 Mobile: Certificate and network key messages sent successfully");

        Ok(())
    }
}

#[tokio::test]
async fn test_e2e_cli_initialization() -> Result<()> {
    println!("🚀 Starting comprehensive end-to-end CLI initialization test");

    let temp_dir = TempDir::new().context("Failed to create temp directory")?;
    let config_dir = temp_dir.path().to_path_buf();

    println!("📁 Using test config directory: {config_dir:?}");

    let logger = Arc::new(Logger::new_root(Component::CLI));

    // ==========================================
    // STEP 1: Initialize mobile device (simulate mobile app)
    // ==========================================
    println!("\n📱 STEP 1: Initializing mobile device");

    let mut mobile =
        MobileSimulator::new(logger.clone()).context("Failed to create mobile simulator")?;

    let _user_root_public_key = mobile.initialize_mobile()?;
    println!("   ✅ Mobile device initialized with user root key");

    // ==========================================
    // STEP 2: Generate node keys and CSR (CLI process)
    // ==========================================
    println!("\n🖥️  STEP 2: Creating node and generating keys");

    let _init_cmd = InitCommand::new(config_dir.clone(), logger.clone());

    let (mut node_key_manager, setup_token) = {
        // Create NodeKeyManager with full persistence setup (like the new CLI)
        let key_logger = Arc::new(Logger::new_root(Component::Keys));
        let mut node_key_manager =
            NodeKeyManager::new(key_logger).context("Failed to create node key manager")?;

        // Configure persistence directory
        node_key_manager.set_persistence_dir(config_dir.clone());

        // Register device keystore (OS integration)
        let device_keystore = runar_cli::device_keystore::create_device_keystore_for_platform()
            .context("Failed to create device keystore for platform")?;
        node_key_manager.register_device_keystore(device_keystore);

        // Check if already initialized
        let state_loaded = node_key_manager
            .probe_and_load_state()
            .context("Failed to probe and load state")?;
        if state_loaded {
            return Err(anyhow::anyhow!("Node already initialized"));
        }

        // Generate keys for new node
        node_key_manager
            .generate_keys()
            .context("Failed to generate node keys")?;

        let setup_token = node_key_manager
            .generate_csr()
            .context("Failed to generate certificate signing request")?;

        (node_key_manager, setup_token)
    };

    let node_public_key = node_key_manager.get_node_public_key().unwrap();
    let node_id = compact_id(&node_public_key);
    println!("   ✅ Node keys generated:");
    println!("      Node ID: {node_id}");
    println!("      Public Key: {}", compact_id(&node_public_key));

    // ==========================================
    // STEP 3: Generate QR code (CLI process)
    // ==========================================
    println!("\n📱 STEP 3: Generating QR code");

    let setup_config = { runar_cli::init::SetupConfig::new(compact_id(&node_public_key)) };

    let full_setup_token = FullSetupToken {
        setup_token: setup_token.clone(),
        server_address: setup_config.get_setup_server_address(),
    };

    let setup_token_bytes =
        serde_cbor::to_vec(&full_setup_token).context("Failed to serialize setup token")?;

    let _qr_code = qrcode::QrCode::new(&setup_token_bytes).context("Failed to generate QR code")?;

    let qr_code_string = hex::encode(&setup_token_bytes);
    println!("   ✅ QR code generated:");
    println!("      Server: {}", setup_config.get_setup_server_address());
    println!("      QR Data: {}...", &qr_code_string[..50]);

    // ==========================================
    // STEP 4: Mobile parses QR code (simulate mobile app)
    // ==========================================
    println!("\n📱 STEP 4: Mobile parsing QR code");

    let parsed_setup_token = mobile.parse_qr_code(&qr_code_string)?;
    println!("   ✅ QR code parsed successfully");

    // ==========================================
    // STEP 5: Mobile processes setup token and generates network key (simulate mobile app)
    // ==========================================
    println!("\n📱 STEP 5: Mobile generating certificate and network key");

    let certificate_message = mobile.process_setup_token(&parsed_setup_token.setup_token)?;
    println!("   ✅ Certificate generated:");
    println!(
        "      Subject: {}",
        certificate_message.node_certificate.subject()
    );
    println!(
        "      Issuer: {}",
        certificate_message.node_certificate.issuer()
    );

    // Generate network key for the node
    let network_id = mobile.generate_network_data_key()?;
    // Get the network public key from the mobile key manager
    let network_public_key = mobile
        .key_manager
        .get_network_public_key_by_id(&network_id)?;
    let network_key_message = mobile.create_network_key_message(
        &network_public_key,
        &parsed_setup_token.setup_token.node_agreement_public_key,
    )?;
    println!("   ✅ Network key generated:");
    println!("      Network ID: {network_id}");

    // ==========================================
    // STEP 6: Start setup server (CLI process)
    // ==========================================
    println!("\n🌐 STEP 6: Starting setup server");

    let server = runar_cli::setup_server::SetupServer::new(
        setup_config.get_setup_server().ip.clone(),
        setup_config.get_setup_server().port,
        logger.clone(),
    );

    let server_handle = tokio::spawn(async move { server.wait_for_setup_data().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // ==========================================
    // STEP 7: Mobile sends certificate and network key to node (simulate mobile app)
    // ==========================================
    println!("\n📱 STEP 7: Mobile sending certificate and network key to node");

    mobile
        .send_setup_data_to_node(
            &setup_config.get_setup_server_address(),
            certificate_message.clone(),
            network_key_message.clone(),
        )
        .await?;

    println!("   ✅ Certificate and network key sent to node");

    // ==========================================
    // STEP 8: Node receives and installs certificate and network key (CLI process)
    // ==========================================
    println!("\n🖥️  STEP 8: Node receiving and installing certificate and network key");

    let received_setup_data = timeout(Duration::from_secs(10), server_handle)
        .await
        .context("Timeout waiting for server to receive setup data")?
        .context("Server task failed")?
        .context("Failed to receive setup data")?;

    println!("   ✅ Setup data received by node");

    node_key_manager
        .install_certificate(received_setup_data.certificate_message)
        .context("Failed to install certificate")?;

    node_key_manager
        .install_network_key(received_setup_data.network_key_message)
        .context("Failed to install network key")?;

    let _loaded_certificate_status = node_key_manager.get_certificate_status();
    println!("   ✅ Certificate and network key installed:");
    println!("      Certificate Status: {_loaded_certificate_status:?}");
    println!("      Network ID: {network_id}");

    // ==========================================
    // STEP 9: Save configuration and keys (CLI process)
    // ==========================================
    println!("\n💾 STEP 9: Saving configuration and keys");

    let final_config = {
        NodeConfig::new(
            node_id.clone(),
            network_id.clone(),            // Use actual network ID from mobile
            hex::encode(&node_public_key), // Use full hex-encoded public key bytes
            setup_config.get_setup_server().clone(),
            config_dir.clone(), // Persistence directory
        )
    };

    final_config
        .save(&config_dir)
        .context("Failed to save configuration")?;

    let node_state = node_key_manager.export_state();
    let serialized_state =
        serde_cbor::to_vec(&node_state).context("Failed to serialize node state")?;

    let keys_path = config_dir.join("node_keys.bin");
    std::fs::write(&keys_path, &serialized_state)
        .with_context(|| format!("Failed to save node keys to {keys_path:?}"))?;

    println!("   ✅ Configuration and keys saved:");
    println!("      Config: {:?}", config_dir.join("config.json"));
    println!("      Keys: {keys_path:?}");

    // ==========================================
    // STEP 10: Verify saved configuration (CLI process)
    // ==========================================
    println!("\n🔍 STEP 10: Verifying saved configuration");

    let loaded_config =
        NodeConfig::load(&config_dir).context("Failed to load saved configuration")?;

    assert_eq!(loaded_config.node_id, final_config.node_id);
    assert_eq!(loaded_config.node_public_key, final_config.node_public_key);

    println!("   ✅ Configuration verification successful");

    // ==========================================
    // STEP 11: Test node startup with saved configuration (CLI process)
    // ==========================================
    println!("\n🚀 STEP 11: Testing node startup with saved configuration");

    let loaded_serialized_state = std::fs::read(&keys_path)
        .with_context(|| format!("Failed to read node keys from {keys_path:?}"))?;

    let loaded_node_state = serde_cbor::from_slice(&loaded_serialized_state)
        .context("Failed to deserialize node state")?;

    let loaded_node_key_manager = NodeKeyManager::from_state(loaded_node_state, logger.clone())
        .context("Failed to create node key manager from saved state")?;

    let _loaded_certificate_status = loaded_node_key_manager.get_certificate_status();
    println!("   ✅ Node startup test successful");

    // ==========================================
    // FINAL VALIDATION SUMMARY
    // ==========================================
    println!("\n🎉 COMPREHENSIVE END-TO-END CLI INITIALIZATION TEST COMPLETED SUCCESSFULLY!");
    println!("📋 CLI Process Flow Validations:");
    println!("   ✅ Mobile device initialization (simulated)");
    println!("   ✅ Node key generation and CSR creation");
    println!("   ✅ QR code generation and parsing");
    println!("   ✅ Setup token processing (simulated mobile)");
    println!("   ✅ TCP communication for certificate exchange");
    println!("   ✅ Certificate installation");
    println!("   ✅ Configuration and key storage");
    println!("   ✅ Configuration loading and verification");
    println!("   ✅ Node startup with saved configuration");
    println!();
    println!("📊 CLI Test Statistics:");
    println!("   • Node ID: {node_id}");
    println!("   • Persistence Dir: {config_dir:?}");
    println!("   • Configuration: {config_dir:?}");

    Ok(())
}
