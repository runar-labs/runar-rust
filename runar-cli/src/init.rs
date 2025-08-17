//! Node initialization command
//!
//! This module handles the complete node initialization flow including:
//! - Key generation and CSR creation
//! - QR code generation for mobile setup
//! - Setup server for certificate exchange
//! - Configuration storage

use anyhow::{Context, Result};
use runar_common::compact_ids::compact_id;
use runar_common::logging::Logger;
use runar_keys::mobile::{NetworkKeyMessage, NodeCertificateMessage, SetupToken};
use runar_keys::node::NodeKeyManager;
use runar_macros_common::{log_debug, log_info};
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

use crate::config::{NodeConfig, SetupServerConfig};
use crate::key_store::OsKeyStore;
use crate::setup_server::SetupServer;

pub struct InitCommand {
    config_dir: PathBuf,
    logger: Arc<Logger>,
}

/// Temporary setup configuration for the initialization phase
#[derive(Debug, Clone)]
pub struct SetupConfig {
    /// Unique ID for OS key store (format: runar_{uuid})
    keys_name: String,
    /// Setup server configuration
    setup_server: SetupServerConfig,
    /// Node public key for reference
    node_public_key: String,
}

impl SetupConfig {
    pub fn new(node_public_key: String) -> Self {
        Self {
            keys_name: format!("runar_{}", Uuid::new_v4()),
            setup_server: SetupServerConfig::default(),
            node_public_key,
        }
    }

    pub fn get_setup_server_address(&self) -> String {
        format!("{}:{}", self.setup_server.ip, self.setup_server.port)
    }

    pub fn get_setup_server(&self) -> &SetupServerConfig {
        &self.setup_server
    }

    pub fn get_keys_name(&self) -> &str {
        &self.keys_name
    }
}

impl InitCommand {
    pub fn new(config_dir: PathBuf, logger: Arc<Logger>) -> Self {
        Self { config_dir, logger }
    }

    pub async fn run(&self, force: bool) -> Result<()> {
        log_info!(self.logger, "Starting Runar node initialization...");

        // Check if config already exists
        if NodeConfig::exists(&self.config_dir) && !force {
            println!("Configuration already exists in {:?}", self.config_dir);
            println!("Use --force to re-initialize and discard existing configuration.");
            return Ok(());
        }

        if force {
            log_info!(
                self.logger,
                "Force flag specified - will re-initialize existing configuration"
            );
        }

        // Step 1: Generate node keys and CSR
        log_info!(
            self.logger,
            "Step 1: Generating node keys and certificate signing request..."
        );
        let (mut node_key_manager, _setup_token) = self.generate_node_keys()?;

        // Step 2: Create temporary setup configuration
        log_info!(
            self.logger,
            "Step 2: Creating temporary setup configuration..."
        );
        let setup_config = self.create_setup_config(&node_key_manager)?;

        // Step 3: Generate QR code
        log_info!(
            self.logger,
            "Step 3: Generating QR code for mobile setup..."
        );
        self.generate_qr_code(&_setup_token, &setup_config)?;

        // Step 4: Start setup server and wait for mobile
        log_info!(
            self.logger,
            "Step 4: Starting setup server and waiting for mobile device..."
        );
        let setup_data = self
            .wait_for_mobile_setup(&_setup_token, &setup_config)
            .await?;

        // Step 5: Install certificate
        log_info!(self.logger, "Step 5: Installing certificate...");
        self.install_certificate(&mut node_key_manager, setup_data.certificate_message)?;

        // Step 6: Install network key
        log_info!(self.logger, "Step 6: Installing network key...");
        let network_id = setup_data.network_key_message.network_id.clone();
        self.install_network_key(&mut node_key_manager, setup_data.network_key_message)?;

        // Step 7: Save configuration and keys
        log_info!(self.logger, "Step 7: Saving configuration and keys...");
        self.save_configuration(&setup_config, &node_key_manager, &network_id)?;

        // Step 8: Complete initialization
        log_info!(self.logger, "Step 8: Initialization complete!");
        self.print_success_message(&setup_config);

        Ok(())
    }

    fn generate_node_keys(&self) -> Result<(NodeKeyManager, SetupToken)> {
        // Create node key manager
        let  node_key_manager = NodeKeyManager::new(self.logger.clone())
            .context("Failed to create node key manager")?;

        // Generate CSR
        let _setup_token = node_key_manager
            .generate_csr()
            .context("Failed to generate certificate signing request")?;

        let node_public_key = node_key_manager.get_node_public_key();
        let node_id = compact_id(&node_public_key);

        log_info!(self.logger, "Node identity created: {node_id}");
        log_debug!(
            self.logger,
            "Node public key: {}",
            compact_id(&node_public_key)
        );

        Ok((node_key_manager, _setup_token))
    }

    fn create_setup_config(&self, node_key_manager: &NodeKeyManager) -> Result<SetupConfig> {
        let node_public_key = node_key_manager.get_node_public_key();

        // Create temporary setup config with unique keys name for OS key store
        let setup_config = SetupConfig::new(compact_id(&node_public_key));

        log_info!(
            self.logger,
            "Setup configuration created with keys name: {}",
            setup_config.get_keys_name()
        );
        log_debug!(
            self.logger,
            "Setup server will be available at: {}",
            setup_config.get_setup_server_address()
        );

        Ok(setup_config)
    }

    fn generate_qr_code(
        &self,
        _setup_token: &SetupToken,
        setup_config: &SetupConfig,
    ) -> Result<()> {
        // Create full setup token with server information
        let full_setup_token = FullSetupToken {
            setup_token: _setup_token.clone(),
            server_address: setup_config.get_setup_server_address(),
        };

        // Serialize the full setup token (CBOR)
        let setup_token_bytes =
            serde_cbor::to_vec(&full_setup_token).context("Failed to serialize setup token")?;

        // Generate QR code
        let qr_code =
            qrcode::QrCode::new(&setup_token_bytes).context("Failed to generate QR code")?;

        // Convert to image (PNG) - commented out, not needed for now
        // let qr_image = qr_code.to_image()
        //     .context("Failed to convert QR code to image")?;

        // Save QR code image (optional)
        // let qr_path = self.config_dir.join("setup_qr.png");
        // qr_image.save(&qr_path)
        //     .with_context(|| format!("Failed to save QR code to {:?}", qr_path))?;

        // Display QR code in terminal (if possible)
        self.display_qr_code_in_terminal(&qr_code)?;

        // println!("📱 QR Code saved to: {:?}", qr_path);
        println!("📱 Scan this QR code with your mobile Runar app to complete setup");
        println!(
            "🌐 Setup server will be available at: {}",
            setup_config.get_setup_server_address()
        );

        Ok(())
    }

    fn display_qr_code_in_terminal(&self, qr_code: &qrcode::QrCode) -> Result<()> {
        // Try to display QR code in terminal using ASCII art
        let qr_string = qr_code
            .render::<qrcode::render::unicode::Dense1x2>()
            .build();
        println!("\n📱 QR Code (ASCII):");
        println!("{qr_string}");
        println!();

        Ok(())
    }

    async fn wait_for_mobile_setup(
        &self,
        _setup_token: &SetupToken,
        setup_config: &SetupConfig,
    ) -> Result<crate::setup_server::SetupData> {
        let server = SetupServer::new(
            setup_config.get_setup_server().ip.clone(),
            setup_config.get_setup_server().port,
            self.logger.clone(),
        );

        println!("🔐 Waiting for mobile device to complete setup...");
        println!("📱 Please scan the QR code with your mobile Runar app");

        let setup_data = server
            .wait_for_setup_data()
            .await
            .context("Failed to receive setup data from mobile device")?;

        log_info!(self.logger, "Setup data received from mobile device");

        Ok(setup_data)
    }

    fn install_certificate(
        &self,
        node_key_manager: &mut NodeKeyManager,
        certificate_message: NodeCertificateMessage,
    ) -> Result<()> {
        node_key_manager
            .install_certificate(certificate_message)
            .context("Failed to install certificate")?;

        let status = node_key_manager.get_certificate_status();
        log_info!(self.logger, "Certificate status: {status:?}");

        if status != runar_keys::node::CertificateStatus::Valid {
            return Err(anyhow::anyhow!(
                "Certificate installation failed - status: {:?}",
                status
            ));
        }

        log_info!(self.logger, "Certificate installed successfully");
        Ok(())
    }

    fn install_network_key(
        &self,
        node_key_manager: &mut NodeKeyManager,
        network_key_message: NetworkKeyMessage,
    ) -> Result<()> {
        node_key_manager
            .install_network_key(network_key_message)
            .context("Failed to install network key")?;

        log_info!(self.logger, "Network key installed successfully");
        Ok(())
    }

    fn save_configuration(
        &self,
        setup_config: &SetupConfig,
        node_key_manager: &NodeKeyManager,
        network_id: &str,
    ) -> Result<()> {
        // Get the full public key bytes from the node key manager
        let node_public_key_bytes = node_key_manager.get_node_public_key();

        // Create final NodeConfig with correct formats:
        // - node_id: compact ID (for display/identification)
        // - node_public_key: full hex-encoded public key bytes (for cryptographic operations)
        let node_id = setup_config.node_public_key.clone(); // This is already the compact ID
        let node_public_key_hex = hex::encode(&node_public_key_bytes);

        let final_config = NodeConfig::new(
            node_id,
            network_id.to_string(), // Use actual network ID from mobile
            node_public_key_hex,    // Full hex-encoded public key bytes
            setup_config.setup_server.clone(),
        );

        // Save final configuration file
        final_config
            .save(&self.config_dir)
            .context("Failed to save configuration file")?;

        // Export and save node state to OS key store
        let node_state = node_key_manager.export_state();
        let serialized_state =
            serde_cbor::to_vec(&node_state).context("Failed to serialize node state")?;

        // Store keys securely in OS key store
        let key_store = OsKeyStore::new(self.logger.clone());
        key_store
            .store_node_keys(setup_config.get_keys_name(), &serialized_state)
            .context("Failed to store node keys in OS key store")?;

        log_info!(self.logger, "Configuration saved to {:?}", self.config_dir);
        log_info!(
            self.logger,
            "Node keys stored securely in OS key store: {}",
            setup_config.get_keys_name()
        );
        log_info!(self.logger, "Default network ID: {network_id}");

        Ok(())
    }

    fn print_success_message(&self, setup_config: &SetupConfig) {
        println!("\n🎉 Runar node initialization completed successfully!");
        println!("📋 Setup Information:");
        println!("   • Keys Name: {}", setup_config.keys_name);
        println!("   • Node Public Key: {}", setup_config.node_public_key);
        println!("   • Configuration: {:?}", self.config_dir);
        println!();
        println!("🚀 You can now start the node with: runar start");
        println!("📱 The node is ready to accept connections from mobile devices");
    }
}

/// Full setup token that includes server information
#[derive(serde::Serialize, serde::Deserialize)]
struct FullSetupToken {
    setup_token: SetupToken,
    server_address: String,
}
