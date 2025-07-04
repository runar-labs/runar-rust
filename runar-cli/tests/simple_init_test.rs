//! Simple initialization test that focuses on CLI process flow
//!
//! This test verifies the CLI initialization flow without re-testing
//! cryptographic validation that's already covered in the keys crate.

use anyhow::{Context, Result};
use bincode;
use hex;
use qrcode;
use runar_cli::{InitCommand, NodeConfig};
use runar_common::logging::{Component, Logger};
use runar_keys::{
    compact_ids,
    mobile::{MobileKeyManager, NodeCertificateMessage, SetupToken},
    NodeKeyManager,
};
use std::sync::Arc;
use tempfile::TempDir;
use uuid::Uuid;

/// Full setup token that includes server information
#[derive(serde::Serialize, serde::Deserialize)]
struct FullSetupToken {
    setup_token: SetupToken,
    server_address: String,
}

#[tokio::test]
async fn test_simple_initialization_flow() -> Result<()> {
    println!("🚀 Starting simple CLI initialization flow test");

    // Create temporary directory for test
    let temp_dir = TempDir::new().context("Failed to create temp directory")?;
    let config_dir = temp_dir.path().to_path_buf();
    
    println!("📁 Using test config directory: {:?}", config_dir);

    // Create logger
    let logger = Arc::new(Logger::new_root(Component::CLI, "simple-test"));

    // ==========================================
    // STEP 1: Initialize mobile device (simulate mobile app)
    // ==========================================
    println!("\n📱 STEP 1: Initializing mobile device");
    
    let mut mobile = MobileKeyManager::new(logger.clone())
        .context("Failed to create mobile key manager")?;
    
    let user_root_public_key = mobile
        .initialize_user_root_key()
        .context("Failed to initialize user root key")?;
    
    println!("   ✅ Mobile device initialized with user root key: {}", hex::encode(&user_root_public_key));

    // ==========================================
    // STEP 2: Generate node keys and CSR (CLI process)
    // ==========================================
    println!("\n🖥️  STEP 2: Generating node keys and CSR");
    
    let mut node_key_manager = NodeKeyManager::new(logger.clone())
        .context("Failed to create node key manager")?;
    
    let setup_token = node_key_manager
        .generate_csr()
        .context("Failed to generate certificate signing request")?;

    let node_public_key = node_key_manager.get_node_public_key();
    let node_id = compact_ids::compact_node_id(&node_public_key);
    println!("   ✅ Node keys generated:");
    println!("      Node ID: {node_id}");
    println!("      Public Key: {}", hex::encode(&node_public_key));

    // ==========================================
    // STEP 3: Create setup configuration (CLI process)
    // ==========================================
    println!("\n⚙️  STEP 3: Creating setup configuration");
    
    use runar_cli::config::SetupServerConfig;
    
    let setup_config = runar_cli::init::SetupConfig {
        keys_name: format!("runar_{}", Uuid::new_v4()),
        setup_server: SetupServerConfig::default(),
        node_public_key: hex::encode(&node_public_key),
    };
    
    println!("   ✅ Setup configuration created:");
    println!("      Keys Name: {}", setup_config.keys_name);
    println!("      Server: {}", setup_config.get_setup_server_address());

    // ==========================================
    // STEP 4: Generate QR code (CLI process)
    // ==========================================
    println!("\n📱 STEP 4: Generating QR code");
    
    let full_setup_token = FullSetupToken {
        setup_token: setup_token.clone(),
        server_address: setup_config.get_setup_server_address(),
    };

    let setup_token_bytes = bincode::serialize(&full_setup_token)
        .context("Failed to serialize setup token")?;
    
    let qr_code = qrcode::QrCode::new(&setup_token_bytes)
        .context("Failed to generate QR code")?;
    
    let qr_code_string = hex::encode(&setup_token_bytes);
    println!("   ✅ QR code generated:");
    println!("      QR Data: {}...", &qr_code_string[..50]);

    // ==========================================
    // STEP 5: Mobile processes setup token (simulate mobile app)
    // ==========================================
    println!("\n📱 STEP 5: Mobile processing setup token");
    
    let certificate_message = mobile
        .process_setup_token(&setup_token)
        .context("Failed to process setup token")?;
    
    println!("   ✅ Certificate generated:");
    println!("      Subject: {}", certificate_message.node_certificate.subject());
    println!("      Issuer: {}", certificate_message.node_certificate.issuer());

    // ==========================================
    // STEP 6: Install certificate in node (CLI process)
    // ==========================================
    println!("\n🖥️  STEP 6: Installing certificate in node");
    
    node_key_manager
        .install_certificate(certificate_message)
        .context("Failed to install certificate")?;
    
    let certificate_status = node_key_manager.get_certificate_status();
    println!("   ✅ Certificate installed:");
    println!("      Status: {:?}", certificate_status);

    // ==========================================
    // STEP 7: Save configuration and keys (CLI process)
    // ==========================================
    println!("\n💾 STEP 7: Saving configuration and keys");
    
    let final_config = NodeConfig::new(
        node_id,
        format!("network_{}", Uuid::new_v4()),
        hex::encode(&node_public_key),
        setup_config.setup_server,
    );
    
    final_config.save(&config_dir)
        .context("Failed to save configuration")?;
    
    let node_state = node_key_manager.export_state();
    let serialized_state = bincode::serialize(&node_state)
        .context("Failed to serialize node state")?;
    
    let keys_path = config_dir.join("node_keys.bin");
    std::fs::write(&keys_path, &serialized_state)
        .with_context(|| format!("Failed to save node keys to {:?}", keys_path))?;
    
    println!("   ✅ Configuration and keys saved");

    // ==========================================
    // STEP 8: Verify saved configuration (CLI process)
    // ==========================================
    println!("\n🔍 STEP 8: Verifying saved configuration");
    
    let loaded_config = NodeConfig::load(&config_dir)
        .context("Failed to load saved configuration")?;
    
    assert_eq!(loaded_config.node_id, final_config.node_id);
    assert_eq!(loaded_config.node_public_key, final_config.node_public_key);
    
    println!("   ✅ Configuration verification successful");

    // ==========================================
    // STEP 9: Test node startup with saved configuration (CLI process)
    // ==========================================
    println!("\n🚀 STEP 9: Testing node startup with saved configuration");
    
    let loaded_serialized_state = std::fs::read(&keys_path)
        .with_context(|| format!("Failed to read node keys from {:?}", keys_path))?;
    
    let loaded_node_state = bincode::deserialize(&loaded_serialized_state)
        .context("Failed to deserialize node state")?;
    
    let loaded_node_key_manager = NodeKeyManager::from_state(loaded_node_state, logger.clone())
        .context("Failed to create node key manager from saved state")?;
    
    let loaded_certificate_status = loaded_node_key_manager.get_certificate_status();
    println!("   ✅ Node startup test successful");

    // ==========================================
    // FINAL VALIDATION SUMMARY
    // ==========================================
    println!("\n🎉 SIMPLE CLI INITIALIZATION FLOW TEST COMPLETED SUCCESSFULLY!");
    println!("📋 CLI Process Flow Validations:");
    println!("   ✅ Mobile device initialization (simulated)");
    println!("   ✅ Node key generation and CSR creation");
    println!("   ✅ Setup configuration creation");
    println!("   ✅ QR code generation");
    println!("   ✅ Setup token processing (simulated mobile)");
    println!("   ✅ Certificate installation");
    println!("   ✅ Configuration and key storage");
    println!("   ✅ Configuration loading and verification");
    println!("   ✅ Node startup with saved configuration");
    println!();
    println!("📊 CLI Test Statistics:");
    println!("   • Node ID: {node_id}");
    println!("   • Keys Name: {}", setup_config.keys_name);
    println!("   • Configuration: {:?}", config_dir);

    Ok(())
} 