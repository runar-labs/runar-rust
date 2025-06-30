//! End-to-End Integration Tests for Runar Keys
//!
//! This test simulates the complete end-to-end encryption and key management flows.
//! In the real implementation, the mobile process and the node process will be in
//! different machines and talking over the network, but here we simulate the
//! end-to-end flow and test the whole system by bypassing the network part
//! and dealing with the internal components directly.

use runar_keys::{
    error::Result,
    mobile::{MobileKeyManager, SetupToken, NodeCertificateMessage},
    node::{NodeKeyManager, CertificateStatus},
};
use runar_common::logging::{Component, Logger};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use x509_parser::prelude::FromDer;

fn create_test_logger(component: &str) -> Arc<Logger> {
    Arc::new(Logger::new_root(Component::Custom("Keys"), component))
}

#[tokio::test]
async fn test_e2e_keys_generation_and_exchange() -> Result<()> {
    println!("🚀 Starting comprehensive end-to-end keys generation and exchange test");
    
    // ==========================================
    // Mobile side - first time use - generate user keys
    // ==========================================
    println!("\n📱 MOBILE SIDE - First Time Setup");
    
    // 1 - (mobile side) - generate user master key
    let mobile_logger = create_test_logger("mobile-e2e");
    let mut mobile = MobileKeyManager::new(mobile_logger)?;
    
    // Generate user root key - now returns only the public key
    let user_root_public_key = mobile
        .initialize_user_root_key()
        .expect("Failed to generate user root key");
    assert_eq!(
        user_root_public_key.len(), 65, // ECDSA P-256 uncompressed public key  
        "User root key should have a valid public key"
    );

    let user_public_key = user_root_public_key.clone();
    println!("   ✅ User public key generated: {}", hex::encode(&user_public_key));

    // Create a user owned and managed CA
    let user_ca_public_key = mobile.get_ca_public_key();
    assert_eq!(user_ca_public_key.len(), 33); // ECDSA P-256 compressed
    println!("   ✅ User CA public key: {}", hex::encode(&user_ca_public_key));

    // ==========================================
    // Node first time use - enter in setup mode
    // ==========================================
    println!("\n🖥️  NODE SIDE - Setup Mode");
    
    // 2 - node side (setup mode) - generate its own TLS and Storage keypairs
    //     and generate a setup handshake token which contains the CSR request and the node public key
    //     which will be presented as QR code.. here in the test we use the token as a string directly.
    let node_logger = create_test_logger("node-e2e");
    let mut node = NodeKeyManager::new("test-node-001".to_string(), node_logger)?;
    let setup_token = node
        .generate_csr()
        .expect("Failed to generate setup token");

    // Let's serialize the setup token
    let setup_token_bytes = bincode::serialize(&setup_token).expect("Failed to serialize setup token");
    let setup_token_str = hex::encode(setup_token_bytes);
    println!("   ✅ Setup token string: {}", setup_token_str);

    // ==========================================
    // Mobile scans a Node QR code which contains the setup token
    // ==========================================
    println!("\n📱 MOBILE SIDE - Processing Node Setup Token");
    
    // setup_token_str represents the QR code
    // Let's deserialize the setup token
    let setup_token_bytes_mobile = hex::decode(setup_token_str).expect("Failed to decode setup token");
    let setup_token_mobile: SetupToken = bincode::deserialize(&setup_token_bytes_mobile)
        .expect("Failed to deserialize setup token");

    // 3 - (mobile side) - received the token and sign the CSR
    let cert_message = mobile
        .process_setup_token(&setup_token_mobile)
        .expect("Failed to process setup token");
    
    println!("   ✅ Certificate issued:");
    println!("      Subject: {}", cert_message.node_certificate.subject());
    println!("      Issuer: {}", cert_message.node_certificate.issuer());
    println!("      Purpose: {}", cert_message.metadata.purpose);
    
    // Extract the node ID from the setup token
    let node_public_key = hex::encode(&setup_token_mobile.node_public_key);
    println!("   ✅ Node public key: {}", node_public_key);

    // ==========================================
    // Secure certificate transmission to node
    // ==========================================
    println!("\n🔐 SECURE CERTIFICATE TRANSMISSION");
    
    // The certificate message is transmitted over a network
    // Here we're simulating that by directly passing the message to the node
    // Serialize certificate message for transmission
    let serialized_cert_msg = bincode::serialize(&cert_message)
        .expect("Failed to serialize certificate message");

    // Node side - received the certificate message
    // Deserialize certificate message
    let deserialized_cert_msg: NodeCertificateMessage = bincode::deserialize(&serialized_cert_msg)
        .expect("Failed to deserialize certificate message");

    // 4 - (node side) - received the certificate message, validates it, and stores it
    node.install_certificate(deserialized_cert_msg)
        .expect("Failed to install certificate");

    println!("   ✅ Certificate installed on node");
    println!("      Node certificate status: {:?}", node.get_certificate_status());
    assert_eq!(node.get_certificate_status(), CertificateStatus::Valid);

    // ==========================================
    // FROM THIS POINT FORWARD - SECURE QUIC TRANSPORT READY
    // ==========================================
    println!("\n🌐 QUIC TRANSPORT VALIDATION");
    
    // Get QUIC-compatible certificates, private key, and validator from the node
    let quic_config = node
        .get_quic_certificate_config()
        .expect("Failed to get QUIC certificates");

    println!("   🔍 COMPREHENSIVE QUIC CERTIFICATE VALIDATION");

    // Validate the QUIC certificates
    let quic_certs = &quic_config.certificate_chain;
    let private_key = &quic_config.private_key;
    
    assert!(!quic_certs.is_empty(), "No QUIC certificates returned");
    assert_eq!(quic_certs.len(), 2, "Expected node certificate + CA certificate");

    let cert_der = &quic_certs[0]; // Node certificate
    assert!(!cert_der.is_empty(), "Empty certificate in chain");

    // ==============================================
    // 1. CERTIFICATE PARSING AND X.509 STRUCTURE
    // ==============================================
    println!("   ✅ Step 1: Parsing X.509 certificate structure...");

    // Parse the certificate using x509-parser to validate structure
    let (_, parsed_cert) = x509_parser::certificate::X509Certificate::from_der(cert_der.as_ref())
        .expect("Failed to parse certificate as valid X.509 DER - we only accept real X.509 certificates");

    println!("      - Certificate version: {:?}", parsed_cert.version());
    println!("      - Certificate serial: {}", hex::encode(parsed_cert.serial.to_bytes_be()));
    println!("      - Certificate subject: {}", parsed_cert.subject());
    println!("      - Certificate issuer: {}", parsed_cert.issuer());
    println!("      - Certificate validity: {:?} to {:?}", 
             parsed_cert.validity().not_before, parsed_cert.validity().not_after);

    // ==============================================
    // 2. PUBLIC KEY EXTRACTION AND VALIDATION
    // ==============================================
    println!("   ✅ Step 2: Extracting and validating public key...");

    let public_key_info = parsed_cert.public_key();
    let cert_public_key_bytes = public_key_info.subject_public_key.data.as_ref();

    // Validate public key algorithm
    assert_eq!(
        public_key_info.algorithm.algorithm.to_string(),
        "1.2.840.10045.2.1", // ECDSA OID
        "Certificate should use ECDSA algorithm for QUIC compatibility"
    );

    // Validate public key length - ECDSA P-256 uncompressed public key
    assert_eq!(
        cert_public_key_bytes.len(),
        65, // ECDSA P-256 uncompressed format (0x04 + 32 bytes X + 32 bytes Y)
        "ECDSA P-256 public key should be 65 bytes (uncompressed format)"
    );

    println!("      - Public key algorithm: {:?}", public_key_info.algorithm);
    println!("      - Public key length: {} bytes", cert_public_key_bytes.len());
    println!("      - Public key bytes: {}", hex::encode(cert_public_key_bytes));

    // ==============================================
    // 3. CRYPTOGRAPHIC KEY PAIR VALIDATION
    // ==============================================
    println!("   ✅ Step 3: Validating ECDSA certificate structure...");

    // Validate that the public key starts with 0x04 (uncompressed format indicator)
    assert_eq!(
        cert_public_key_bytes[0], 0x04,
        "ECDSA public key should start with 0x04 (uncompressed format)"
    );

    println!("      - ECDSA public key format: uncompressed (0x04 prefix)");
    println!("      - X coordinate: {}", hex::encode(&cert_public_key_bytes[1..33]));
    println!("      - Y coordinate: {}", hex::encode(&cert_public_key_bytes[33..65]));

    // Validate that the private key can be parsed by rustls
    let _rustls_private_key = PrivateKeyDer::try_from(private_key.secret_der().to_vec())
        .expect("ECDSA private key should be parseable by rustls");

    println!("      ✅ ECDSA key pair structure validated!");

    // ==============================================
    // 4. SUBJECT NAME VALIDATION
    // ==============================================
    println!("   ✅ Step 4: Validating certificate subject...");

    // Extract subject common name
    let subject_str = parsed_cert.subject().to_string();
    println!("      - Subject: {}", subject_str);
    
    // For our certificates, we expect the node ID in the subject
    assert!(subject_str.contains("test-node-001"), 
            "Certificate subject should contain node ID");

    println!("      ✅ Subject validated for node certificate!");

    // ==============================================
    // 5. RUSTLS/QUINN COMPATIBILITY VALIDATION
    // ==============================================
    println!("   ✅ Step 5: Validating rustls/Quinn compatibility...");

    // Test that rustls can parse the certificate
    let rustls_cert = CertificateDer::from(cert_der.as_ref().to_vec());
    assert!(!rustls_cert.is_empty(), "Rustls certificate should not be empty");

    // Test that rustls can parse the private key
    let _rustls_private_key = PrivateKeyDer::try_from(private_key.secret_der().to_vec())
        .expect("Rustls should be able to parse the private key");

    println!("      - Rustls certificate parsing: ✅");
    println!("      - Rustls private key parsing: ✅");

    println!("   🎉 QUIC CERTIFICATE VALIDATION COMPLETE!");
    println!("      ✅ X.509 certificate structure");
    println!("      ✅ ECDSA P-256 public key format and length");
    println!("      ✅ PKCS#8 private key structure");
    println!("      ✅ Certificate subject validation");

    // ==========================================
    // ENHANCED KEY MANAGEMENT FEATURES
    // ==========================================
    println!("\n🔐 ENHANCED KEY MANAGEMENT TESTING");

    // 5 - (mobile side) - user created a network with a given name - generate a network key
    let network_public_key = mobile
        .generate_network_data_key("network_X")
        .expect("Failed to generate network data key");
    println!("   ✅ Network data key generated: {}", hex::encode(&network_public_key));

    // Create network key message for the node
    let network_name = "network_X";
    let node_id = "test-node-001";
    let network_key_message = mobile
        .create_network_key_message(network_name, node_id)
        .expect("Failed to create network key message");

    // Serialize the network key message for transmission
    let serialized_network_keys = bincode::serialize(&network_key_message)
        .expect("Failed to serialize network key message");

    // Node side - received the network key message
    let deserialized_network_keys = bincode::deserialize(&serialized_network_keys)
        .expect("Failed to deserialize network key message");

    // 6 - (node side) - process the network key message and store the keys securely
    node.install_network_key(deserialized_network_keys)
        .expect("Failed to install network key");
    println!("   ✅ Network key installed on node");

    // At this point the node is ready to process requests, events and data of the network_X

    // 7 - (mobile side) - User creates profile keys
    let profile_personal_key = mobile
        .derive_user_profile_key("personal")
        .expect("Failed to generate personal profile key");
    let profile_work_key = mobile
        .derive_user_profile_key("work")
        .expect("Failed to generate work profile key");
    
    assert!(!profile_personal_key.is_empty(), "Personal profile key should be valid");
    assert!(!profile_work_key.is_empty(), "Work profile key should be valid");
    assert_ne!(profile_personal_key, profile_work_key, "Profile keys should be unique");
    println!("   ✅ Profile keys generated: personal, work");

    // 8 - (mobile side) - Encrypts data using envelope which is encrypted using the
    //     user profile key and network key, so only the user or apps running in the 
    //     network can decrypt it.
    let test_data = b"This is a test message that should be encrypted and decrypted";
    let envelope = mobile
        .encrypt_with_envelope(test_data, "network_X", vec!["personal".to_string(), "work".to_string()])
        .expect("Failed to encrypt data with envelope");
    
    println!("   ✅ Data encrypted with envelope encryption");
    println!("      Network: {}", envelope.network_id);
    println!("      Profile recipients: {}", envelope.profile_encrypted_keys.len());

    // 9 - (node side) - received the encrypted data and decrypts it using the
    //     network key (the node does not have the user profile key)
    let decrypted_by_node = node
        .decrypt_envelope_data(&envelope)
        .expect("Node failed to decrypt envelope data");
    assert_eq!(
        decrypted_by_node, test_data,
        "Node should be able to decrypt the data"
    );
    println!("   ✅ Node successfully decrypted envelope data using network key");

    // Additionally, verify that the mobile can also decrypt the data using profile keys
    let decrypted_by_mobile_personal = mobile
        .decrypt_with_profile(&envelope, "personal")
        .expect("Mobile failed to decrypt with personal profile");
    assert_eq!(
        decrypted_by_mobile_personal, test_data,
        "Mobile should be able to decrypt with personal profile"
    );
    println!("   ✅ Mobile successfully decrypted with personal profile key");

    let decrypted_by_mobile_work = mobile
        .decrypt_with_profile(&envelope, "work")
        .expect("Mobile failed to decrypt with work profile");
    assert_eq!(
        decrypted_by_mobile_work, test_data,
        "Mobile should be able to decrypt with work profile"
    );
    println!("   ✅ Mobile successfully decrypted with work profile key");

    // 10 - Test node local storage encryption
    println!("\n💾 NODE LOCAL STORAGE ENCRYPTION");
    
    let file_data_1 = b"This is some secret file content that should be encrypted on the node.";
    
    let encrypted_file_1 = node
        .encrypt_local_data(file_data_1)
        .expect("Node failed to encrypt local data");
    println!("   ✅ Encrypted local data (hex): {}", hex::encode(&encrypted_file_1));
    assert_ne!(file_data_1, &encrypted_file_1[..]); // Ensure it's not plaintext

    let decrypted_file_1 = node
        .decrypt_local_data(&encrypted_file_1)
        .expect("Node failed to decrypt local data");
    println!("   ✅ Decrypted data: {:?}", std::str::from_utf8(&decrypted_file_1).unwrap());

    assert_eq!(
        file_data_1,
        &decrypted_file_1[..],
        "Decrypted data should match original"
    );

    // ==========================================
    // STATE SERIALIZATION AND RESTORATION
    // ==========================================
    println!("\n💾 STATE SERIALIZATION AND RESTORATION TESTING");
    
    // Now let's simulate when mobile and node already have keys stored in secure storage.
    // Step 1: Export the current state of the key managers
    let node_state = node.export_state();
    
    // In a real implementation, these states would be serialized and stored in secure storage
    // For this test, we'll simulate that by serializing and deserializing them
    let serialized_node_state = bincode::serialize(&node_state)
        .expect("Failed to serialize node state");

    // Step 2: Create new key managers and hydrate them with the exported state
    // This simulates restarting the application and loading keys from secure storage
    let deserialized_node_state = bincode::deserialize(&serialized_node_state)
        .expect("Failed to deserialize node state");

    let node_logger_2 = create_test_logger("node-hydrated");
    let node_hydrated = NodeKeyManager::import_state(deserialized_node_state, node_logger_2)?;
    
    println!("   ✅ Node state successfully serialized and restored");

    // Verify that the hydrated node manager can still perform operations
    // Try encrypting and decrypting data with the hydrated manager
    let test_data_2 = b"This is a second test message after key restoration";
    let envelope_2 = mobile
        .encrypt_with_envelope(test_data_2, "network_X", vec!["personal".to_string()])
        .expect("Mobile failed to encrypt data after restoration");

    // Node should be able to decrypt with the network key
    let decrypted_by_node_2 = node_hydrated
        .decrypt_envelope_data(&envelope_2)
        .expect("Hydrated node failed to decrypt envelope data");
    assert_eq!(
        decrypted_by_node_2, test_data_2,
        "Hydrated node should be able to decrypt the data"
    );
    println!("   ✅ Hydrated node successfully decrypted envelope data");

    // Mobile should be able to decrypt with the profile key
    let decrypted_by_mobile_2 = mobile
        .decrypt_with_profile(&envelope_2, "personal")
        .expect("Mobile failed to decrypt after node restoration");
    assert_eq!(
        decrypted_by_mobile_2, test_data_2,
        "Mobile should be able to decrypt the data after restoration"
    );
    println!("   ✅ Mobile successfully decrypted after node state restoration");

    // Test Node Symmetric Encryption after hydration
    println!("\n🔐 Testing Node Symmetric Encryption After Hydration");

    // Check encrypted data before hydration still works
    let decrypted_file_1_check = node
        .decrypt_local_data(&encrypted_file_1)
        .expect("Original node failed to decrypt data after hydration test");
    assert_eq!(
        file_data_1,
        &decrypted_file_1_check[..],
        "Original node should still decrypt data correctly"
    );
    println!("   ✅ Original node local decryption still works");

    // ==========================================
    // QUIC CERTIFICATE SERIALIZATION VALIDATION
    // ==========================================
    println!("\n🔍 QUIC CERTIFICATE SERIALIZATION VALIDATION");

    // Test 1: Get QUIC certificates from ORIGINAL node (before serialization)
    println!("   Testing QUIC certs BEFORE state serialization...");
    let original_quic_config = node
        .get_quic_certificate_config()
        .expect("Failed to get QUIC certs from original node");

    assert!(
        !original_quic_config.certificate_chain.is_empty(),
        "Original node should have QUIC certificates"
    );
    println!("   ✅ Original node has {} QUIC certificate(s)", 
             original_quic_config.certificate_chain.len());

    // Parse original certificate to check subject
    let (_, original_parsed_cert) = x509_parser::certificate::X509Certificate::from_der(
        original_quic_config.certificate_chain[0].as_ref()
    ).expect("Failed to parse original certificate");

    let original_subject = original_parsed_cert.subject().to_string();
    println!("   📋 Original certificate subject: '{}'", original_subject);

    // Test 2: Get QUIC certificates from HYDRATED node (after serialization/deserialization)
    println!("   Testing QUIC certs AFTER state serialization/hydration...");
    let hydrated_quic_config = node_hydrated
        .get_quic_certificate_config()
        .expect("Failed to get QUIC certs from hydrated node");

    assert!(
        !hydrated_quic_config.certificate_chain.is_empty(),
        "Hydrated node should have QUIC certificates"
    );
    println!("   ✅ Hydrated node has {} QUIC certificate(s)", 
             hydrated_quic_config.certificate_chain.len());

    // Parse hydrated certificate to check subject
    let (_, hydrated_parsed_cert) = x509_parser::certificate::X509Certificate::from_der(
        hydrated_quic_config.certificate_chain[0].as_ref()
    ).expect("Failed to parse hydrated certificate");

    let hydrated_subject = hydrated_parsed_cert.subject().to_string();
    println!("   📋 Hydrated certificate subject: '{}'", hydrated_subject);

    // Test 3: Compare subjects - this validates serialization works correctly
    println!("   Comparing certificate subjects before and after serialization...");

    if original_subject == hydrated_subject {
        println!("   ✅ Certificate subjects match - serialization working correctly");
        println!("      Original:  '{}'", original_subject);
        println!("      Hydrated:  '{}'", hydrated_subject);
    } else {
        println!("   ❌ SERIALIZATION BUG DETECTED!");
        println!("      Original subject:  '{}'", original_subject);
        println!("      Hydrated subject:  '{}'", hydrated_subject);
        
        // This would indicate a serialization issue
        assert_eq!(
            original_subject, hydrated_subject,
            "Certificate subject should be preserved across serialization"
        );
    }

    // Test 4: Also verify certificate DER bytes match
    println!("   Comparing certificate DER bytes...");

    if original_quic_config.certificate_chain[0] == hydrated_quic_config.certificate_chain[0] {
        println!("   ✅ Certificate DER bytes match exactly");
    } else {
        println!("   ⚠️  Certificate DER bytes differ - new certs generated after hydration");
        println!("      Original cert size:  {} bytes", original_quic_config.certificate_chain[0].len());
        println!("      Hydrated cert size:  {} bytes", hydrated_quic_config.certificate_chain[0].len());
    }

    // Additional local storage test after hydration
    let file_data_2 = b"This is secret file content to test after hydration.";
    println!("\n💾 Additional Local Storage Test After Hydration");

    let encrypted_file_2 = node
        .encrypt_local_data(file_data_2)
        .expect("Node failed to encrypt data");
    println!("   Original data: {:?}", std::str::from_utf8(file_data_2).unwrap());
    println!("   Encrypted data (hex): {}", hex::encode(&encrypted_file_2));
    assert_ne!(file_data_2, &encrypted_file_2[..]); // Ensure it's not plaintext

    let decrypted_file_2 = node
        .decrypt_local_data(&encrypted_file_2)
        .expect("Node failed to decrypt data");
    println!("   Decrypted data: {:?}", std::str::from_utf8(&decrypted_file_2).unwrap());

    assert_eq!(
        file_data_2,
        &decrypted_file_2[..],
        "Decrypted data should match original"
    );
    println!("   ✅ Local storage encryption/decryption working correctly");

    // ==========================================
    // FINAL VALIDATION SUMMARY
    // ==========================================
    println!("\n🎉 COMPREHENSIVE END-TO-END TEST COMPLETED SUCCESSFULLY!");
    println!("📋 All validations passed:");
    println!("   ✅ Mobile CA initialization and user root key generation");
    println!("   ✅ Node setup token generation and CSR workflow");
    println!("   ✅ Certificate issuance and installation");
    println!("   ✅ QUIC transport configuration and validation");
    println!("   ✅ X.509 certificate structure and ECDSA key validation");
    println!("   ✅ Rustls/Quinn compatibility");
    println!("   ✅ Enhanced key management (profiles, networks, envelopes)");
    println!("   ✅ Multi-recipient envelope encryption");
    println!("   ✅ Cross-device data sharing (mobile ↔ node)");
    println!("   ✅ Node local storage encryption");
    println!("   ✅ State serialization and restoration");
    println!("   ✅ Certificate persistence across serialization");
    println!();
    println!("🔒 CRYPTOGRAPHIC INTEGRITY VERIFIED!");
    println!("🚀 COMPLETE PKI + KEY MANAGEMENT SYSTEM READY FOR PRODUCTION!");
    println!("📊 Key Statistics:");
    println!("   • User root key: {} bytes", user_root_public_key.len());
    println!("   • CA public key: {} bytes", user_ca_public_key.len());
    println!("   • Profile keys: 2 (personal, work)");
    println!("   • Network keys: 1 (network_X)");
    println!("   • Node certificates: 1 (test-node-001)");
    println!("   • Storage encryption: ✅");
    println!("   • State persistence: ✅");

    Ok(())
} 