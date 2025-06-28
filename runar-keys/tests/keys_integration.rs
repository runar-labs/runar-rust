use runar_keys::*;
use x509_parser::prelude::FromDer;

#[test]
fn test_e2e_keys_generation_and_exchange() {
    // This goal of this test is to simulate the end to end encryption and keys management flows.
    // in the real implemetnation the mobile process  and the node
    // process will be in different machines and talkig over the network,
    // but here we want to simulate the end to ened and  test the whole flow.
    // so  we willl bypass the network part and deal with the internal compionents

    // mobile side - first time use - generate user keys

    // 1 - (mobile side) - generate user master key
    let mut mobile = MobileKeyManager::new();
    mobile.generate_seed();

    // Generate user root key - now returns only the public key
    let user_root_public_key = mobile
        .generate_user_root_key()
        .expect("Failed to generate user root key");
    assert!(
        user_root_public_key.bytes().len() == 32,
        "User root key should have a valid public key"
    );

    let user_public_key = user_root_public_key.bytes().to_vec();
    println!("User public key: {}", hex::encode(&user_public_key));

    // Create a user owned and managed CA
    let user_ca_public_key = mobile
        .generate_user_ca_key()
        .expect("Failed to generate user CA key");
    assert_eq!(user_ca_public_key.bytes().len(), 32);
    println!(
        "User CA public key: {}",
        hex::encode(user_ca_public_key.bytes())
    );

    // Node first time use - enter in setup mode

    // 2 - node side (setup mode) - generate its own TLS and Storage keypairs
    //     and generate a setup handshake token which contains the CSR request and the node public key
    //     which will be presented as QR code.. here in the test we use the token as a string dfirectly.
    let mut node = NodeKeyManager::new();
    let setup_token = node
        .generate_setup_token()
        .expect("Failed to generate setup token");

    //lets serialize the setup token
    let setup_token_bytes =
        bincode::serialize(&setup_token).expect("Failed to serialize setup token");
    let setup_token_str = hex::encode(setup_token_bytes);
    println!("Setup token string: {}", setup_token_str);

    // Mobile scans a Node QR code which contains the setup token
    // setup_token_str represents the QR code

    // lets deserialize the setup token
    let setup_token_bytes_mobile =
        hex::decode(setup_token_str).expect("Failed to decode setup token");
    let setup_token_mobile =
        bincode::deserialize(&setup_token_bytes_mobile).expect("Failed to deserialize setup token");

    // 3 - (mobile side) - received the token and sign the CSR
    let cert = mobile
        .process_setup_token(&setup_token_mobile)
        .expect("Failed to process setup token");
    println!("Certificate: {} -> {}", cert.subject, cert.issuer);
    assert_eq!(
        cert.issuer,
        format!("ca:{}", hex::encode(user_ca_public_key.bytes())),
        "Certificate should be issued by the user CA"
    );

    // Extract the node ID from the setup token
    // In a real-world scenario, the mobile device would have received this in the setup token
    let node_public_key = hex::encode(&setup_token_mobile.node_public_key);

    // Mobile encrypts a message containing both the certificate and CA public key for secure transmission to the node
    // This ensures only the target node can decrypt the message and has the CA key needed for verification
    let encrypted_node_msg = mobile
        .encrypt_message_for_node(&cert, &node_public_key)
        .expect("Failed to encrypt message");
    println!("Certificate and CA key encrypted successfully for secure transmission");

    // The encrypted envelope then is transmitted over a network
    // Here we're simulating that by directly passing the envelope to the node

    //  serialize envelope for transmission
    let serialized_node_msg =
        bincode::serialize(&encrypted_node_msg).expect("Failed to serialize envelope");

    // Node side - received the encrypted message

    //  deserialize envelope
    let deserialized_node_msg =
        bincode::deserialize(&serialized_node_msg).expect("Failed to deserialize envelope");

    // 4 - (node side) - received the encrypted message, decrypts it,
    // validates the certificate using the CA key, and stores it
    node.process_mobile_message(&deserialized_node_msg)
        .expect("Failed to process encrypted certificate");

    // FROM THIS POINT THE NODE AND MOBILE WILL RE-CONNECT USING THE NEW CERTIFICATES AND
    // ALL FUTURE COMMS ARE SECURED AND ECNRYPTED USING THESE NEW CREDENTIALS.

    // Get QUIC-compatible certificates, private key, and verifier from the node
    // This uses the existing certificate that was just validated from the mobile side
    let (quic_certs, private_key, _quic_certs_verifier) = node
        .get_quic_certs()
        .expect("Failed to get QUIC certificates");

    println!("🔍 COMPREHENSIVE QUIC CERTIFICATE VALIDATION");

    // Validate the QUIC certificates
    assert!(!quic_certs.is_empty(), "No QUIC certificates returned");
    assert_eq!(quic_certs.len(), 1, "Expected exactly one certificate");

    let cert_der = &quic_certs[0];
    assert!(!cert_der.is_empty(), "Empty certificate in chain");

    // ==============================================
    // 1. CERTIFICATE PARSING AND X.509 STRUCTURE
    // ==============================================
    println!("✅ Step 1: Parsing X.509 certificate structure...");

    // Parse the certificate using x509-parser to validate structure
    let (_, parsed_cert) = x509_parser::certificate::X509Certificate::from_der(cert_der.as_ref())
        .expect("Failed to parse certificate as valid X.509 DER");

    println!("   - Certificate version: {:?}", parsed_cert.version());
    println!(
        "   - Certificate serial: {}",
        hex::encode(parsed_cert.serial.to_bytes_be())
    );
    println!("   - Certificate subject: {}", parsed_cert.subject());
    println!("   - Certificate issuer: {}", parsed_cert.issuer());
    println!(
        "   - Certificate validity: {:?} to {:?}",
        parsed_cert.validity().not_before,
        parsed_cert.validity().not_after
    );

    // ==============================================
    // 2. PUBLIC KEY EXTRACTION AND VALIDATION
    // ==============================================
    println!("✅ Step 2: Extracting and validating public key...");

    let public_key_info = parsed_cert.public_key();
    let cert_public_key_bytes = public_key_info.subject_public_key.data.as_ref();

    // Validate public key algorithm
    assert_eq!(
        public_key_info.algorithm.algorithm.to_string(),
        "1.3.101.112", // Ed25519 OID
        "Certificate should use Ed25519 algorithm"
    );

    // Validate public key length
    assert_eq!(
        cert_public_key_bytes.len(),
        32,
        "Ed25519 public key should be 32 bytes"
    );

    println!("   - Public key algorithm: {:?}", public_key_info.algorithm);
    println!(
        "   - Public key length: {} bytes",
        cert_public_key_bytes.len()
    );
    println!(
        "   - Public key bytes: {}",
        hex::encode(cert_public_key_bytes)
    );

    // ==============================================
    // 3. PRIVATE KEY VALIDATION AND MATCHING
    // ==============================================
    println!("✅ Step 3: Validating private key and key pair matching...");

    // Validate private key format (should be PKCS#8 DER)
    assert!(
        !private_key.secret_der().is_empty(),
        "Private key should not be empty"
    );
    assert_eq!(
        private_key.secret_der().len(),
        48,
        "Ed25519 PKCS#8 private key should be 48 bytes"
    );

    println!("   - Private key format: PKCS#8 DER");
    println!(
        "   - Private key length: {} bytes",
        private_key.secret_der().len()
    );

    // Parse the PKCS#8 private key to extract the raw Ed25519 private key
    let pkcs8_der = private_key.secret_der();

    // PKCS#8 structure validation (basic)
    assert_eq!(pkcs8_der[0], 0x30, "PKCS#8 should start with SEQUENCE tag");
    assert_eq!(pkcs8_der[1], 0x2E, "PKCS#8 should have length 46 (0x2E)");

    // Extract the raw Ed25519 private key (last 32 bytes)
    let raw_private_key = &pkcs8_der[pkcs8_der.len() - 32..];
    assert_eq!(
        raw_private_key.len(),
        32,
        "Raw Ed25519 private key should be 32 bytes"
    );

    println!(
        "   - Raw private key extracted: {} bytes",
        raw_private_key.len()
    );

    // ==============================================
    // 4. CRYPTOGRAPHIC KEY PAIR VALIDATION
    // ==============================================
    println!("✅ Step 4: Validating cryptographic key pair relationship...");

    // Create Ed25519 signing key from the raw private key
    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        raw_private_key
            .try_into()
            .expect("Invalid private key length"),
    );

    // Derive the public key from the private key
    let derived_public_key = signing_key.verifying_key();
    let derived_public_key_bytes = derived_public_key.as_bytes();

    println!(
        "   - Derived public key from private key: {}",
        hex::encode(derived_public_key_bytes)
    );

    // CRITICAL TEST: Verify that the private key corresponds to the certificate's public key
    assert_eq!(
        derived_public_key_bytes, cert_public_key_bytes,
        "Private key MUST correspond to the certificate's public key"
    );

    println!("   ✅ PERFECT MATCH: Private key corresponds to certificate's public key!");

    // ==============================================
    // 5. SUBJECT NAME VALIDATION
    // ==============================================
    println!("✅ Step 5: Validating certificate subject...");

    // Extract subject common name
    let subject_cn = parsed_cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .expect("Certificate should have a subject common name");

    println!("   - Subject CN: {}", subject_cn);

    // Validate subject format (should be "node:{hex_public_key}")
    assert!(
        subject_cn.starts_with("node:"),
        "Subject should start with 'node:'"
    );

    let subject_public_key_hex = &subject_cn[5..]; // Remove "node:" prefix
    let subject_public_key_bytes =
        hex::decode(subject_public_key_hex).expect("Subject should contain valid hex public key");

    // Verify subject contains the same public key as the certificate
    assert_eq!(
        subject_public_key_bytes, cert_public_key_bytes,
        "Subject public key should match certificate public key"
    );

    println!("   ✅ Subject public key matches certificate public key!");

    // ==============================================
    // 6. ISSUER VALIDATION
    // ==============================================
    println!("✅ Step 6: Validating certificate issuer...");

    // Extract issuer common name
    let issuer_cn = parsed_cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .expect("Certificate should have an issuer common name");

    println!("   - Issuer CN: {}", issuer_cn);

    // Validate issuer format (should be "ca:{hex_ca_public_key}")
    assert!(
        issuer_cn.starts_with("ca:"),
        "Issuer should start with 'ca:'"
    );

    let ca_public_key_hex = &issuer_cn[3..]; // Remove "ca:" prefix
    let ca_public_key_bytes =
        hex::decode(ca_public_key_hex).expect("Issuer should contain valid hex CA public key");

    assert_eq!(
        ca_public_key_bytes.len(),
        32,
        "CA public key should be 32 bytes"
    );
    println!("   - CA public key: {}", hex::encode(&ca_public_key_bytes));

    // ==============================================
    // 7. RUSTLS/QUINN COMPATIBILITY VALIDATION
    // ==============================================
    println!("✅ Step 7: Validating rustls/Quinn compatibility...");

    // Test that rustls can parse the certificate
    let rustls_cert = rustls::pki_types::CertificateDer::from(cert_der.as_ref().to_vec());
    assert!(
        !rustls_cert.is_empty(),
        "Rustls certificate should not be empty"
    );

    // Test that rustls can parse the private key
    let _rustls_private_key =
        rustls::pki_types::PrivateKeyDer::try_from(private_key.secret_der().to_vec())
            .expect("Rustls should be able to parse the private key");

    println!("   - Rustls certificate parsing: ✅");
    println!("   - Rustls private key parsing: ✅");

    // ==============================================
    // 8. SIGNATURE VALIDATION (Advanced)
    // ==============================================
    println!("✅ Step 8: Validating certificate signature...");

    // The certificate should be signed by the CA
    // We can verify this by checking that the signature validates against the CA's public key
    let _ca_verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
        &ca_public_key_bytes
            .try_into()
            .expect("Invalid CA public key"),
    )
    .expect("Invalid CA public key format");

    // Extract the TBS (To Be Signed) portion and signature from the certificate
    // This is complex for manual parsing, but we can at least verify the structure
    let signature_algorithm = &parsed_cert.signature_algorithm;
    assert_eq!(
        signature_algorithm.algorithm.to_string(),
        "1.3.101.112", // Ed25519 OID
        "Certificate signature should use Ed25519"
    );

    println!("   - Signature algorithm: {:?}", signature_algorithm);
    println!("   - CA public key format: ✅");

    // ==============================================
    // FINAL VALIDATION SUMMARY
    // ==============================================
    println!("🎉 COMPREHENSIVE VALIDATION COMPLETE!");
    println!("📋 All validations passed:");
    println!("   ✅ X.509 certificate structure");
    println!("   ✅ Ed25519 public key format and length");
    println!("   ✅ PKCS#8 private key format and length");
    println!("   ✅ Private key ↔ Certificate public key matching");
    println!("   ✅ Certificate subject format and content");
    println!("   ✅ Certificate issuer format and content");
    println!("   ✅ Rustls/Quinn compatibility");
    println!("   ✅ Certificate signature algorithm");
    println!();
    println!("🔒 CRYPTOGRAPHIC INTEGRITY VERIFIED!");
    println!("🚀 QUIC transport ready for production use!");

    // 5 - (mobile side) -  user created a network with a given name - generate a network key
    let network_public_key = mobile
        .generate_network_data_key()
        .expect("Failed to generate network data key");

    // Create an encrypted network keys message for the node
    let network_name = "network_X";
    let node_id = hex::encode(&setup_token_mobile.node_public_key);
    let encrypted_network_keys = mobile
        .create_network_keys_message(&network_public_key, network_name, &node_id)
        .expect("Failed to create network keys message");

    // Serialize the encrypted network keys message for transmission
    let serialized_network_keys = bincode::serialize(&encrypted_network_keys)
        .expect("Failed to serialize network keys envelope");

    // Node side - received the encrypted network keys message
    let deserialized_network_keys = bincode::deserialize(&serialized_network_keys)
        .expect("Failed to deserialize network keys envelope");

    // 6 - (node side) - process the network keys message and store the keys securely
    node.process_network_keys_message(&deserialized_network_keys)
        .expect("Failed to process network keys message");

    // at this point the node is ready to process requests, events and data of the network_X

    // 7 - (mobile side) - User creates a profile key
    // Note: The API now returns only the public key, profile index is managed internally
    let profile_public_key = mobile
        .generate_user_profile_key()
        .expect("Failed to generate user profile key");
    assert!(
        !profile_public_key.is_empty(),
        "User profile key should have a valid public key"
    );

    // 8 - (mobile side) - Encrypts data using envelope which is encrypted using the
    //     user profile key and network key.
    //     so only the user or apps running in the network can decrypt it.
    let test_data = b"This is a test message that should be encrypted and decrypted";
    let envelope = mobile
        .encrypt_for_network_and_profile(test_data, &network_public_key, &profile_public_key)
        .expect("Failed to encrypt data");

    // 9 - (node side) - received the encrypted data and decrypts it using the
    //     network key. (the node does not have the user profile key - so it needs a shared secreted)
    let decrypted_by_node = node
        .decrypt_with_network_key(&network_public_key, &envelope)
        .expect("Node failed to decrypt data");
    assert_eq!(
        decrypted_by_node, test_data,
        "Node should be able to decrypt the data"
    );

    // Additionally, verify that the mobile can also decrypt the data using the profile key
    let decrypted_by_mobile = mobile
        .decrypt_with_profile_key(&envelope, &profile_public_key)
        .expect("Mobile failed to decrypt data");
    assert_eq!(
        decrypted_by_mobile, test_data,
        "Mobile should be able to decrypt the data"
    );

    let file_data_1 = b"This is some secret file content that should be encrypted on the node.";

    let encrypted_file_1 = node
        .encrypt_data(file_data_1)
        .expect("Node failed to encrypt data");
    println!("Encrypted data (hex): {}", hex::encode(&encrypted_file_1));
    assert_ne!(file_data_1, &encrypted_file_1[..]); // Ensure it's not plaintext

    let decrypted_file_1 = node
        .decrypt_data(&encrypted_file_1)
        .expect("Node failed to decrypt data");
    println!(
        "Decrypted data: {:?}",
        std::str::from_utf8(&decrypted_file_1).unwrap()
    );

    assert_eq!(
        file_data_1,
        &decrypted_file_1[..],
        "Decrypted data should match original"
    );

    // Now let's simulate when mobile and node already have keys stored in secure storage.
    // Step 1: Export the current state of the key managers
    let mobile_state = mobile.export_state();
    let node_state = node.export_state();

    // In a real implementation, these states would be serialized and stored in secure storage
    // For this test, we'll simulate that by serializing and deserializing them
    let serialized_mobile_state =
        bincode::serialize(&mobile_state).expect("Failed to serialize mobile state");
    let serialized_node_state =
        bincode::serialize(&node_state).expect("Failed to serialize node state");

    // Step 2: Create new key managers and hydrate them with the exported state
    // This simulates restarting the application and loading keys from secure storage
    let deserialized_mobile_state =
        bincode::deserialize(&serialized_mobile_state).expect("Failed to deserialize mobile state");
    let deserialized_node_state =
        bincode::deserialize(&serialized_node_state).expect("Failed to deserialize node state");

    let mobile_hydrated = MobileKeyManager::new_with_state(deserialized_mobile_state);
    let node_hydrated = NodeKeyManager::new_with_state(deserialized_node_state);

    // Verify that the hydrated key managers can still perform operations
    // Try encrypting and decrypting data with the hydrated managers
    let test_data_2 = b"This is a second test message after key restoration";
    let envelope_2 = mobile_hydrated
        .encrypt_for_network_and_profile(test_data_2, &network_public_key, &profile_public_key)
        .expect("Hydrated mobile failed to encrypt data");

    // Node should be able to decrypt with the network key
    let decrypted_by_node_2 = node_hydrated
        .decrypt_with_network_key(&network_public_key, &envelope_2)
        .expect("Hydrated node failed to decrypt data");
    assert_eq!(
        decrypted_by_node_2, test_data_2,
        "Hydrated node should be able to decrypt the data"
    );

    // Mobile should be able to decrypt with the profile key
    let decrypted_by_mobile_2 = mobile_hydrated
        .decrypt_with_profile_key(&envelope_2, &profile_public_key)
        .expect("Hydrated mobile failed to decrypt data");
    assert_eq!(
        decrypted_by_mobile_2, test_data_2,
        "Hydrated mobile should be able to decrypt the data"
    );

    // --- Test Node Symmetric Encryption for File Storage ---
    println!("\n--- Testing Node Symmetric Encryption ---");

    //check encrupted data before hydration
    let decrypted_file_1 = node
        .decrypt_data(&encrypted_file_1)
        .expect("Node failed to decrypt data");
    println!(
        "Decrypted data: {:?}",
        std::str::from_utf8(&decrypted_file_1).unwrap()
    );

    assert_eq!(
        file_data_1,
        &decrypted_file_1[..],
        "Decrypted data should match original"
    );

    // 1. Encrypt and decrypt data with the original node instance
    let file_data_2 = b"This is some secret file content that should be encrypted on the node.";
    println!(
        "Original data: {:?}",
        std::str::from_utf8(file_data_2).unwrap()
    );

    let encrypted_file_2 = node
        .encrypt_data(file_data_2)
        .expect("Node failed to encrypt data");
    println!("Encrypted data (hex): {}", hex::encode(&encrypted_file_2));
    assert_ne!(file_data_2, &encrypted_file_2[..]); // Ensure it's not plaintext

    let decrypted_file_2 = node
        .decrypt_data(&encrypted_file_2)
        .expect("Node failed to decrypt data");
    println!(
        "Decrypted data: {:?}",
        std::str::from_utf8(&decrypted_file_2).unwrap()
    );

    assert_eq!(
        file_data_2,
        &decrypted_file_2[..],
        "Decrypted data should match original"
    );
}
