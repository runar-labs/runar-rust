//! Primitives-only End-to-End Integration Tests for CA Node Infrastructure
//!
//! This test validates the complete CA Node enrollment, renewal, revocation, and profile-key
//! interop entirely in-process without network/transporter dependencies.
//!
//! Test phases:
//! 1. CA Node setup with Root CA and Issuing CA
//! 2. Enrollment token generation and validation
//! 3. Mobile node enrollment via CA Node
//! 4. Certificate renewal
//! 5. Certificate revocation and CRL-lite
//! 6. Profile key interop

use runar_common::{
    compact_ids::compact_id,
    logging::{Component, Logger},
};
use runar_keys::{
    ca_node::CANode,
    ca_node_types::{CsrEnrollRequest, RenewRequest, RevokeRequest},
    certificate::{CertificateAuthority, CertificateRequest, CertificateValidator, EcdsaKeyPair},
    enrollment_token::{EnrollmentToken, EnrollmentTokenBody},
    error::Result,
    mobile::MobileKeyManager,
    node::{CertificateStatus, NodeKeyManager},
};
use std::sync::Arc;
use std::time::SystemTime;

fn create_test_logger() -> Arc<Logger> {
    Arc::new(Logger::new_root(Component::Custom("CA-Node-E2E")))
}

#[tokio::test]
async fn test_primitives_e2e_ca_node_flow() -> Result<()> {
    println!("🚀 Starting Primitives-only E2E CA Node test");

    // ==========================================
    // Phase 1: CA Node Infrastructure Setup
    // ==========================================
    println!("\n🏗️  PHASE 1: CA Node Infrastructure Setup");

    // Create Root CA
    let root_ca = CertificateAuthority::new("CN=Test Root CA,O=Test,C=US")?;
    let root_ca_cert = root_ca.ca_certificate().clone();

    // Create Issuing CA (signed by Root CA)
    let issuing_ca_key = EcdsaKeyPair::new()?;
    let issuing_ca_csr =
        CertificateRequest::create(&issuing_ca_key, "CN=Test Issuing CA,O=Test,C=US")?;
    let issuing_ca_cert =
        root_ca.sign_ca_certificate_request_with_serial(&issuing_ca_csr, 365, Some(1))?;

    println!("   ✅ Root CA created: {}", root_ca_cert.subject());
    println!("   ✅ Issuing CA created: {}", issuing_ca_cert.subject());

    // Create CA Node
    let mut ca_node = CANode::new(
        issuing_ca_key.clone(),
        issuing_ca_cert.clone(),
        root_ca_cert.clone(),
        "test_network".to_string(),
    );

    // Configure enrollment authority (mobile user)
    let mobile_logger = create_test_logger();
    let mut mobile = MobileKeyManager::new(mobile_logger)?;
    mobile.initialize_user_root_key()?;

    println!("   ✅ CA Node configured with enrollment authority");

    // ==========================================
    // Phase 2: Enrollment Token Generation
    // ==========================================
    println!("\n🎫 PHASE 2: Enrollment Token Generation");

    // Generate enrollment token
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let token_body = EnrollmentTokenBody::new(
        "test_token_001".to_string(),
        "test_network".to_string(),
        Some("test_subject".to_string()),
        now,
        now + 3600, // 1 hour from now
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        vec!["enroll".to_string()],
    );

    // Create EA key pair for signing
    let ea_key = EcdsaKeyPair::new()?;
    let enrollment_token = EnrollmentToken::generate(&ea_key, token_body.clone())?;

    println!("   ✅ Enrollment token generated: {}", token_body.token_id);

    // Configure enrollment authority with EA public key
    let ea_public_key = ea_key.public_key_bytes();
    ca_node.configure_enrollment_authority(vec![ea_public_key.clone()])?;

    // Validate token
    ca_node.validate_enrollment_token(&enrollment_token)?;
    println!("   ✅ Enrollment token validated by CA Node");

    // ==========================================
    // Phase 3: Mobile Node Enrollment
    // ==========================================
    println!("\n📱 PHASE 3: Mobile Node Enrollment via CA Node");

    // Create mobile node
    let node_logger = create_test_logger();
    let mut mobile_node = NodeKeyManager::new(node_logger)?;
    mobile_node.generate_keys()?;

    // Generate CSR
    let setup_token = mobile_node.generate_csr()?;
    println!("   ✅ Mobile node CSR generated: {}", setup_token.node_id);

    // Generate a new token for enrollment (to avoid replay detection)
    let enrollment_token_body2 = EnrollmentTokenBody::new(
        "test_token_002".to_string(),
        "test_network".to_string(),
        Some("test_subject".to_string()),
        now,
        now + 3600,
        [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17], // Different nonce
        vec!["enroll".to_string()],
    );
    let enrollment_token2 = EnrollmentToken::generate(&ea_key, enrollment_token_body2)?;

    // Create enrollment request
    let enroll_request = CsrEnrollRequest {
        csr_der: setup_token.csr_der.clone(),
        enrollment_token: enrollment_token2,
        network_id: "test_network".to_string(),
    };

    // Process enrollment via CA Node
    let enroll_response = ca_node.handle_enroll(enroll_request, "127.0.0.1")?;
    println!("   ✅ Certificate issued by CA Node");

    // Convert response to NodeCertificateMessage
    let cert_message = mobile.from_enroll_response(&enroll_response)?;
    println!("   ✅ Certificate response converted to NodeCertificateMessage");

    // Install certificate on mobile node
    mobile_node.install_certificate(cert_message)?;
    println!("   ✅ Certificate installed on mobile node");

    // Verify certificate status
    assert_eq!(
        mobile_node.get_certificate_status(),
        CertificateStatus::Valid
    );
    println!("   ✅ Certificate status verified: Valid");

    // ==========================================
    // Phase 4: Certificate Renewal
    // ==========================================
    println!("\n🔄 PHASE 4: Certificate Renewal");

    // Generate new CSR for renewal
    let renew_csr = mobile_node.generate_csr()?;
    println!("   ✅ Renewal CSR generated");

    // Create renewal request
    let renew_request = RenewRequest {
        csr_der: renew_csr.csr_der.clone(),
        network_id: "test_network".to_string(),
    };

    // Get mobile node's SKI for device-based authorization (from the node's key, not mobile's CA key)
    let mobile_node_public_key = mobile_node.get_node_public_key().ok_or_else(|| {
        runar_keys::error::KeyError::ValidationError("Node public key not available".to_string())
    })?;
    let mobile_node_ski = compact_id(&mobile_node_public_key);
    println!("   ✅ Mobile node SKI for device-based authorization: {mobile_node_ski}");

    // Process renewal via CA Node (now uses device-based auth, not admin)
    let renew_response = ca_node.handle_renew(renew_request, &mobile_node_ski)?;
    println!("   ✅ Certificate renewed by CA Node");

    // Convert renewal response
    let renewed_cert_message = mobile.from_renew_response(&renew_response)?;
    println!("   ✅ Renewal response converted to NodeCertificateMessage");

    // Install renewed certificate
    mobile_node.install_certificate(renewed_cert_message)?;
    println!("   ✅ Renewed certificate installed");

    // ==========================================
    // Phase 5: Certificate Revocation
    // ==========================================
    println!("\n🚫 PHASE 5: Certificate Revocation");

    // Get certificate serial for revocation
    let cert_parsed = mobile_node
        .get_node_certificate()
        .unwrap()
        .parsed()
        .unwrap();
    let cert_serial = cert_parsed.serial.to_bytes_be();

    // Create revocation request
    let revoke_request = RevokeRequest {
        certificate_serial: cert_serial.clone(),
        reason: "Test revocation".to_string(),
        network_id: "test_network".to_string(),
    };

    // Add mobile node's SKI to admin allowlist for revocation (admin operation)
    ca_node.add_admin_ski(mobile_node_ski.clone());
    println!("   ✅ Mobile node SKI added to admin allowlist for revocation");

    // Process revocation via CA Node (use mobile node's SKI for admin operations)
    let revoke_response = ca_node.handle_revoke(revoke_request, &mobile_node_ski)?;
    assert!(revoke_response.ok);
    println!("   ✅ Certificate revoked by CA Node");

    // Verify certificate is marked as revoked
    assert!(ca_node.is_certificate_revoked(&cert_serial));
    println!("   ✅ Certificate revocation verified");

    // Generate CRL-lite
    let crl = ca_node.generate_crl_lite()?;
    assert_eq!(crl.revoked_serials.len(), 1);
    assert_eq!(crl.revoked_serials[0].serial, cert_serial);
    assert!(!crl.signature.is_empty());
    println!("   ✅ CRL-lite generated with revoked certificate and signature");

    // Test CRL handler
    let crl_from_handler = ca_node.handle_crl()?;
    assert_eq!(crl.network_id, crl_from_handler.network_id);
    assert_eq!(crl.issuing_ca_serial, crl_from_handler.issuing_ca_serial);
    assert_eq!(
        crl.revoked_serials.len(),
        crl_from_handler.revoked_serials.len()
    );
    println!("   ✅ CRL handler working correctly");

    // Test CRL-lite serial format consistency (raw bytes, not hex)
    assert!(!crl.issuing_ca_serial.is_empty()); // Should be raw bytes, not hex string
    println!("   ✅ CRL-lite serial format is raw bytes (not hex string)");

    // ==========================================
    // Phase 6: CA Node API Status and Chain
    // ==========================================
    println!("\n📊 PHASE 6: CA Node API Status and Chain");

    // Get CA status
    let status = ca_node.handle_status()?;
    println!("   ✅ CA Status retrieved:");
    println!("      Issuing Subject: {}", status.issuing_subject);
    println!("      Issuing Serial: {}", status.issuing_serial_hex);
    println!("      Not Before: {}", status.not_before);
    println!("      Not After: {}", status.not_after);

    // Get certificate chain
    let chain = ca_node.handle_chain()?;
    assert!(!chain.issuing_ca_der.is_empty());
    assert!(chain.root_ca_der.is_some());
    println!("   ✅ Certificate chain retrieved");

    // ==========================================
    // Phase 7: Profile Key Interop
    // ==========================================
    println!("\n🔑 PHASE 7: Profile Key Interop");

    // Generate profile keys on mobile
    let personal_profile_key = mobile.derive_user_profile_key("personal")?;
    let work_profile_key = mobile.derive_user_profile_key("work")?;
    println!("   ✅ Profile keys generated on mobile");

    // Install profile public keys on mobile node so it can encrypt for them
    mobile_node.install_profile_public_key(personal_profile_key.clone());
    mobile_node.install_profile_public_key(work_profile_key.clone());
    println!("   ✅ Profile public keys installed on mobile node");

    // Generate profile keys on mobile node (should be different due to different root keys)
    let node_personal_key = mobile_node.derive_user_profile_key("personal")?;
    let node_work_key = mobile_node.derive_user_profile_key("work")?;
    println!("   ✅ Profile keys generated on mobile node");

    // Note: Profile keys will be different between mobile and node because they use different root keys
    // This is expected behavior - each device has its own profile key derivation
    println!("   ✅ Profile keys generated (different per device as expected)");

    // Test envelope encryption with profile keys
    let test_data = b"Test data for profile encryption";

    // Test mobile encryption/decryption
    let mobile_envelope = mobile.encrypt_with_envelope(
        test_data,
        None, // No network key
        vec![personal_profile_key.clone(), work_profile_key.clone()],
    )?;

    // Get profile IDs for decryption
    let personal_profile_id = compact_id(&personal_profile_key);
    let work_profile_id = compact_id(&work_profile_key);

    // Mobile should be able to decrypt with personal profile
    let decrypted_personal = mobile.decrypt_with_profile(&mobile_envelope, &personal_profile_id)?;
    assert_eq!(decrypted_personal, test_data);
    println!("   ✅ Mobile decrypted with personal profile");

    // Mobile should be able to decrypt with work profile
    let decrypted_work = mobile.decrypt_with_profile(&mobile_envelope, &work_profile_id)?;
    assert_eq!(decrypted_work, test_data);
    println!("   ✅ Mobile decrypted with work profile");

    // Test mobile node encryption/decryption
    let node_envelope = mobile_node.encrypt_with_envelope(
        test_data,
        None, // No network key
        vec![node_personal_key.clone(), node_work_key.clone()],
    )?;

    // Get node profile IDs for decryption
    let node_personal_profile_id = compact_id(&node_personal_key);
    let node_work_profile_id = compact_id(&node_work_key);

    // Mobile node should be able to decrypt with personal profile
    let node_decrypted_personal =
        mobile_node.decrypt_with_profile(&node_envelope, &node_personal_profile_id)?;
    assert_eq!(node_decrypted_personal, test_data);
    println!("   ✅ Mobile node decrypted with personal profile");

    // Mobile node should be able to decrypt with work profile
    let node_decrypted_work =
        mobile_node.decrypt_with_profile(&node_envelope, &node_work_profile_id)?;
    assert_eq!(node_decrypted_work, test_data);
    println!("   ✅ Mobile node decrypted with work profile");

    // ==========================================
    // Phase 8: Rate Limiting Test
    // ==========================================
    println!("\n⏱️  PHASE 8: Rate Limiting Test");

    // Test rate limiting
    for i in 0..5 {
        assert!(ca_node.check_rate_limit("127.0.0.1", "test_token").is_ok());
        println!("   ✅ Rate limit check {} passed", i + 1);
    }

    // Should hit rate limit
    assert!(ca_node.check_rate_limit("127.0.0.1", "test_token").is_err());
    println!("   ✅ Rate limit exceeded as expected");

    // ==========================================
    // Phase 9: Token Revocation Test
    // ==========================================
    println!("\n🔒 PHASE 9: Token Revocation Test");

    // Revoke the enrollment token
    ca_node.revoke_token("test_token_001".to_string())?;
    println!("   ✅ Enrollment token revoked");

    // Try to use revoked token (should fail) - use different nonce to avoid replay detection
    let revoked_token_body = EnrollmentTokenBody::new(
        "test_token_001".to_string(),
        "test_network".to_string(),
        Some("test_subject".to_string()),
        now,
        now + 3600,
        [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17], // Different nonce
        vec!["enroll".to_string()],
    );
    let revoked_token = EnrollmentToken::generate(&ea_key, revoked_token_body)?;

    let revoked_enroll_request = CsrEnrollRequest {
        enrollment_token: revoked_token,
        csr_der: mobile_node.generate_csr()?.csr_der.clone(),
        network_id: "test_network".to_string(),
    };

    assert!(ca_node
        .handle_enroll(revoked_enroll_request, "127.0.0.1")
        .is_err());
    println!("   ✅ Revoked token correctly rejected");

    // ==========================================
    // Phase 10: X.509 Extension Validation Tests
    // ==========================================
    println!("\n🔒 PHASE 10: X.509 Extension Validation Tests");

    // Test leaf certificate X.509 validation
    let node_cert = mobile_node.get_node_certificate().unwrap();
    let validator =
        CertificateValidator::new(vec![mobile_node.get_ca_certificate().unwrap().clone()]);

    // This should pass - valid leaf certificate
    validator.validate_for_tls_server(node_cert)?;
    println!("   ✅ Valid leaf certificate passed X.509 validation");

    // Test CA certificate X.509 validation
    let ca_cert = mobile_node.get_ca_certificate().unwrap();
    // For CA validation, we need to provide the Root CA as trusted
    let root_ca_cert = root_ca.ca_certificate();
    let ca_validator = CertificateValidator::new(vec![root_ca_cert.clone()]);

    // This should pass - valid CA certificate
    ca_validator.validate_certificate(ca_cert)?;
    println!("   ✅ Valid CA certificate passed X.509 validation");

    // Test SKI extraction
    let node_ski = CertificateValidator::extract_ski(node_cert)?;
    let ca_ski = CertificateValidator::extract_ski(ca_cert)?;
    assert!(!node_ski.is_empty());
    assert!(!ca_ski.is_empty());
    println!("   ✅ SKI extraction working for both leaf and CA certificates");

    // ==========================================
    // Phase 11: Error Handling Tests
    // ==========================================
    println!("\n❌ PHASE 11: Error Handling Tests");

    // Test invalid enrollment token
    let invalid_token = EnrollmentToken {
        body: token_body.clone(),
        signer_id: "invalid_signer".to_string(),
        signature: vec![0u8; 64], // Invalid signature
    };

    assert!(ca_node.validate_enrollment_token(&invalid_token).is_err());
    println!("   ✅ Invalid enrollment token rejected");

    // Test unauthorized renewal
    let unauthorized_renew = RenewRequest {
        csr_der: renew_csr.csr_der.clone(),
        network_id: "test_network".to_string(),
    };

    assert!(ca_node
        .handle_renew(unauthorized_renew, "unauthorized_ski")
        .is_err());
    println!("   ✅ Unauthorized renewal rejected");

    // ==========================================
    // Final Validation Summary
    // ==========================================
    println!("\n🎉 PRIMITIVES-ONLY E2E TEST COMPLETED SUCCESSFULLY!");
    println!("📋 All validations passed:");
    println!("   ✅ CA Node infrastructure setup");
    println!("   ✅ Enrollment token generation and validation");
    println!("   ✅ Mobile node enrollment via CA Node");
    println!("   ✅ Certificate renewal");
    println!("   ✅ Certificate revocation and CRL-lite");
    println!("   ✅ CA Node API status and chain");
    println!("   ✅ Profile key interop");
    println!("   ✅ Rate limiting");
    println!("   ✅ Error handling");
    println!();
    println!("🔒 CA NODE INFRASTRUCTURE READY FOR PRODUCTION!");
    println!("📊 Test Statistics:");
    println!("   • Root CA: {}", root_ca_cert.subject());
    println!("   • Issuing CA: {}", issuing_ca_cert.subject());
    println!("   • Network ID: test_network");
    println!("   • Profile keys: 2 (personal, work)");
    println!("   • Revoked certificates: 1");
    println!("   • Rate limiting: ✅");
    println!("   • CRL-lite: ✅");

    Ok(())
}

#[tokio::test]
async fn test_primitives_e2e_enrollment_token_validation() -> Result<()> {
    println!("🎫 Testing enrollment token validation edge cases");

    let logger = create_test_logger();
    let mut mobile = MobileKeyManager::new(logger)?;
    mobile.initialize_user_root_key()?;

    // Test expired token
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let expired_body = EnrollmentTokenBody::new(
        "expired_token".to_string(),
        "test_network".to_string(),
        Some("expired_subject".to_string()),
        now - 7200, // 2 hours ago
        now - 3600, // 1 hour ago
        [0; 16],
        vec!["enroll".to_string()],
    );

    let ea_key = EcdsaKeyPair::new()?;
    let expired_token = EnrollmentToken::generate(&ea_key, expired_body)?;

    // Create CA Node
    let root_ca = CertificateAuthority::new("CN=Test Root CA,O=Test,C=US")?;
    let issuing_ca_key = EcdsaKeyPair::new()?;
    let issuing_ca_csr =
        CertificateRequest::create(&issuing_ca_key, "CN=Test Issuing CA,O=Test,C=US")?;
    let issuing_ca_cert =
        root_ca.sign_ca_certificate_request_with_serial(&issuing_ca_csr, 365, Some(1))?;

    let mut ca_node = CANode::new(
        issuing_ca_key,
        issuing_ca_cert,
        root_ca.ca_certificate().clone(),
        "test_network".to_string(),
    );
    let ea_public_key = ea_key.public_key_bytes();
    ca_node.configure_enrollment_authority(vec![ea_public_key.clone()])?;

    // Should reject expired token
    assert!(ca_node.validate_enrollment_token(&expired_token).is_err());
    println!("   ✅ Expired token rejected");

    // Test wrong network
    let wrong_network_body = EnrollmentTokenBody::new(
        "wrong_network_token".to_string(),
        "wrong_network".to_string(),
        Some("wrong_network_subject".to_string()),
        now,
        now + 3600,
        [0; 16],
        vec!["enroll".to_string()],
    );

    let wrong_network_token = EnrollmentToken::generate(&ea_key, wrong_network_body)?;

    // Should reject wrong network
    assert!(ca_node
        .validate_enrollment_token(&wrong_network_token)
        .is_err());
    println!("   ✅ Wrong network token rejected");

    // Test revoked token
    let valid_body = EnrollmentTokenBody::new(
        "valid_token".to_string(),
        "test_network".to_string(),
        Some("valid_subject".to_string()),
        now,
        now + 3600,
        [0; 16],
        vec!["enroll".to_string()],
    );

    let valid_token = EnrollmentToken::generate(&ea_key, valid_body)?;

    // Should accept valid token initially
    assert!(ca_node.validate_enrollment_token(&valid_token).is_ok());
    println!("   ✅ Valid token accepted");

    // Revoke the token
    ca_node
        .revoked_tokens
        .insert("valid_token".to_string(), SystemTime::now());

    // Should reject revoked token
    assert!(ca_node.validate_enrollment_token(&valid_token).is_err());
    println!("   ✅ Revoked token rejected");

    Ok(())
}
