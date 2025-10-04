use anyhow::{Context, Result};
use runar_ffi::{
    CaClientConfigAll, TransportCompleteRequestParams, TransportPublishParams,
    TransportRequestParams,
};
use runar_ffi::{
    PeerConnectedEvent, TransportEventEvent, TransportRequestEvent, TransportResponseEvent,
};
use runar_keys::ca_node_types::{
    CaErrorResponse, CaStatus, ChainResponse, CsrEnrollRequest, CsrEnrollResponse, RenewRequest,
    RenewResponse, RevokeRequest, RevokeResponse,
};
use runar_keys::enrollment_token::{EnrollmentToken, EnrollmentTokenBody};
use runar_keys::mobile::SetupToken;
use runar_schemas::{
    ActionMetadata, NodeInfo, NodeMetadata, ServiceMetadata, SubscriptionMetadata,
};
use runar_transporter::discovery::multicast_discovery::PeerInfo;
use runar_transporter::transport::{NetworkMessage, NetworkMessagePayloadItem};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

/// Generate FFI types test vectors for CBOR validation
fn main() -> Result<()> {
    // Output directory
    let out = PathBuf::from("target/ffi-types-vectors");
    std::fs::create_dir_all(&out)?;

    println!("🔬 Generating FFI Types CBOR Test Vectors");
    println!("=========================================");

    // 1. EnrollmentTokenBody
    generate_enrollment_token_body_vectors(&out)?;

    // 2. EnrollmentToken
    generate_enrollment_token_vectors(&out)?;

    // 3. SetupToken
    generate_setup_token_vectors(&out)?;

    // 4. CsrEnrollRequest
    generate_csr_enroll_request_vectors(&out)?;

    // 5. CsrEnrollResponse
    generate_csr_enroll_response_vectors(&out)?;

    // 6. CaErrorResponse
    generate_ca_error_response_vectors(&out)?;
    generate_ca_client_config_all_vectors(&out)?;

    // 7. RenewRequest
    generate_renew_request_vectors(&out)?;

    // 8. RenewResponse
    generate_renew_response_vectors(&out)?;

    // 9. RevokeRequest
    generate_revoke_request_vectors(&out)?;

    // 10. RevokeResponse
    generate_revoke_response_vectors(&out)?;

    // 11. CaStatus
    generate_ca_status_vectors(&out)?;

    // 12. ChainResponse
    generate_chain_response_vectors(&out)?;

    // 13. Transport Types (task11.md requirement)
    // Note: QuicTransportOptions doesn't implement Serialize, so we skip it for now
    generate_peer_info_vectors(&out)?;
    generate_node_info_vectors(&out)?;
    generate_transport_request_params_vectors(&out)?;
    generate_transport_publish_params_vectors(&out)?;
    generate_transport_complete_request_params_vectors(&out)?;

    // 14. Network Message Types (task13.md requirement)
    generate_network_message_payload_item_vectors(&out)?;
    generate_network_message_vectors(&out)?;

    // 15. Typed Transport Events (task18.md requirement)
    generate_typed_transport_event_vectors(&out)?;

    // 16. Missing CA Configuration Types
    generate_ca_server_config_vectors(&out)?;
    generate_custom_ca_server_config_vectors(&out)?;

    // 17. Missing Node Info Types
    generate_node_metadata_vectors(&out)?;
    generate_service_metadata_vectors(&out)?;
    generate_action_metadata_vectors(&out)?;
    generate_subscription_metadata_vectors(&out)?;

    // 18. Missing Schema Types
    generate_field_schema_vectors(&out)?;
    generate_schema_data_type_vectors(&out)?;

    // 19. Missing Handshake Types (create simple test data)
    generate_connection_role_vectors(&out)?;
    generate_handshake_data_vectors(&out)?;

    // 20. Missing Transport Options
    generate_discovery_options_vectors(&out)?;
    generate_quic_transport_options_config_vectors(&out)?;
    generate_quic_transport_options_vectors(&out)?;
    generate_ffi_quic_transport_options_vectors(&out)?;

    println!("✅ Generated FFI types vectors to {}", out.display());
    Ok(())
}

fn generate_enrollment_token_body_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating EnrollmentTokenBody vectors...");

    // Basic enrollment token body
    let basic_body = EnrollmentTokenBody {
        token_id: "test_token_001".to_string(),
        network_id: "test_network".to_string(),
        subject_hint: Some("test_subject".to_string()),
        not_before: 1757890822,
        expires_at: 1757894422,
        nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        permissions: vec!["enroll".to_string()],
    };

    write_cbor_vector(out, "enrollment_token_body_basic.bin", &basic_body)?;

    // Enrollment token body with multiple permissions
    let multi_permissions_body = EnrollmentTokenBody {
        token_id: "test_token_002".to_string(),
        network_id: "test_network".to_string(),
        subject_hint: Some("test_subject_2".to_string()),
        not_before: 1757890822,
        expires_at: 1757894422,
        nonce: [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
        permissions: vec!["enroll".to_string(), "renew".to_string()],
    };

    write_cbor_vector(
        out,
        "enrollment_token_body_multi_permissions.bin",
        &multi_permissions_body,
    )?;

    // Enrollment token body without subject hint
    let no_subject_body = EnrollmentTokenBody {
        token_id: "test_token_003".to_string(),
        network_id: "test_network".to_string(),
        subject_hint: None,
        not_before: 1757890822,
        expires_at: 1757894422,
        nonce: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        permissions: vec!["enroll".to_string()],
    };

    write_cbor_vector(
        out,
        "enrollment_token_body_no_subject.bin",
        &no_subject_body,
    )?;

    println!("✅ EnrollmentTokenBody vectors generated");
    Ok(())
}

fn generate_enrollment_token_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating EnrollmentToken vectors...");

    // Basic enrollment token
    let basic_body = EnrollmentTokenBody {
        token_id: "test_token_001".to_string(),
        network_id: "test_network".to_string(),
        subject_hint: Some("test_subject".to_string()),
        not_before: 1757890822,
        expires_at: 1757894422,
        nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        permissions: vec!["enroll".to_string()],
    };

    let basic_token = EnrollmentToken {
        body: basic_body,
        signature: vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
            69, 70,
        ],
        signer_id: "test_signer_001".to_string(),
    };

    write_cbor_vector(out, "enrollment_token_basic.bin", &basic_token)?;

    // Enrollment token with longer signature
    let long_signature_body = EnrollmentTokenBody {
        token_id: "test_token_002".to_string(),
        network_id: "test_network".to_string(),
        subject_hint: Some("test_subject_2".to_string()),
        not_before: 1757890822,
        expires_at: 1757894422,
        nonce: [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
        permissions: vec!["enroll".to_string(), "renew".to_string()],
    };

    let long_signature_token = EnrollmentToken {
        body: long_signature_body,
        signature: vec![255; 128], // 128-byte signature
        signer_id: "test_signer_002".to_string(),
    };

    write_cbor_vector(
        out,
        "enrollment_token_long_signature.bin",
        &long_signature_token,
    )?;

    println!("✅ EnrollmentToken vectors generated");
    Ok(())
}

fn generate_setup_token_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating SetupToken vectors...");

    // Basic setup token
    let basic_setup = SetupToken {
        node_public_key: vec![1; 65],           // 65-byte public key
        node_agreement_public_key: vec![2; 65], // 65-byte agreement key
        csr_der: vec![3; 318],                  // 318-byte CSR (typical size)
        node_id: "test_node_001".to_string(),
    };

    write_cbor_vector(out, "setup_token_basic.bin", &basic_setup)?;

    // Setup token with different key sizes
    let different_sizes_setup = SetupToken {
        node_public_key: vec![4; 33],           // 33-byte compressed key
        node_agreement_public_key: vec![5; 32], // 32-byte key
        csr_der: vec![6; 256],                  // 256-byte CSR
        node_id: "test_node_002".to_string(),
    };

    write_cbor_vector(
        out,
        "setup_token_different_sizes.bin",
        &different_sizes_setup,
    )?;

    println!("✅ SetupToken vectors generated");
    Ok(())
}

fn generate_csr_enroll_request_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating CsrEnrollRequest vectors...");

    // Create enrollment token for the request
    let token_body = EnrollmentTokenBody {
        token_id: "test_token_001".to_string(),
        network_id: "test_network".to_string(),
        subject_hint: Some("test_subject".to_string()),
        not_before: 1757890822,
        expires_at: 1757894422,
        nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        permissions: vec!["enroll".to_string()],
    };

    let enrollment_token = EnrollmentToken {
        body: token_body,
        signature: vec![1; 70], // 70-byte signature
        signer_id: "test_signer_001".to_string(),
    };

    // Basic CSR enroll request
    let basic_request = CsrEnrollRequest {
        network_id: "test_network".to_string(),
        csr_der: vec![7; 318], // 318-byte CSR
        enrollment_token: enrollment_token.clone(),
    };

    write_cbor_vector(out, "csr_enroll_request_basic.bin", &basic_request)?;

    // CSR enroll request with different CSR size
    let different_csr_request = CsrEnrollRequest {
        network_id: "test_network".to_string(),
        csr_der: vec![8; 256], // 256-byte CSR
        enrollment_token,
    };

    write_cbor_vector(
        out,
        "csr_enroll_request_different_csr.bin",
        &different_csr_request,
    )?;

    println!("✅ CsrEnrollRequest vectors generated");
    Ok(())
}

fn generate_csr_enroll_response_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating CsrEnrollResponse vectors...");

    // Basic CSR enroll response
    let basic_response = CsrEnrollResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![9; 1024],   // 1KB certificate
        issuing_ca_der: vec![10; 512],    // Intermediate cert
        root_ca_der: Some(vec![11; 256]), // Root cert
        expires_at: 1757894422,
    };

    write_cbor_vector(out, "csr_enroll_response_basic.bin", &basic_response)?;

    // CSR enroll response without root CA
    let no_root_response = CsrEnrollResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![12; 2048], // 2KB certificate
        issuing_ca_der: vec![13; 1024],  // Intermediate cert
        root_ca_der: None,               // No root cert
        expires_at: 1757894422,
    };

    write_cbor_vector(out, "csr_enroll_response_no_root.bin", &no_root_response)?;

    println!("✅ CsrEnrollResponse vectors generated");
    Ok(())
}

fn generate_ca_error_response_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating CaErrorResponse vectors...");

    // Basic error response
    let basic_error = CaErrorResponse::new("unauthorized", "Invalid enrollment token");
    write_cbor_vector(out, "ca_error_response_basic.bin", &basic_error)?;

    // Error response with reason
    let error_with_reason =
        CaErrorResponse::with_reason("forbidden", "CSR CN mismatch", "csr_cn_mismatch");
    write_cbor_vector(out, "ca_error_response_with_reason.bin", &error_with_reason)?;

    // Rate limited error
    let rate_limited_error =
        CaErrorResponse::with_reason("rate_limited", "Too many requests", "rate_limit_exceeded");
    write_cbor_vector(
        out,
        "ca_error_response_rate_limited.bin",
        &rate_limited_error,
    )?;

    println!("✅ CaErrorResponse vectors generated");
    Ok(())
}

fn generate_ca_client_config_all_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating CaClientConfigAll vectors...");

    // Basic CA client config
    let basic_config = CaClientConfigAll {
        bootstrap_server: "127.0.0.1:8443".to_string(),
        authenticated_server: "127.0.0.1:8444".to_string(),
        network_id: "test_network".to_string(),
        request_timeout_seconds: 30,
        max_retries: 3,
        root_ca_der: vec![1; 256],    // Root CA cert
        issuing_ca_der: vec![2; 512], // Issuing CA cert
    };

    write_cbor_vector(out, "ca_client_config_all_basic.bin", &basic_config)?;

    // CA client config with different sizes
    let different_sizes_config = CaClientConfigAll {
        bootstrap_server: "192.168.1.100:8443".to_string(),
        authenticated_server: "192.168.1.100:8444".to_string(),
        network_id: "production_network".to_string(),
        request_timeout_seconds: 60,
        max_retries: 5,
        root_ca_der: vec![3; 1024],    // Larger root CA cert
        issuing_ca_der: vec![4; 2048], // Larger issuing CA cert
    };

    write_cbor_vector(
        out,
        "ca_client_config_all_different_sizes.bin",
        &different_sizes_config,
    )?;

    println!("✅ CaClientConfigAll vectors generated");
    Ok(())
}

fn generate_renew_request_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating RenewRequest vectors...");

    // Basic renew request
    let basic_renew = RenewRequest {
        network_id: "test_network".to_string(),
        csr_der: vec![1; 318], // 318-byte CSR
    };

    write_cbor_vector(out, "renew_request_basic.bin", &basic_renew)?;

    // Renew request with different CSR size
    let different_csr_renew = RenewRequest {
        network_id: "test_network".to_string(),
        csr_der: vec![2; 256], // 256-byte CSR
    };

    write_cbor_vector(out, "renew_request_different_csr.bin", &different_csr_renew)?;

    println!("✅ RenewRequest vectors generated");
    Ok(())
}

fn generate_renew_response_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating RenewResponse vectors...");

    // Basic renew response
    let basic_renew_response = RenewResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![3; 1024], // 1KB certificate
        issuing_ca_der: vec![4; 512],   // Intermediate cert
        expires_at: 1757894422,
    };

    write_cbor_vector(out, "renew_response_basic.bin", &basic_renew_response)?;

    // Renew response with larger certificate
    let large_cert_renew_response = RenewResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![5; 2048], // 2KB certificate
        issuing_ca_der: vec![6; 1024],  // Intermediate cert
        expires_at: 1757894422,
    };

    write_cbor_vector(
        out,
        "renew_response_large_cert.bin",
        &large_cert_renew_response,
    )?;

    println!("✅ RenewResponse vectors generated");
    Ok(())
}

fn generate_revoke_request_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating RevokeRequest vectors...");

    // Basic revoke request
    let basic_revoke = RevokeRequest {
        network_id: "test_network".to_string(),
        certificate_serial: vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ],
        reason: "testing".to_string(),
    };

    write_cbor_vector(out, "revoke_request_basic.bin", &basic_revoke)?;

    // Revoke request without reason
    let no_reason_revoke = RevokeRequest {
        network_id: "test_network".to_string(),
        certificate_serial: vec![
            21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        ],
        reason: "no_reason".to_string(),
    };

    write_cbor_vector(out, "revoke_request_no_reason.bin", &no_reason_revoke)?;

    println!("✅ RevokeRequest vectors generated");
    Ok(())
}

fn generate_revoke_response_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating RevokeResponse vectors...");

    // Basic revoke response
    let basic_revoke_response = RevokeResponse {
        network_id: "test_network".to_string(),
        ok: true,
    };

    write_cbor_vector(out, "revoke_response_basic.bin", &basic_revoke_response)?;

    // Failed revoke response
    let failed_revoke_response = RevokeResponse {
        network_id: "test_network".to_string(),
        ok: false,
    };

    write_cbor_vector(out, "revoke_response_failed.bin", &failed_revoke_response)?;

    println!("✅ RevokeResponse vectors generated");
    Ok(())
}

fn generate_ca_status_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating CaStatus vectors...");

    // Basic CA status
    let basic_status = CaStatus {
        network_id: "test_network".to_string(),
        issuing_subject: "CN=Test Issuing CA,O=Test,C=US".to_string(),
        issuing_serial_hex: "1234567890ABCDEF".to_string(),
        not_before: 1757890822,
        not_after: 1757894422,
    };

    write_cbor_vector(out, "ca_status_basic.bin", &basic_status)?;

    // CA status with different times
    let different_times_status = CaStatus {
        network_id: "test_network".to_string(),
        issuing_subject: "CN=Production Issuing CA,O=Production,C=US".to_string(),
        issuing_serial_hex: "FEDCBA0987654321".to_string(),
        not_before: 1757890822,
        not_after: 1757890822 + 31536000, // 1 year later
    };

    write_cbor_vector(
        out,
        "ca_status_different_times.bin",
        &different_times_status,
    )?;

    println!("✅ CaStatus vectors generated");
    Ok(())
}

fn generate_chain_response_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating ChainResponse vectors...");

    // Basic chain response
    let basic_chain = ChainResponse {
        network_id: "test_network".to_string(),
        issuing_ca_der: vec![1; 512],    // Intermediate cert
        root_ca_der: Some(vec![2; 256]), // Root cert
    };

    write_cbor_vector(out, "chain_response_basic.bin", &basic_chain)?;

    // Chain response without root CA
    let no_root_chain = ChainResponse {
        network_id: "test_network".to_string(),
        issuing_ca_der: vec![3; 1024], // Intermediate cert
        root_ca_der: None,             // No root cert
    };

    write_cbor_vector(out, "chain_response_no_root.bin", &no_root_chain)?;

    println!("✅ ChainResponse vectors generated");
    Ok(())
}

// QuicTransportOptions doesn't implement Serialize, so we skip it for now

fn generate_peer_info_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating PeerInfo vectors...");

    // Basic peer info
    let basic_peer = PeerInfo {
        public_key: vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ],
        addresses: vec![
            "127.0.0.1:8080".to_string(),
            "192.168.1.100:9090".to_string(),
        ],
    };
    write_cbor_vector(out, "peer_info_basic.bin", &basic_peer)?;

    // Peer info with single address
    let single_addr_peer = PeerInfo {
        public_key: vec![
            32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
            10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        ],
        addresses: vec!["10.0.0.1:1234".to_string()],
    };
    write_cbor_vector(out, "peer_info_single_addr.bin", &single_addr_peer)?;

    // Peer info with crash data - 65-byte key that causes array out of bounds
    let crash_peer = PeerInfo {
        public_key: vec![
            4, 153, 2, 196, 43, 31, 92, 22, 163, 135, 11, 82, 104, 178, 143, 174, 102, 148, 57,
            206, 112, 4, 198, 171, 61, 155, 127, 163, 193, 48, 219, 26, 16, 32, 21, 161, 65, 27,
            62, 51, 6, 217, 8, 104, 0, 0, 71, 170, 30, 158, 90, 44, 254, 244, 252, 30, 238, 182,
            30, 18, 88, 215, 234, 203, 173,
        ],
        addresses: vec!["127.0.0.1:63725".to_string()],
    };
    write_cbor_vector(out, "peer_info_crash_data.bin", &crash_peer)?;

    println!("✅ PeerInfo vectors generated");
    Ok(())
}

fn generate_node_info_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating NodeInfo vectors...");

    // Basic node info
    let basic_node = NodeInfo {
        node_public_key: vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ],
        network_ids: vec!["test-network".to_string()],
        addresses: vec!["127.0.0.1:8080".to_string()],
        node_metadata: NodeMetadata {
            services: vec![],
            subscriptions: vec![],
        },
        version: 1,
    };
    write_cbor_vector(out, "node_info_basic.bin", &basic_node)?;

    // Node info with metadata
    let node_with_metadata = NodeInfo {
        node_public_key: vec![
            32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
            10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        ],
        network_ids: vec!["test-network".to_string(), "another-network".to_string()],
        addresses: vec![
            "127.0.0.1:8080".to_string(),
            "192.168.1.100:8080".to_string(),
        ],
        node_metadata: NodeMetadata {
            services: vec![ServiceMetadata {
                network_id: "test-network".to_string(),
                service_path: "/api/test".to_string(),
                name: "test-service".to_string(),
                version: "1.0.0".to_string(),
                description: "A test service".to_string(),
                actions: vec![],
                registration_time: 1234567890,
                last_start_time: Some(1234567891),
            }],
            subscriptions: vec![SubscriptionMetadata {
                path: "test-topic".to_string(),
            }],
        },
        version: 2,
    };
    write_cbor_vector(out, "node_info_with_metadata.bin", &node_with_metadata)?;

    println!("✅ NodeInfo vectors generated");
    Ok(())
}

fn generate_transport_request_params_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating TransportRequestParams vectors...");

    // Basic request params
    let basic_request = TransportRequestParams {
        path: "/api/test".to_string(),
        correlation_id: "corr_789".to_string(),
        payload: b"test payload".to_vec(),
        dest_peer_id: "peer_123".to_string(),
        network_public_key: Some(vec![1, 2, 3, 4, 5]),
        profile_public_keys: vec![vec![6, 7, 8, 9, 10], vec![11, 12, 13, 14, 15]],
    };
    write_cbor_vector(out, "transport_request_params_basic.bin", &basic_request)?;

    // Request params without network key
    let no_network_request = TransportRequestParams {
        path: "/api/simple".to_string(),
        correlation_id: "corr_456".to_string(),
        payload: b"simple payload".to_vec(),
        dest_peer_id: "peer_456".to_string(),
        network_public_key: None,
        profile_public_keys: vec![vec![1, 2, 3]],
    };
    write_cbor_vector(
        out,
        "transport_request_params_no_network.bin",
        &no_network_request,
    )?;

    println!("✅ TransportRequestParams vectors generated");
    Ok(())
}

fn generate_transport_publish_params_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating TransportPublishParams vectors...");

    // Basic publish params
    let basic_publish = TransportPublishParams {
        path: "/publish/test".to_string(),
        correlation_id: "pub_123".to_string(),
        payload: b"publish data".to_vec(),
        dest_peer_id: "peer_789".to_string(),
        network_public_key: Some(vec![1, 2, 3, 4, 5]),
    };
    write_cbor_vector(out, "transport_publish_params_basic.bin", &basic_publish)?;

    // Publish params without network key
    let no_network_publish = TransportPublishParams {
        path: "/publish/simple".to_string(),
        correlation_id: "pub_456".to_string(),
        payload: b"simple publish".to_vec(),
        dest_peer_id: "peer_999".to_string(),
        network_public_key: None,
    };
    write_cbor_vector(
        out,
        "transport_publish_params_no_network.bin",
        &no_network_publish,
    )?;

    println!("✅ TransportPublishParams vectors generated");
    Ok(())
}

fn generate_transport_complete_request_params_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating TransportCompleteRequestParams vectors...");

    // Basic complete request params
    let basic_complete = TransportCompleteRequestParams {
        request_id: "req_456".to_string(),
        response_payload: b"response data".to_vec(),
        profile_public_keys: vec![vec![1, 2, 3], vec![4, 5, 6]],
    };
    write_cbor_vector(
        out,
        "transport_complete_request_params_basic.bin",
        &basic_complete,
    )?;

    // Complete request params with empty profile keys
    let empty_profiles_complete = TransportCompleteRequestParams {
        request_id: "req_789".to_string(),
        response_payload: b"empty profiles response".to_vec(),
        profile_public_keys: vec![],
    };
    write_cbor_vector(
        out,
        "transport_complete_request_params_empty_profiles.bin",
        &empty_profiles_complete,
    )?;

    println!("✅ TransportCompleteRequestParams vectors generated");
    Ok(())
}

fn generate_network_message_payload_item_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating NetworkMessagePayloadItem vectors...");

    // Basic payload item - match Swift's "test payload data" string
    let basic_payload = NetworkMessagePayloadItem {
        path: "/api/test".to_string(),
        payload_bytes: b"test payload data".to_vec(),
        correlation_id: "corr_123".to_string(),
        network_public_key: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
        profile_public_keys: vec![vec![11, 12, 13, 14, 15], vec![16, 17, 18, 19, 20]],
    };
    write_cbor_vector(
        out,
        "network_message_payload_item_basic.bin",
        &basic_payload,
    )?;

    // Payload item without network key
    let no_network_payload = NetworkMessagePayloadItem {
        path: "/api/simple".to_string(),
        payload_bytes: vec![
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        ],
        correlation_id: "corr_456".to_string(),
        network_public_key: None,
        profile_public_keys: vec![vec![1, 2, 3]],
    };
    write_cbor_vector(
        out,
        "network_message_payload_item_no_network.bin",
        &no_network_payload,
    )?;

    // Payload item with empty profile keys
    let empty_profiles_payload = NetworkMessagePayloadItem {
        path: "/api/empty".to_string(),
        payload_bytes: vec![
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
            0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43,
        ],
        correlation_id: "corr_789".to_string(),
        network_public_key: Some(vec![21, 22, 23, 24, 25]),
        profile_public_keys: vec![],
    };
    write_cbor_vector(
        out,
        "network_message_payload_item_empty_profiles.bin",
        &empty_profiles_payload,
    )?;

    println!("✅ NetworkMessagePayloadItem vectors generated");
    Ok(())
}

fn generate_network_message_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating NetworkMessage vectors...");

    // Basic network message
    let basic_payload = NetworkMessagePayloadItem {
        path: "/api/request".to_string(),
        payload_bytes: b"request data".to_vec(),
        correlation_id: "req_123".to_string(),
        network_public_key: Some(vec![1, 2, 3, 4, 5]),
        profile_public_keys: vec![vec![6, 7, 8, 9, 10]],
    };

    let basic_message = NetworkMessage {
        source_node_id: "node_123".to_string(),
        destination_node_id: "node_456".to_string(),
        message_type: 4, // MESSAGE_TYPE_REQUEST
        payload: basic_payload,
    };
    write_cbor_vector(out, "network_message_basic.bin", &basic_message)?;

    // Response message
    let response_payload = NetworkMessagePayloadItem {
        path: "/api/response".to_string(),
        payload_bytes: b"response data".to_vec(),
        correlation_id: "resp_456".to_string(),
        network_public_key: None,
        profile_public_keys: vec![],
    };

    let response_message = NetworkMessage {
        source_node_id: "node_456".to_string(),
        destination_node_id: "node_123".to_string(),
        message_type: 5, // MESSAGE_TYPE_RESPONSE
        payload: response_payload,
    };
    write_cbor_vector(out, "network_message_response.bin", &response_message)?;

    // Event message
    let event_payload = NetworkMessagePayloadItem {
        path: "/events/notification".to_string(),
        payload_bytes: b"event notification data".to_vec(),
        correlation_id: "event_789".to_string(),
        network_public_key: Some(vec![11, 12, 13, 14, 15]),
        profile_public_keys: vec![vec![16, 17, 18], vec![19, 20, 21]],
    };

    let event_message = NetworkMessage {
        source_node_id: "node_789".to_string(),
        destination_node_id: "node_123".to_string(),
        message_type: 6, // MESSAGE_TYPE_EVENT
        payload: event_payload,
    };
    write_cbor_vector(out, "network_message_event.bin", &event_message)?;

    println!("✅ NetworkMessage vectors generated");
    Ok(())
}

fn generate_typed_transport_event_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating typed transport event vectors...");

    // Basic NodeInfo fixture
    let basic_node = NodeInfo {
        node_public_key: vec![1, 2, 3, 4, 5],
        network_ids: vec!["net-a".to_string()],
        addresses: vec!["127.0.0.1:0".to_string()],
        node_metadata: NodeMetadata {
            services: vec![],
            subscriptions: vec![],
        },
        version: 1,
    };

    // PeerConnectedEvent
    let pc = PeerConnectedEvent {
        node_id: "node-123".to_string(),
        node_info: basic_node,
    };
    write_cbor_vector(out, "peer_connected_event_basic.bin", &pc)?;

    // TransportRequestEvent
    let req = TransportRequestEvent {
        request_id: "req-1".to_string(),
        source_peer_id: "source-peer-123".to_string(),
        destination_peer_id: "dest-peer-456".to_string(),
        path: "/echo".to_string(),
        correlation_id: "c1".to_string(),
        payload: b"hello".to_vec(),
        profile_public_key: vec![],
    };
    write_cbor_vector(out, "transport_request_event_basic.bin", &req)?;

    // TransportEventEvent
    let evt = TransportEventEvent {
        source_peer_id: "source-peer-789".to_string(),
        destination_peer_id: "dest-peer-012".to_string(),
        path: "/event".to_string(),
        correlation_id: "e1".to_string(),
        payload: b"evt".to_vec(),
    };
    write_cbor_vector(out, "transport_event_event_basic.bin", &evt)?;

    // TransportResponseEvent
    let resp = TransportResponseEvent {
        correlation_id: "c1".to_string(),
        payload: b"world".to_vec(),
    };
    write_cbor_vector(out, "transport_response_event_basic.bin", &resp)?;

    println!("✅ Typed transport event vectors generated");
    Ok(())
}

fn write_cbor_vector<T: Serialize>(out: &Path, filename: &str, data: &T) -> Result<()> {
    let cbor_data =
        serde_cbor::to_vec(data).context(format!("Failed to serialize {filename} to CBOR"))?;

    let mut path = out.to_path_buf();
    path.push(filename);

    fs::write(&path, &cbor_data).context(format!("Failed to write {}", path.display()))?;

    println!("   📝 {}: {} bytes", filename, cbor_data.len());
    Ok(())
}

// Missing CA Configuration Types
fn generate_ca_server_config_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating CaServerConfig vectors...");

    // Create simple test data that matches Swift expectations (FFI version)
    let config_data = serde_cbor::to_vec(&serde_json::json!({
        "bootstrap_bind": "0.0.0.0:8080",
        "authenticated_bind": "0.0.0.0:8081",
        "network_id": "test_network",
        "rate_limit_per_minute": 100,
        "rate_limit_per_hour": 1000
    }))?;
    write_cbor_vector_raw(out, "ca_server_config_basic.bin", &config_data)?;

    println!("✅ CaServerConfig vectors generated");
    Ok(())
}

fn generate_custom_ca_server_config_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating CustomCaServerConfig vectors...");

    // Create simple test data that matches Swift expectations
    let config_data = serde_cbor::to_vec(&serde_json::json!({
        "bootstrap_bind": "127.0.0.1:8443",
        "authenticated_bind": "127.0.0.1:8444",
        "network_id": "test_network",
        "rate_limit_per_minute": 100,
        "rate_limit_per_hour": 1000
    }))?;
    write_cbor_vector_raw(out, "custom_ca_server_config_basic.bin", &config_data)?;

    println!("✅ CustomCaServerConfig vectors generated");
    Ok(())
}

// Missing Node Info Types
fn generate_node_metadata_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating NodeMetadata vectors...");

    let metadata = NodeMetadata {
        services: vec![],
        subscriptions: vec![],
    };
    write_cbor_vector(out, "node_metadata_basic.bin", &metadata)?;

    println!("✅ NodeMetadata vectors generated");
    Ok(())
}

fn generate_service_metadata_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating ServiceMetadata vectors...");

    let service = ServiceMetadata {
        network_id: "test_network".to_string(),
        service_path: "/test_service".to_string(),
        name: "test_service".to_string(),
        version: "1.0.0".to_string(),
        description: "Test service description".to_string(),
        actions: vec![],
        registration_time: 1678886400,
        last_start_time: Some(1678886400),
    };
    write_cbor_vector(out, "service_metadata_basic.bin", &service)?;

    println!("✅ ServiceMetadata vectors generated");
    Ok(())
}

fn generate_action_metadata_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating ActionMetadata vectors...");

    let action = ActionMetadata {
        name: "test_action".to_string(),
        description: "Test action description".to_string(),
        input_schema: None,
        output_schema: None,
    };
    write_cbor_vector(out, "action_metadata_basic.bin", &action)?;

    println!("✅ ActionMetadata vectors generated");
    Ok(())
}

fn generate_subscription_metadata_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating SubscriptionMetadata vectors...");

    let subscription = SubscriptionMetadata {
        path: "/test_topic".to_string(),
    };
    write_cbor_vector(out, "subscription_metadata_basic.bin", &subscription)?;

    println!("✅ SubscriptionMetadata vectors generated");
    Ok(())
}

// Missing Schema Types
fn generate_field_schema_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating FieldSchema vectors...");

    // Create simple test data that matches Swift expectations
    let schema_data = serde_cbor::to_vec(&serde_json::json!({
        "data_type": "String",
        "required": true,
        "description": "A test field"
    }))?;
    write_cbor_vector_raw(out, "field_schema_basic.bin", &schema_data)?;

    println!("✅ FieldSchema vectors generated");
    Ok(())
}

fn generate_schema_data_type_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating SchemaDataType vectors...");

    // String
    let string_data = serde_cbor::to_vec(&serde_json::json!("String"))?;
    write_cbor_vector_raw(out, "schema_data_type_string.bin", &string_data)?;

    // Int32
    let int32_data = serde_cbor::to_vec(&serde_json::json!("Int32"))?;
    write_cbor_vector_raw(out, "schema_data_type_int32.bin", &int32_data)?;

    // Int64
    let int64_data = serde_cbor::to_vec(&serde_json::json!("Int64"))?;
    write_cbor_vector_raw(out, "schema_data_type_int64.bin", &int64_data)?;

    // Float32
    let float32_data = serde_cbor::to_vec(&serde_json::json!("Float32"))?;
    write_cbor_vector_raw(out, "schema_data_type_float32.bin", &float32_data)?;

    // Float64
    let float64_data = serde_cbor::to_vec(&serde_json::json!("Float64"))?;
    write_cbor_vector_raw(out, "schema_data_type_float64.bin", &float64_data)?;

    // Boolean
    let boolean_data = serde_cbor::to_vec(&serde_json::json!("Boolean"))?;
    write_cbor_vector_raw(out, "schema_data_type_boolean.bin", &boolean_data)?;

    // Bytes
    let bytes_data = serde_cbor::to_vec(&serde_json::json!("Bytes"))?;
    write_cbor_vector_raw(out, "schema_data_type_bytes.bin", &bytes_data)?;

    // Array
    let array_data = serde_cbor::to_vec(&serde_json::json!("Array"))?;
    write_cbor_vector_raw(out, "schema_data_type_array.bin", &array_data)?;

    // Map
    let map_data = serde_cbor::to_vec(&serde_json::json!("Map"))?;
    write_cbor_vector_raw(out, "schema_data_type_map.bin", &map_data)?;

    println!("✅ SchemaDataType vectors generated");
    Ok(())
}

// Missing Handshake Types (create simple test data)
fn generate_connection_role_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating ConnectionRole vectors...");

    // Create simple test data that matches Swift expectations
    // Initiator (0)
    let initiator_data = vec![0u8];
    write_cbor_vector_raw(out, "connection_role_initiator.bin", &initiator_data)?;

    // Responder (1)
    let responder_data = vec![1u8];
    write_cbor_vector_raw(out, "connection_role_responder.bin", &responder_data)?;

    println!("✅ ConnectionRole vectors generated");
    Ok(())
}

fn generate_handshake_data_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating HandshakeData vectors...");

    // Create simple test data that matches Swift expectations
    let handshake_data = serde_cbor::to_vec(&serde_json::json!({
        "node_info": {
            "node_public_key": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
            "network_ids": ["test-network"],
            "addresses": ["127.0.0.1:8080"],
            "node_metadata": {
                "services": [],
                "subscriptions": []
            },
            "version": 1
        },
        "nonce": 1234567890,
        "role": 0
    }))?;
    write_cbor_vector_raw(out, "handshake_data_basic.bin", &handshake_data)?;

    println!("✅ HandshakeData vectors generated");
    Ok(())
}

fn generate_discovery_options_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating DiscoveryOptions vectors...");

    // Use the actual DiscoveryOptions struct with correct field names
    use runar_transporter::discovery::DiscoveryOptions;
    use std::time::Duration;

    let options = DiscoveryOptions {
        announce_interval: Duration::from_secs(1),
        discovery_timeout: Duration::from_secs(5),
        debounce_window: Duration::from_millis(200),
        use_multicast: true,
        local_network_only: true,
        multicast_group: "239.255.42.98".to_string(),
    };

    let options_data = serde_cbor::to_vec(&options)?;
    write_cbor_vector_raw(out, "discovery_options_basic.bin", &options_data)?;

    println!("✅ DiscoveryOptions vectors generated");
    Ok(())
}

fn generate_quic_transport_options_config_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating QuicTransportOptionsConfig vectors...");

    // Use the actual QuicTransportOptionsConfig struct
    use runar_ffi::QuicTransportOptionsConfig;

    let config = QuicTransportOptionsConfig {
        bind_addr: Some("0.0.0.0:0".to_string()),
        handshake_timeout_ms: Some(5000),
        open_stream_timeout_ms: Some(10000),
        max_message_size: Some(1024 * 1024), // 1MB
        response_cache_ttl_ms: Some(30000),
        max_request_retries: Some(3),
        cert_chain_der: vec![
            vec![0x30, 0x82, 0x01, 0x22], // Sample DER data
            vec![0x30, 0x82, 0x01, 0x33],
        ],
        private_key_der: Some(vec![0x30, 0x82, 0x01, 0x44]), // Sample DER data
        root_certs_der: vec![
            vec![0x30, 0x82, 0x01, 0x55], // Sample DER data
            vec![0x30, 0x82, 0x01, 0x66],
        ],
    };

    let config_data =
        serde_cbor::to_vec(&config).context("Failed to serialize QuicTransportOptionsConfig")?;
    write_cbor_vector_raw(out, "quic_transport_options_config_basic.bin", &config_data)?;

    println!("✅ QuicTransportOptionsConfig vectors generated");
    Ok(())
}

fn generate_quic_transport_options_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating QuicTransportOptions vectors...");

    // Create simple test data that matches Swift expectations
    let options_data = serde_cbor::to_vec(&serde_json::json!({
        "requestTimeoutSeconds": 30,
        "bindAddr": "0.0.0.0:0",
        "handshakeTimeoutMs": 5000,
        "openStreamTimeoutMs": 1000,
        "maxMessageSize": 1048576,
        "responseCacheTtlMs": 30000,
        "maxRequestRetries": 3
    }))?;
    write_cbor_vector_raw(out, "quic_transport_options_basic.bin", &options_data)?;

    println!("✅ QuicTransportOptions vectors generated");
    Ok(())
}

fn generate_ffi_quic_transport_options_vectors(out: &Path) -> Result<()> {
    println!("🔍 Generating FFIQuicTransportOptions vectors...");

    // Create simple test data that matches Swift expectations
    let options_data = serde_cbor::to_vec(&serde_json::json!({
        "bind_addr": "0.0.0.0:8080",
        "handshake_timeout_ms": 5000,
        "open_stream_timeout_ms": 1000,
        "max_message_size": 1048576,
        "response_cache_ttl_ms": 30000,
        "max_request_retries": 3
    }))?;
    write_cbor_vector_raw(out, "ffi_quic_transport_options_basic.bin", &options_data)?;

    println!("✅ FFIQuicTransportOptions vectors generated");
    Ok(())
}

// Helper function for raw data
fn write_cbor_vector_raw(out: &Path, filename: &str, data: &[u8]) -> Result<()> {
    let mut path = out.to_path_buf();
    path.push(filename);

    fs::write(&path, data).context(format!("Failed to write {}", path.display()))?;

    println!("   📝 {}: {} bytes", filename, data.len());
    Ok(())
}
