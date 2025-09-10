use runar_keys::ca_node_types::*;
use runar_keys::enrollment_token::{EnrollmentToken, EnrollmentTokenBody};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_ca_error_response() {
    let error = CaErrorResponse {
        code: "invalid_token".to_string(),
        message: "Token validation failed".to_string(),
    };

    let serialized = serde_cbor::to_vec(&error).unwrap();
    let deserialized: CaErrorResponse = serde_cbor::from_slice(&serialized).unwrap();

    assert_eq!(error, deserialized);
}

#[test]
fn test_csr_enroll_request_response() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token_body = EnrollmentTokenBody::new(
        "test_token".to_string(),
        "test_network".to_string(),
        None,
        now,
        now + 3600,
        [0; 16],
        vec!["enroll".to_string()],
    );
    let token = EnrollmentToken {
        body: token_body,
        signature: vec![1, 2, 3, 4],
        signer_id: "test_signer".to_string(),
    };

    let request = CsrEnrollRequest {
        csr_der: vec![1, 2, 3, 4, 5],
        enrollment_token: token.clone(),
        network_id: "test_network".to_string(),
    };

    let response = CsrEnrollResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![6, 7, 8, 9, 10],
        issuing_ca_der: vec![11, 12, 13, 14, 15],
        root_ca_der: Some(vec![16, 17, 18, 19, 20]),
        expires_at: now + 86400,
    };

    // Test serialization/deserialization
    let request_serialized = serde_cbor::to_vec(&request).unwrap();
    let request_deserialized: CsrEnrollRequest =
        serde_cbor::from_slice(&request_serialized).unwrap();
    assert_eq!(request, request_deserialized);

    let response_serialized = serde_cbor::to_vec(&response).unwrap();
    let response_deserialized: CsrEnrollResponse =
        serde_cbor::from_slice(&response_serialized).unwrap();
    assert_eq!(response, response_deserialized);
}

#[test]
fn test_rate_limiting() {
    let mut rate_limit = RateLimitState::new(5, 30);

    // Should allow initial requests
    for _ in 0..5 {
        assert!(rate_limit.is_allowed());
    }

    // Should reject burst limit exceeded
    assert!(!rate_limit.is_allowed());

    // Wait a bit and try again (in real implementation, we'd use actual time)
    // For this test, we'll just verify the structure works
    let mut rate_limit2 = RateLimitState::new(10, 100);
    for _ in 0..10 {
        assert!(rate_limit2.is_allowed());
    }
    assert!(!rate_limit2.is_allowed());
}

#[test]
fn test_crl_serialization() {
    let crl = CaRevocationList {
        network_id: "test_network".to_string(),
        issuing_ca_serial_hex: "01020304".to_string(),
        revoked_serials: vec![vec![5, 6, 7, 8]],
        generated_at: 1234567890,
        signature: vec![9, 10, 11, 12],
        signer_ski: vec![13, 14, 15, 16],
        sig_alg: "p256-sha256-der".to_string(),
    };

    let serialized = serde_cbor::to_vec(&crl).unwrap();
    let deserialized: CaRevocationList = serde_cbor::from_slice(&serialized).unwrap();
    assert_eq!(crl, deserialized);
}

#[test]
fn test_renew_request_response() {
    let request = RenewRequest {
        network_id: "test_network".to_string(),
        csr_der: vec![1, 2, 3, 4, 5],
    };

    let response = RenewResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![6, 7, 8, 9, 10],
        issuing_ca_der: vec![11, 12, 13, 14, 15],
        expires_at: 1234567890,
    };

    // Test serialization/deserialization
    let request_serialized = serde_cbor::to_vec(&request).unwrap();
    let request_deserialized: RenewRequest = serde_cbor::from_slice(&request_serialized).unwrap();
    assert_eq!(request, request_deserialized);

    let response_serialized = serde_cbor::to_vec(&response).unwrap();
    let response_deserialized: RenewResponse =
        serde_cbor::from_slice(&response_serialized).unwrap();
    assert_eq!(response, response_deserialized);
}

#[test]
fn test_revoke_request_response() {
    let request = RevokeRequest {
        network_id: "test_network".to_string(),
        certificate_serial: vec![1, 2, 3, 4],
        reason: "compromise".to_string(),
    };

    let response = RevokeResponse {
        network_id: "test_network".to_string(),
        ok: true,
    };

    // Test serialization/deserialization
    let request_serialized = serde_cbor::to_vec(&request).unwrap();
    let request_deserialized: RevokeRequest = serde_cbor::from_slice(&request_serialized).unwrap();
    assert_eq!(request, request_deserialized);

    let response_serialized = serde_cbor::to_vec(&response).unwrap();
    let response_deserialized: RevokeResponse =
        serde_cbor::from_slice(&response_serialized).unwrap();
    assert_eq!(response, response_deserialized);
}

#[test]
fn test_chain_request_response() {
    let request = ChainRequest {
        network_id: "test_network".to_string(),
    };

    let response = ChainResponse {
        network_id: "test_network".to_string(),
        issuing_ca_der: vec![1, 2, 3, 4],
        root_ca_der: Some(vec![5, 6, 7, 8]),
    };

    // Test serialization/deserialization
    let request_serialized = serde_cbor::to_vec(&request).unwrap();
    let request_deserialized: ChainRequest = serde_cbor::from_slice(&request_serialized).unwrap();
    assert_eq!(request, request_deserialized);

    let response_serialized = serde_cbor::to_vec(&response).unwrap();
    let response_deserialized: ChainResponse =
        serde_cbor::from_slice(&response_serialized).unwrap();
    assert_eq!(response, response_deserialized);
}

#[test]
fn test_status_request_response() {
    let request = StatusRequest {
        network_id: "test_network".to_string(),
    };

    let response = CaStatus {
        network_id: "test_network".to_string(),
        issuing_subject: "CN=Test CA".to_string(),
        issuing_serial_hex: "1234567890abcdef".to_string(),
        not_before: 1234567890,
        not_after: 1234567890 + 86400,
    };

    // Test serialization/deserialization
    let request_serialized = serde_cbor::to_vec(&request).unwrap();
    let request_deserialized: StatusRequest = serde_cbor::from_slice(&request_serialized).unwrap();
    assert_eq!(request, request_deserialized);

    let response_serialized = serde_cbor::to_vec(&response).unwrap();
    let response_deserialized: CaStatus = serde_cbor::from_slice(&response_serialized).unwrap();
    assert_eq!(response, response_deserialized);
}

#[test]
fn test_crl_request_response() {
    let request = CrlRequest {
        network_id: "test_network".to_string(),
    };

    let response = CaRevocationList {
        network_id: "test_network".to_string(),
        issuing_ca_serial_hex: "01020304".to_string(),
        revoked_serials: vec![vec![5, 6, 7, 8]],
        generated_at: 1234567890,
        signature: vec![9, 10, 11, 12],
        signer_ski: vec![13, 14, 15, 16],
        sig_alg: "p256-sha256-der".to_string(),
    };

    // Test serialization/deserialization
    let request_serialized = serde_cbor::to_vec(&request).unwrap();
    let request_deserialized: CrlRequest = serde_cbor::from_slice(&request_serialized).unwrap();
    assert_eq!(request, request_deserialized);

    let response_serialized = serde_cbor::to_vec(&response).unwrap();
    let response_deserialized: CaRevocationList =
        serde_cbor::from_slice(&response_serialized).unwrap();
    assert_eq!(response, response_deserialized);
}
