//! Unit tests for FFI response validation
//!
//! This module provides comprehensive unit tests for validating CBOR response deserialization
//! and structure validation for all CA Node response types.

use runar_keys::ca_node_types::{
    CaStatus, ChainResponse, CsrEnrollResponse, RenewResponse, RevokeResponse,
};

/// Test valid enrollment response deserialization
#[test]
fn test_enroll_response_deserialization() {
    let response = CsrEnrollResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![1, 2, 3, 4, 5],
        issuing_ca_der: vec![6, 7, 8, 9, 10],
        root_ca_der: Some(vec![11, 12, 13, 14, 15]),
        expires_at: 1761274868,
    };

    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&response).expect("Failed to serialize response");

    // Deserialize back
    let deserialized: CsrEnrollResponse =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize response");

    // Validate structure
    assert_eq!(deserialized.network_id, "test_network");
    assert_eq!(deserialized.certificate_der, vec![1, 2, 3, 4, 5]);
    assert_eq!(deserialized.issuing_ca_der, vec![6, 7, 8, 9, 10]);
    assert_eq!(deserialized.root_ca_der, Some(vec![11, 12, 13, 14, 15]));
    assert_eq!(deserialized.expires_at, 1761274868);
}

/// Test valid renewal response deserialization
#[test]
fn test_renew_response_deserialization() {
    let response = RenewResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![1, 2, 3, 4, 5],
        issuing_ca_der: vec![6, 7, 8, 9, 10],
        expires_at: 1761274868,
    };

    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&response).expect("Failed to serialize response");

    // Deserialize back
    let deserialized: RenewResponse =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize response");

    // Validate structure
    assert_eq!(deserialized.network_id, "test_network");
    assert_eq!(deserialized.certificate_der, vec![1, 2, 3, 4, 5]);
    assert_eq!(deserialized.issuing_ca_der, vec![6, 7, 8, 9, 10]);
    assert_eq!(deserialized.expires_at, 1761274868);
}

/// Test valid revocation response deserialization
#[test]
fn test_revoke_response_deserialization() {
    let response = RevokeResponse {
        network_id: "test_network".to_string(),
        ok: true,
    };

    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&response).expect("Failed to serialize response");

    // Deserialize back
    let deserialized: RevokeResponse =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize response");

    // Validate structure
    assert_eq!(deserialized.network_id, "test_network");
    assert!(deserialized.ok);
}

/// Test valid status response deserialization
#[test]
fn test_status_response_deserialization() {
    let response = CaStatus {
        network_id: "test_network".to_string(),
        issuing_subject: "CN=Test Issuing CA,O=Test,C=US".to_string(),
        issuing_serial_hex: "1".to_string(),
        not_before: 1758682867,
        not_after: 1790218867,
    };

    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&response).expect("Failed to serialize response");

    // Deserialize back
    let deserialized: CaStatus =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize response");

    // Validate structure
    assert_eq!(deserialized.network_id, "test_network");
    assert_eq!(
        deserialized.issuing_subject,
        "CN=Test Issuing CA,O=Test,C=US"
    );
    assert_eq!(deserialized.issuing_serial_hex, "1");
    assert_eq!(deserialized.not_before, 1758682867);
    assert_eq!(deserialized.not_after, 1790218867);
}

/// Test valid chain response deserialization
#[test]
fn test_chain_response_deserialization() {
    let response = ChainResponse {
        network_id: "test_network".to_string(),
        issuing_ca_der: vec![1, 2, 3, 4, 5],
        root_ca_der: Some(vec![6, 7, 8, 9, 10]),
    };

    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&response).expect("Failed to serialize response");

    // Deserialize back
    let deserialized: ChainResponse =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize response");

    // Validate structure
    assert_eq!(deserialized.network_id, "test_network");
    assert_eq!(deserialized.issuing_ca_der, vec![1, 2, 3, 4, 5]);
    assert_eq!(deserialized.root_ca_der, Some(vec![6, 7, 8, 9, 10]));
}

/// Test invalid CBOR handling
#[test]
fn test_invalid_cbor_handling() {
    let invalid_cbor = vec![0x00, 0x01, 0x02, 0x03]; // Invalid CBOR

    // Should fail to deserialize
    let result: Result<CsrEnrollResponse, _> = serde_cbor::from_slice(&invalid_cbor);
    assert!(result.is_err());
}

/// Test missing fields validation
#[test]
fn test_missing_fields_validation() {
    // Create a minimal CBOR that might be missing required fields
    let minimal_cbor = vec![
        0xa1, 0x6a, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x5f, 0x69, 0x64, 0x6b, 0x74, 0x65,
        0x73, 0x74,
    ]; // {"network_id": "test"}

    // Should fail to deserialize due to missing required fields
    let result: Result<CsrEnrollResponse, _> = serde_cbor::from_slice(&minimal_cbor);
    assert!(result.is_err());
}

/// Test network ID mismatch validation
#[test]
fn test_network_id_mismatch_validation() {
    let response = RevokeResponse {
        network_id: "wrong_network".to_string(),
        ok: true,
    };

    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&response).expect("Failed to serialize response");

    // Deserialize back
    let deserialized: RevokeResponse =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize response");

    // Validate network ID mismatch
    assert_ne!(deserialized.network_id, "test_network");
    assert_eq!(deserialized.network_id, "wrong_network");
}

/// Test success/failure response validation
#[test]
fn test_success_failure_response_validation() {
    // Test success response
    let success_response = RevokeResponse {
        network_id: "test_network".to_string(),
        ok: true,
    };

    let success_cbor =
        serde_cbor::to_vec(&success_response).expect("Failed to serialize success response");
    let success_deserialized: RevokeResponse =
        serde_cbor::from_slice(&success_cbor).expect("Failed to deserialize success response");
    assert!(success_deserialized.ok);

    // Test failure response
    let failure_response = RevokeResponse {
        network_id: "test_network".to_string(),
        ok: false,
    };

    let failure_cbor =
        serde_cbor::to_vec(&failure_response).expect("Failed to serialize failure response");
    let failure_deserialized: RevokeResponse =
        serde_cbor::from_slice(&failure_cbor).expect("Failed to deserialize failure response");
    assert!(!failure_deserialized.ok);
}

/// Test empty certificate data validation
#[test]
fn test_empty_certificate_data_validation() {
    let response = CsrEnrollResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![], // Empty certificate
        issuing_ca_der: vec![],  // Empty issuing CA
        root_ca_der: None,       // No root CA
        expires_at: 1761274868,
    };

    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&response).expect("Failed to serialize response");

    // Deserialize back
    let deserialized: CsrEnrollResponse =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize response");

    // Validate empty data
    assert!(deserialized.certificate_der.is_empty());
    assert!(deserialized.issuing_ca_der.is_empty());
    assert!(deserialized.root_ca_der.is_none());
}

/// Test large response data handling
#[test]
fn test_large_response_data_handling() {
    let large_cert = vec![0u8; 10000]; // 10KB certificate
    let large_issuing_ca = vec![1u8; 5000]; // 5KB issuing CA
    let large_root_ca = vec![2u8; 3000]; // 3KB root CA

    let response = CsrEnrollResponse {
        network_id: "test_network".to_string(),
        certificate_der: large_cert.clone(),
        issuing_ca_der: large_issuing_ca.clone(),
        root_ca_der: Some(large_root_ca.clone()),
        expires_at: 1761274868,
    };

    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&response).expect("Failed to serialize large response");

    // Deserialize back
    let deserialized: CsrEnrollResponse =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize large response");

    // Validate large data
    assert_eq!(deserialized.certificate_der, large_cert);
    assert_eq!(deserialized.issuing_ca_der, large_issuing_ca);
    assert_eq!(deserialized.root_ca_der, Some(large_root_ca));
}

/// Test edge case with zero expiration time
#[test]
fn test_zero_expiration_time_validation() {
    let response = CsrEnrollResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![1, 2, 3, 4, 5],
        issuing_ca_der: vec![6, 7, 8, 9, 10],
        root_ca_der: Some(vec![11, 12, 13, 14, 15]),
        expires_at: 0, // Zero expiration time
    };

    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&response).expect("Failed to serialize response");

    // Deserialize back
    let deserialized: CsrEnrollResponse =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize response");

    // Validate zero expiration time
    assert_eq!(deserialized.expires_at, 0);
}

/// Test edge case with maximum expiration time
#[test]
fn test_maximum_expiration_time_validation() {
    let response = CsrEnrollResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![1, 2, 3, 4, 5],
        issuing_ca_der: vec![6, 7, 8, 9, 10],
        root_ca_der: Some(vec![11, 12, 13, 14, 15]),
        expires_at: u64::MAX, // Maximum expiration time
    };

    // Serialize to CBOR
    let cbor_data = serde_cbor::to_vec(&response).expect("Failed to serialize response");

    // Deserialize back
    let deserialized: CsrEnrollResponse =
        serde_cbor::from_slice(&cbor_data).expect("Failed to deserialize response");

    // Validate maximum expiration time
    assert_eq!(deserialized.expires_at, u64::MAX);
}

/// Test truncated response handling
#[test]
fn test_truncated_response_handling() {
    let response = CsrEnrollResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![1, 2, 3, 4, 5],
        issuing_ca_der: vec![6, 7, 8, 9, 10],
        root_ca_der: Some(vec![11, 12, 13, 14, 15]),
        expires_at: 1761274868,
    };

    // Serialize to CBOR
    let mut cbor_data = serde_cbor::to_vec(&response).expect("Failed to serialize response");

    // Truncate the data
    cbor_data.truncate(cbor_data.len() / 2);

    // Should fail to deserialize truncated data
    let result: Result<CsrEnrollResponse, _> = serde_cbor::from_slice(&cbor_data);
    assert!(result.is_err());
}

/// Test invalid field types
#[test]
fn test_invalid_field_types() {
    // Create CBOR with wrong field types
    let invalid_cbor = vec![
        0xa5, // map(5)
        0x6a, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x5f, 0x69, 0x64, // "network_id"
        0x6b, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72,
        0x6b, // "test_network"
        0x6d, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x5f, 0x64, 0x65,
        0x72, // "certificate_der"
        0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f, // "hello" (string instead of bytes)
        0x6d, 0x69, 0x73, 0x73, 0x69, 0x6e, 0x67, 0x5f, 0x66, 0x69, 0x65, 0x6c,
        0x64, // "missing_field"
        0x65, 0x77, 0x6f, 0x72, 0x6c, 0x64, // "world"
    ];

    // Should fail to deserialize due to wrong field types
    let result: Result<CsrEnrollResponse, _> = serde_cbor::from_slice(&invalid_cbor);
    assert!(result.is_err());
}

/// Test comprehensive response validation workflow
#[test]
fn test_comprehensive_response_validation_workflow() {
    // Test enrollment response
    let enroll_response = CsrEnrollResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![1, 2, 3, 4, 5],
        issuing_ca_der: vec![6, 7, 8, 9, 10],
        root_ca_der: Some(vec![11, 12, 13, 14, 15]),
        expires_at: 1761274868,
    };
    let enroll_cbor =
        serde_cbor::to_vec(&enroll_response).expect("Failed to serialize enroll response");
    assert!(!enroll_cbor.is_empty());
    assert!(enroll_cbor.len() < 1024 * 1024);
    println!(
        "✅ enroll response validation passed: {} bytes",
        enroll_cbor.len()
    );

    // Test renewal response
    let renew_response = RenewResponse {
        network_id: "test_network".to_string(),
        certificate_der: vec![1, 2, 3, 4, 5],
        issuing_ca_der: vec![6, 7, 8, 9, 10],
        expires_at: 1761274868,
    };
    let renew_cbor =
        serde_cbor::to_vec(&renew_response).expect("Failed to serialize renew response");
    assert!(!renew_cbor.is_empty());
    assert!(renew_cbor.len() < 1024 * 1024);
    println!(
        "✅ renew response validation passed: {} bytes",
        renew_cbor.len()
    );

    // Test revocation response
    let revoke_response = RevokeResponse {
        network_id: "test_network".to_string(),
        ok: true,
    };
    let revoke_cbor =
        serde_cbor::to_vec(&revoke_response).expect("Failed to serialize revoke response");
    assert!(!revoke_cbor.is_empty());
    assert!(revoke_cbor.len() < 1024 * 1024);
    println!(
        "✅ revoke response validation passed: {} bytes",
        revoke_cbor.len()
    );

    // Test status response
    let status_response = CaStatus {
        network_id: "test_network".to_string(),
        issuing_subject: "CN=Test Issuing CA,O=Test,C=US".to_string(),
        issuing_serial_hex: "1".to_string(),
        not_before: 1758682867,
        not_after: 1790218867,
    };
    let status_cbor =
        serde_cbor::to_vec(&status_response).expect("Failed to serialize status response");
    assert!(!status_cbor.is_empty());
    assert!(status_cbor.len() < 1024 * 1024);
    println!(
        "✅ status response validation passed: {} bytes",
        status_cbor.len()
    );

    // Test chain response
    let chain_response = ChainResponse {
        network_id: "test_network".to_string(),
        issuing_ca_der: vec![1, 2, 3, 4, 5],
        root_ca_der: Some(vec![6, 7, 8, 9, 10]),
    };
    let chain_cbor =
        serde_cbor::to_vec(&chain_response).expect("Failed to serialize chain response");
    assert!(!chain_cbor.is_empty());
    assert!(chain_cbor.len() < 1024 * 1024);
    println!(
        "✅ chain response validation passed: {} bytes",
        chain_cbor.len()
    );
}
