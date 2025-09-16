use anyhow::{Context, Result};
use runar_ffi::CaClientConfigAll;
use runar_keys::ca_node_types::{CaErrorResponse, CsrEnrollRequest, CsrEnrollResponse};
use runar_keys::enrollment_token::{EnrollmentToken, EnrollmentTokenBody};
use runar_keys::mobile::SetupToken;
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

fn write_cbor_vector<T: Serialize>(out: &Path, filename: &str, data: &T) -> Result<()> {
    let cbor_data =
        serde_cbor::to_vec(data).context(format!("Failed to serialize {filename} to CBOR"))?;

    let mut path = out.to_path_buf();
    path.push(filename);

    fs::write(&path, &cbor_data).context(format!("Failed to write {}", path.display()))?;

    println!("   📝 {}: {} bytes", filename, cbor_data.len());
    Ok(())
}
