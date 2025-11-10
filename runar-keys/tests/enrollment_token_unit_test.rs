//! Unit tests for enrollment token functionality
//!
//! This module tests individual enrollment token methods and functionality
//! without the full E2E integration tests.

use runar_keys::{
    certificate::EcdsaKeyPair,
    enrollment_token::{EnrollmentToken, EnrollmentTokenBody},
    error::Result,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_enrollment_token_generation_and_verification() -> Result<()> {
    // Create EA key pair
    let ea_key = EcdsaKeyPair::new()?;
    let ea_public_key = ea_key.public_key().as_bytes().to_vec();

    // Create token body
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let body = EnrollmentTokenBody::new(
        "test_token_123".to_string(),
        "test_network".to_string(),
        Some("test_subject".to_string()),
        now,
        now + 3600, // 1 hour from now
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        vec!["enroll".to_string()],
    );

    // Generate token
    let token = EnrollmentToken::generate(&ea_key, body)?;

    // Verify token
    token.verify(&ea_public_key)?;

    // Validate for enrollment
    token.validate_for_enrollment("test_network")?;

    Ok(())
}

#[test]
fn test_token_validation_errors() -> Result<()> {
    let ea_key = EcdsaKeyPair::new()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Test expired token
    let expired_body = EnrollmentTokenBody::new(
        "expired_token".to_string(),
        "test_network".to_string(),
        None,
        now - 7200, // 2 hours ago
        now - 3600, // 1 hour ago
        [0; 16],
        vec!["enroll".to_string()],
    );
    let expired_token = EnrollmentToken::generate(&ea_key, expired_body)?;
    assert!(expired_token
        .validate_for_enrollment("test_network")
        .is_err());

    // Test wrong network
    let wrong_network_body = EnrollmentTokenBody::new(
        "wrong_network_token".to_string(),
        "wrong_network".to_string(),
        None,
        now,
        now + 3600,
        [0; 16],
        vec!["enroll".to_string()],
    );
    let wrong_network_token = EnrollmentToken::generate(&ea_key, wrong_network_body)?;
    assert!(wrong_network_token
        .validate_for_enrollment("test_network")
        .is_err());

    // Test missing permission
    let no_permission_body = EnrollmentTokenBody::new(
        "no_permission_token".to_string(),
        "test_network".to_string(),
        None,
        now,
        now + 3600,
        [0; 16],
        vec!["renew".to_string()], // No enroll permission
    );
    let no_permission_token = EnrollmentToken::generate(&ea_key, no_permission_body)?;
    assert!(no_permission_token
        .validate_for_enrollment("test_network")
        .is_err());

    Ok(())
}
