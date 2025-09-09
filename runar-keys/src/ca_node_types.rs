use serde::{Deserialize, Serialize};

use crate::enrollment_token::EnrollmentToken;

/// Error response from CA Node operations
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CaErrorResponse {
    /// Error code (e.g., "invalid_token", "csr_invalid", "rate_limited")
    pub code: String,
    /// Human-readable error message
    pub message: String,
}

/// CSR enrollment request
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CsrEnrollRequest {
    /// DER-encoded CSR
    pub csr_der: Vec<u8>,
    /// Enrollment token for authorization
    pub enrollment_token: EnrollmentToken,
}

/// CSR enrollment response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CsrEnrollResponse {
    /// DER-encoded device certificate
    pub certificate_der: Vec<u8>,
    /// DER-encoded issuing CA certificate
    pub issuing_ca_der: Vec<u8>,
    /// DER-encoded root CA certificate (optional)
    pub root_ca_der: Option<Vec<u8>>,
    /// Certificate expiration time (UNIX seconds)
    pub expires_at: u64,
}

/// Certificate renewal request
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RenewRequest {
    /// DER-encoded CSR for renewal
    pub csr_der: Vec<u8>,
}

/// Certificate renewal response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RenewResponse {
    /// DER-encoded renewed certificate
    pub certificate_der: Vec<u8>,
    /// DER-encoded issuing CA certificate
    pub issuing_ca_der: Vec<u8>,
    /// Certificate expiration time (UNIX seconds)
    pub expires_at: u64,
}

/// Certificate revocation request
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RevokeRequest {
    /// Certificate serial number to revoke
    pub certificate_serial: Vec<u8>,
    /// Reason for revocation
    pub reason: String,
}

/// Certificate revocation response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RevokeResponse {
    /// Whether revocation was successful
    pub ok: bool,
}

/// CA certificate chain response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ChainResponse {
    /// DER-encoded issuing CA certificate
    pub issuing_ca_der: Vec<u8>,
    /// DER-encoded root CA certificate (optional)
    pub root_ca_der: Option<Vec<u8>>,
}

/// CA Node status response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CaStatus {
    /// Issuing CA subject
    pub issuing_subject: String,
    /// Issuing CA serial number (hex)
    pub issuing_serial_hex: String,
    /// Certificate valid from (UNIX seconds)
    pub not_before: u64,
    /// Certificate valid until (UNIX seconds)
    pub not_after: u64,
}

/// CRL-lite structure for certificate revocation list
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CaRevocationList {
    /// Network ID this CRL applies to
    pub network_id: String,
    /// Issuing CA serial number (hex)
    pub issuing_ca_serial: Vec<u8>,
    /// List of revoked certificate serials
    pub revoked_serials: Vec<RevokedSerial>,
    /// Next update time (UNIX seconds)
    pub next_update: u64,
    /// ECDSA P-256 DER signature
    pub signature: Vec<u8>,
}

/// Revoked certificate entry
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RevokedSerial {
    /// Certificate serial number
    pub serial: Vec<u8>,
    /// Revocation time (UNIX seconds)
    pub revocation_time: u64,
    /// Reason for revocation
    pub reason: String,
}

/// Rate limiting state for tracking request frequency
#[derive(Clone, Debug)]
pub struct RateLimitState {
    /// Timestamps of recent requests
    pub requests: std::collections::VecDeque<std::time::SystemTime>,
    /// Burst limit (requests per minute)
    pub burst_limit: usize,
    /// Sustained limit (requests per hour)
    pub sustained_limit: usize,
}

impl RateLimitState {
    /// Create a new rate limit state
    pub fn new(burst_limit: usize, sustained_limit: usize) -> Self {
        Self {
            requests: std::collections::VecDeque::new(),
            burst_limit,
            sustained_limit,
        }
    }

    /// Check if a request is allowed under rate limiting
    pub fn is_allowed(&mut self) -> bool {
        let now = std::time::SystemTime::now();

        // Remove old requests outside the time windows
        let one_minute_ago = now - std::time::Duration::from_secs(60);
        let one_hour_ago = now - std::time::Duration::from_secs(3600);

        while let Some(&front) = self.requests.front() {
            if front < one_hour_ago {
                self.requests.pop_front();
            } else {
                break;
            }
        }

        // Check burst limit (last minute)
        let recent_requests = self
            .requests
            .iter()
            .filter(|&&time| time >= one_minute_ago)
            .count();

        if recent_requests >= self.burst_limit {
            return false;
        }

        // Check sustained limit (last hour)
        if self.requests.len() >= self.sustained_limit {
            return false;
        }

        // Add current request
        self.requests.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment_token::EnrollmentTokenBody;
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
        };

        let response = CsrEnrollResponse {
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
            issuing_ca_serial: vec![1, 2, 3, 4],
            revoked_serials: vec![RevokedSerial {
                serial: vec![5, 6, 7, 8],
                revocation_time: 1234567890,
                reason: "compromise".to_string(),
            }],
            next_update: 1234567890 + 3600,
            signature: vec![9, 10, 11, 12],
        };

        let serialized = serde_cbor::to_vec(&crl).unwrap();
        let deserialized: CaRevocationList = serde_cbor::from_slice(&serialized).unwrap();
        assert_eq!(crl, deserialized);
    }
}
