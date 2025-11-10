use runar_macros_common::VecVecBytes;
use serde::{Deserialize, Serialize};
use serde_bytes;

use crate::enrollment_token::EnrollmentToken;

/// Error response from CA Node operations
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CaErrorResponse {
    /// HTTP-style error code (e.g., "unauthorized", "forbidden", "bad_request", "rate_limited")
    pub code: String,
    /// Human-readable error message
    pub message: String,
    /// Specific error reason for programmatic handling (e.g., "csr_cn_mismatch", "replay_detected")
    pub reason: Option<String>,
}

impl CaErrorResponse {
    /// Create a new error response
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
            reason: None,
        }
    }

    /// Create a new error response with specific reason
    pub fn with_reason(code: &str, message: &str, reason: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
            reason: Some(reason.to_string()),
        }
    }

    /// Unauthorized error (401)
    pub fn unauthorized(message: &str) -> Self {
        Self::new("unauthorized", message)
    }

    /// Forbidden error (403)
    pub fn forbidden(message: &str) -> Self {
        Self::new("forbidden", message)
    }

    /// Forbidden error with reason (403)
    pub fn forbidden_with_reason(message: &str, reason: &str) -> Self {
        Self::with_reason("forbidden", message, reason)
    }

    /// Bad request error (400)
    pub fn bad_request(message: &str) -> Self {
        Self::new("bad_request", message)
    }

    /// Bad request error with reason (400)
    pub fn bad_request_with_reason(message: &str, reason: &str) -> Self {
        Self::with_reason("bad_request", message, reason)
    }

    /// Rate limited error (429)
    pub fn rate_limited(message: &str) -> Self {
        Self::new("rate_limited", message)
    }

    /// Internal server error (500)
    pub fn internal(message: &str) -> Self {
        Self::new("internal", message)
    }
}

/// CSR enrollment request
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CsrEnrollRequest {
    /// Network ID for the request
    pub network_id: String,
    /// DER-encoded CSR
    #[serde(with = "serde_bytes")]
    pub csr_der: Vec<u8>,
    /// Enrollment token for authorization
    pub enrollment_token: EnrollmentToken,
}

/// CSR enrollment response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CsrEnrollResponse {
    /// Network ID for the response
    pub network_id: String,
    /// DER-encoded device certificate
    #[serde(with = "serde_bytes")]
    pub certificate_der: Vec<u8>,
    /// DER-encoded issuing CA certificate
    #[serde(with = "serde_bytes")]
    pub issuing_ca_der: Vec<u8>,
    /// DER-encoded root CA certificate (optional)
    #[serde(with = "serde_bytes")]
    pub root_ca_der: Option<Vec<u8>>,
    /// Certificate expiration time (UNIX seconds)
    pub expires_at: u64,
}

/// Certificate renewal request
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RenewRequest {
    /// Network ID for the request
    pub network_id: String,
    /// DER-encoded CSR for renewal
    #[serde(with = "serde_bytes")]
    pub csr_der: Vec<u8>,
}

/// Certificate renewal response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RenewResponse {
    /// Network ID for the response
    pub network_id: String,
    /// DER-encoded renewed certificate
    #[serde(with = "serde_bytes")]
    pub certificate_der: Vec<u8>,
    /// DER-encoded issuing CA certificate
    #[serde(with = "serde_bytes")]
    pub issuing_ca_der: Vec<u8>,
    /// Certificate expiration time (UNIX seconds)
    pub expires_at: u64,
}

/// Certificate revocation request
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RevokeRequest {
    /// Network ID for the request
    pub network_id: String,
    /// Certificate serial number to revoke
    #[serde(with = "serde_bytes")]
    pub certificate_serial: Vec<u8>,
    /// Reason for revocation
    pub reason: String,
}

/// Certificate revocation response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RevokeResponse {
    /// Network ID for the response
    pub network_id: String,
    /// Whether revocation was successful
    pub ok: bool,
}

/// CA certificate chain response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ChainResponse {
    /// Network ID for the response
    pub network_id: String,
    /// DER-encoded issuing CA certificate
    #[serde(with = "serde_bytes")]
    pub issuing_ca_der: Vec<u8>,
    /// DER-encoded root CA certificate (optional)
    #[serde(with = "serde_bytes")]
    pub root_ca_der: Option<Vec<u8>>,
}

/// CA Node status response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CaStatus {
    /// Network ID for the response
    pub network_id: String,
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
    /// Issuing CA serial number (hex string)
    pub issuing_ca_serial_hex: String,
    /// List of revoked certificate serials (raw bytes)
    #[serde(with = "VecVecBytes")]
    pub revoked_serials: Vec<Vec<u8>>,
    /// Generation time (UNIX seconds)
    pub generated_at: u64,
    /// ECDSA P-256 DER signature (raw DER bytes)
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Subject Key Identifier of signer
    #[serde(with = "serde_bytes")]
    pub signer_ski: Vec<u8>,
    /// Signature algorithm identifier
    pub sig_alg: String,
}

/// Revoked certificate entry
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RevokedSerial {
    /// Certificate serial number
    #[serde(with = "serde_bytes")]
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

/// Chain request
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ChainRequest {
    /// Network ID for the request
    pub network_id: String,
}

/// CRL request
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CrlRequest {
    /// Network ID for the request
    pub network_id: String,
}

/// Status request
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StatusRequest {
    /// Network ID for the request
    pub network_id: String,
}

/// CRL response (alias for CaRevocationList)
pub type CrlResponse = CaRevocationList;

/// Status response (alias for CaStatus)
pub type StatusResponse = CaStatus;
