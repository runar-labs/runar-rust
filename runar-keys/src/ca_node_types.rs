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
    /// Network ID for the request
    pub network_id: String,
    /// DER-encoded CSR
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
    /// Network ID for the request
    pub network_id: String,
    /// DER-encoded CSR for renewal
    pub csr_der: Vec<u8>,
}

/// Certificate renewal response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RenewResponse {
    /// Network ID for the response
    pub network_id: String,
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
    /// Network ID for the request
    pub network_id: String,
    /// Certificate serial number to revoke
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
    pub issuing_ca_der: Vec<u8>,
    /// DER-encoded root CA certificate (optional)
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
    pub revoked_serials: Vec<Vec<u8>>,
    /// Generation time (UNIX seconds)
    pub generated_at: u64,
    /// ECDSA P-256 DER signature (raw DER bytes)
    pub signature: Vec<u8>,
    /// Subject Key Identifier of signer
    pub signer_ski: Vec<u8>,
    /// Signature algorithm identifier
    pub sig_alg: String,
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
