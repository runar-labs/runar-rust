//! CA Node Wire Protocol Types
//!
//! This module defines the wire-level message types for the CA Node QUIC protocol.
//! These types include network_id, versioning, and message discriminants for the
//! binary protocol used over QUIC connections.
//!
//! The binary protocol format is:
//! - 8-byte header: [Message Type (u32)] + [Payload Length (u32)]
//! - CBOR payload containing the message data

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// CA Protocol Version
pub const CA_PROTOCOL_VERSION: u16 = 1;

/// Binary protocol message header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaMessageHeader {
    pub message_type: u32,
    pub payload_length: u32,
}

/// CA Message Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaMessageType {
    CsrEnrollRequest = 0x0001,
    CsrEnrollResponse = 0x0002,
    RenewRequest = 0x0003,
    RenewResponse = 0x0004,
    RevokeRequest = 0x0005,
    RevokeResponse = 0x0006,
    ChainRequest = 0x0007,
    ChainResponse = 0x0008,
    CrlRequest = 0x0009,
    CrlResponse = 0x000A,
    StatusRequest = 0x000B,
    StatusResponse = 0x000C,
    ErrorResponse = 0x000D,
}

impl CaMessageType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x0001 => Some(CaMessageType::CsrEnrollRequest),
            0x0002 => Some(CaMessageType::CsrEnrollResponse),
            0x0003 => Some(CaMessageType::RenewRequest),
            0x0004 => Some(CaMessageType::RenewResponse),
            0x0005 => Some(CaMessageType::RevokeRequest),
            0x0006 => Some(CaMessageType::RevokeResponse),
            0x0007 => Some(CaMessageType::ChainRequest),
            0x0008 => Some(CaMessageType::ChainResponse),
            0x0009 => Some(CaMessageType::CrlRequest),
            0x000A => Some(CaMessageType::CrlResponse),
            0x000B => Some(CaMessageType::StatusRequest),
            0x000C => Some(CaMessageType::StatusResponse),
            0x000D => Some(CaMessageType::ErrorResponse),
            _ => None,
        }
    }
}

/// Request context containing connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub remote_addr: SocketAddr,
    pub peer_leaf_cert_der: Option<Vec<u8>>,
}

/// Renew request context for device-based authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewRequestContext {
    pub peer_leaf_cert_der: Vec<u8>,
    pub csr_der: Vec<u8>,
    pub network_id: String,
}

/// Error response with specific codes and reasons
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaErrorResponse {
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
}

/// Enrollment token body (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentTokenBody {
    pub token_id: String,
    pub network_id: String,
    pub permissions: Vec<String>,
    pub expires_at: u64,
    pub nonce: Option<String>,
}

/// Enrollment token (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentToken {
    pub body: EnrollmentTokenBody,
    pub signature: Vec<u8>,
    pub signer_id: String,
}

/// CSR Enrollment Request (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrEnrollRequest {
    pub network_id: String,
    pub version: u16,
    pub csr_der: Vec<u8>,
    pub token: EnrollmentToken,
}

/// CSR Enrollment Response (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrEnrollResponse {
    pub network_id: String,
    pub version: u16,
    pub certificate_der: Vec<u8>,
    pub issuing_ca_der: Vec<u8>,
    pub root_ca_der: Option<Vec<u8>>,
    pub expires_at: u64,
}

/// Renew Request (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewRequest {
    pub network_id: String,
    pub version: u16,
    pub csr_der: Vec<u8>,
}

/// Renew Response (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewResponse {
    pub network_id: String,
    pub version: u16,
    pub certificate_der: Vec<u8>,
    pub issuing_ca_der: Vec<u8>,
    pub expires_at: u64,
}

/// Revoke Request (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub network_id: String,
    pub version: u16,
    pub certificate_serial: Vec<u8>,
    pub reason: String,
}

/// Revoke Response (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeResponse {
    pub network_id: String,
    pub version: u16,
    pub ok: bool,
}

/// Chain Request (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainRequest {
    pub network_id: String,
    pub version: u16,
}

/// Chain Response (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainResponse {
    pub network_id: String,
    pub version: u16,
    pub issuing_ca_der: Vec<u8>,
    pub root_ca_der: Option<Vec<u8>>,
}

/// CRL Request (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlRequest {
    pub network_id: String,
    pub version: u16,
}

/// CRL Response (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlResponse {
    pub network_id: String,
    pub version: u16,
    pub crl: CaRevocationList,
}

/// CA Revocation List (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaRevocationList {
    pub network_id: String,
    pub issuing_ca_serial_hex: String,
    pub revoked_serials: Vec<Vec<u8>>,
    pub generated_at: u64,
    pub signature: Vec<u8>,
    pub signer_ski: Vec<u8>,
    pub sig_alg: String,
}

/// Status Request (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusRequest {
    pub network_id: String,
    pub version: u16,
}

/// Status Response (wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub network_id: String,
    pub version: u16,
    pub status: String,
    pub uptime: u64,
    pub issued_certificates: u64,
    pub revoked_certificates: u64,
}

// Conversion implementations from wire types to internal types

impl From<CsrEnrollRequest> for runar_keys::ca_node_types::CsrEnrollRequest {
    fn from(wire: CsrEnrollRequest) -> Self {
        Self {
            csr_der: wire.csr_der,
            token: runar_keys::enrollment_token::EnrollmentToken {
                body: runar_keys::enrollment_token::EnrollmentTokenBody {
                    token_id: wire.token.body.token_id,
                    network_id: wire.token.body.network_id,
                    permissions: wire.token.body.permissions,
                    expires_at: wire.token.body.expires_at,
                    nonce: wire.token.body.nonce,
                },
                signature: wire.token.signature,
                signer_id: wire.token.signer_id,
            },
        }
    }
}

impl From<runar_keys::ca_node_types::CsrEnrollResponse> for CsrEnrollResponse {
    fn from(internal: runar_keys::ca_node_types::CsrEnrollResponse) -> Self {
        Self {
            network_id: internal.network_id,
            version: CA_PROTOCOL_VERSION,
            certificate_der: internal.certificate_der,
            issuing_ca_der: internal.issuing_ca_der,
            root_ca_der: internal.root_ca_der,
            expires_at: internal.expires_at,
        }
    }
}

impl From<RenewRequest> for runar_keys::ca_node_types::RenewRequest {
    fn from(wire: RenewRequest) -> Self {
        Self {
            csr_der: wire.csr_der,
        }
    }
}

impl From<runar_keys::ca_node_types::RenewResponse> for RenewResponse {
    fn from(internal: runar_keys::ca_node_types::RenewResponse) -> Self {
        Self {
            network_id: internal.network_id,
            version: CA_PROTOCOL_VERSION,
            certificate_der: internal.certificate_der,
            issuing_ca_der: internal.issuing_ca_der,
            expires_at: internal.expires_at,
        }
    }
}

impl From<RevokeRequest> for runar_keys::ca_node_types::RevokeRequest {
    fn from(wire: RevokeRequest) -> Self {
        Self {
            certificate_serial: wire.certificate_serial,
            reason: wire.reason,
        }
    }
}

impl From<runar_keys::ca_node_types::RevokeResponse> for RevokeResponse {
    fn from(internal: runar_keys::ca_node_types::RevokeResponse) -> Self {
        Self {
            network_id: internal.network_id,
            version: CA_PROTOCOL_VERSION,
            ok: internal.ok,
        }
    }
}

impl From<ChainRequest> for runar_keys::ca_node_types::ChainRequest {
    fn from(_wire: ChainRequest) -> Self {
        Self {}
    }
}

impl From<runar_keys::ca_node_types::ChainResponse> for ChainResponse {
    fn from(internal: runar_keys::ca_node_types::ChainResponse) -> Self {
        Self {
            network_id: internal.network_id,
            version: CA_PROTOCOL_VERSION,
            issuing_ca_der: internal.issuing_ca_der,
            root_ca_der: internal.root_ca_der,
        }
    }
}

impl From<CrlRequest> for runar_keys::ca_node_types::CrlRequest {
    fn from(_wire: CrlRequest) -> Self {
        Self {}
    }
}

impl From<runar_keys::ca_node_types::CaRevocationList> for CaRevocationList {
    fn from(internal: runar_keys::ca_node_types::CaRevocationList) -> Self {
        Self {
            network_id: internal.network_id,
            issuing_ca_serial_hex: internal.issuing_ca_serial_hex,
            revoked_serials: internal.revoked_serials,
            generated_at: internal.generated_at,
            signature: internal.signature,
            signer_ski: internal.signer_ski,
            sig_alg: internal.sig_alg,
        }
    }
}

impl From<runar_keys::ca_node_types::CrlResponse> for CrlResponse {
    fn from(internal: runar_keys::ca_node_types::CrlResponse) -> Self {
        Self {
            network_id: internal.network_id,
            version: CA_PROTOCOL_VERSION,
            crl: internal.crl.into(),
        }
    }
}

impl From<StatusRequest> for runar_keys::ca_node_types::StatusRequest {
    fn from(_wire: StatusRequest) -> Self {
        Self {}
    }
}

impl From<runar_keys::ca_node_types::CaStatus> for StatusResponse {
    fn from(internal: runar_keys::ca_node_types::CaStatus) -> Self {
        Self {
            network_id: internal.network_id,
            version: CA_PROTOCOL_VERSION,
            status: internal.status,
            uptime: internal.uptime,
            issued_certificates: internal.issued_certificates,
            revoked_certificates: internal.revoked_certificates,
        }
    }
}
