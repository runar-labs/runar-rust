use crate::p2p::crypto::{AccessToken, NetworkId, PeerId};
use anyhow;
use anyhow::Result;
use base64;
use qrcodegen::{QrCode, QrCodeEcc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct NetworkQr {
    r#type: String,
    network_id: String,
    name: String,
    admin_pubkey: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenQr {
    r#type: String,
    peer_id: String,
    network_id: String,
    expiration: Option<u64>,
    signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct PeerQr {
    r#type: String,
    peer_id: String,
    network_id: String,
    address: String,
    token: String,
}

pub fn generate_network_qr(
    network_id: NetworkId,
    name: String,
    admin_pubkey: ed25519_dalek::PublicKey,
    signature: Vec<u8>,
) -> Result<String> {
    let qr = NetworkQr {
        r#type: "network".to_string(),
        network_id: base64::encode(network_id.0),
        name,
        admin_pubkey: base64::encode(admin_pubkey.to_bytes()),
        signature: base64::encode(signature),
    };
    let serialized = serde_json::to_string(&qr)?;
    let qr_code = QrCode::encode_text(&serialized, QrCodeEcc::Medium)?;

    // Convert to string data instead of SVG
    let data = qr_code_to_string(&qr_code);
    Ok(data)
}

pub fn generate_token_qr(token: AccessToken) -> Result<String> {
    let qr = TokenQr {
        r#type: "token".to_string(),
        peer_id: base64::encode(token.peer_id.0),
        network_id: base64::encode(token.network_id.0),
        expiration: token.expiration,
        signature: base64::encode(token.signature),
    };
    let serialized = serde_json::to_string(&qr)?;
    let qr_code = QrCode::encode_text(&serialized, QrCodeEcc::Medium)?;

    // Convert to string data instead of SVG
    let data = qr_code_to_string(&qr_code);
    Ok(data)
}

pub fn generate_peer_qr(
    peer_id: PeerId,
    network_id: NetworkId,
    address: String,
    token: AccessToken,
) -> Result<String> {
    let qr = PeerQr {
        r#type: "peer".to_string(),
        peer_id: base64::encode(peer_id.0),
        network_id: base64::encode(network_id.0),
        address,
        token: base64::encode(bincode::serialize(&token)?),
    };
    let serialized = serde_json::to_string(&qr)?;
    let qr_code = QrCode::encode_text(&serialized, QrCodeEcc::Medium)?;

    // Convert to string data instead of SVG
    let data = qr_code_to_string(&qr_code);
    Ok(data)
}

// Helper function to convert QrCode to a string representation
fn qr_code_to_string(qr_code: &QrCode) -> String {
    let mut result = String::new();
    let size = qr_code.size() as usize;
    for y in 0..size {
        for x in 0..size {
            if qr_code.get_module(x as i32, y as i32) {
                result.push('■');
            } else {
                result.push('□');
            }
        }
        result.push('\n');
    }
    result
}

pub fn parse_qr(data: &str) -> Result<(Option<NetworkQr>, Option<TokenQr>, Option<PeerQr>)> {
    let json: serde_json::Value = serde_json::from_str(data)?;
    match json.get("type").and_then(|t| t.as_str()) {
        Some("network") => Ok((Some(serde_json::from_value(json)?), None, None)),
        Some("token") => Ok((None, Some(serde_json::from_value(json)?), None)),
        Some("peer") => Ok((None, None, Some(serde_json::from_value(json)?))),
        _ => Err(anyhow::anyhow!("Unknown QR type")),
    }
}
