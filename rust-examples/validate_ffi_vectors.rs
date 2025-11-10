use anyhow::{Context, Result};
use runar_ffi::{
    PeerConnectedEvent, TransportCompleteRequestParams, TransportEventEvent,
    TransportPublishParams, TransportRequestEvent, TransportRequestParams, TransportResponseEvent,
};
use runar_keys::ca_node_types::{
    CaErrorResponse, CaStatus, ChainResponse, CsrEnrollRequest, CsrEnrollResponse, RenewRequest,
    RenewResponse, RevokeRequest, RevokeResponse,
};
use runar_keys::enrollment_token::{EnrollmentToken, EnrollmentTokenBody};
use runar_keys::mobile::SetupToken;
use runar_transporter::discovery::multicast_discovery::PeerInfo;
use runar_transporter::transport::{NetworkMessage, NetworkMessagePayloadItem};
// use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).context(format!("Failed to read {}", path.display()))
}

fn validate_enrollment_token_body() -> Result<()> {
    println!("🔍 Validating EnrollmentTokenBody...");

    // Test basic enrollment token body
    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/enrollment_token_body_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/enrollment_token_body_basic.bin",
    ))?;

    let swift_body: EnrollmentTokenBody = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift EnrollmentTokenBody")?;
    let rust_body: EnrollmentTokenBody = serde_cbor::from_slice(&rust_data)
        .context("Failed to deserialize Rust EnrollmentTokenBody")?;

    if swift_body == rust_body {
        println!("✅ EnrollmentTokenBody validation passed");
    } else {
        anyhow::bail!(
            "EnrollmentTokenBody validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_body,
            rust_body
        );
    }

    Ok(())
}

fn validate_enrollment_token() -> Result<()> {
    println!("🔍 Validating EnrollmentToken...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/enrollment_token_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/enrollment_token_basic.bin",
    ))?;

    let swift_token: EnrollmentToken = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift EnrollmentToken")?;
    let rust_token: EnrollmentToken =
        serde_cbor::from_slice(&rust_data).context("Failed to deserialize Rust EnrollmentToken")?;

    if swift_token == rust_token {
        println!("✅ EnrollmentToken validation passed");
    } else {
        anyhow::bail!(
            "EnrollmentToken validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_token,
            rust_token
        );
    }

    Ok(())
}

fn validate_setup_token() -> Result<()> {
    println!("🔍 Validating SetupToken...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/setup_token_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/ffi-types-vectors/setup_token_basic.bin"))?;

    let swift_setup: SetupToken =
        serde_cbor::from_slice(&swift_data).context("Failed to deserialize Swift SetupToken")?;
    let rust_setup: SetupToken =
        serde_cbor::from_slice(&rust_data).context("Failed to deserialize Rust SetupToken")?;

    if swift_setup == rust_setup {
        println!("✅ SetupToken validation passed");
    } else {
        anyhow::bail!(
            "SetupToken validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_setup,
            rust_setup
        );
    }

    Ok(())
}

fn validate_csr_enroll_request() -> Result<()> {
    println!("🔍 Validating CsrEnrollRequest...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/csr_enroll_request_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/csr_enroll_request_basic.bin",
    ))?;

    let swift_request: CsrEnrollRequest = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift CsrEnrollRequest")?;
    let rust_request: CsrEnrollRequest = serde_cbor::from_slice(&rust_data)
        .context("Failed to deserialize Rust CsrEnrollRequest")?;

    if swift_request == rust_request {
        println!("✅ CsrEnrollRequest validation passed");
    } else {
        anyhow::bail!(
            "CsrEnrollRequest validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_request,
            rust_request
        );
    }

    Ok(())
}

fn validate_csr_enroll_response() -> Result<()> {
    println!("🔍 Validating CsrEnrollResponse...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/csr_enroll_response_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/csr_enroll_response_basic.bin",
    ))?;

    let swift_response: CsrEnrollResponse =
        serde_cbor::from_slice(&swift_data).with_context(|| {
            format!(
                "Failed to deserialize Swift CsrEnrollResponse. Data length: {}, hex: {}",
                swift_data.len(),
                hex::encode(&swift_data[..std::cmp::min(swift_data.len(), 100)])
            )
        })?;
    let rust_response: CsrEnrollResponse = serde_cbor::from_slice(&rust_data)
        .context("Failed to deserialize Rust CsrEnrollResponse")?;

    if swift_response == rust_response {
        println!("✅ CsrEnrollResponse validation passed");
    } else {
        anyhow::bail!(
            "CsrEnrollResponse validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_response,
            rust_response
        );
    }

    Ok(())
}

fn validate_ca_error_response() -> Result<()> {
    println!("🔍 Validating CaErrorResponse...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/ca_error_response_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/ca_error_response_basic.bin",
    ))?;

    let swift_error: CaErrorResponse = serde_cbor::from_slice(&swift_data).with_context(|| {
        format!(
            "Failed to deserialize Swift CaErrorResponse. Data length: {}, hex: {}",
            swift_data.len(),
            hex::encode(&swift_data[..std::cmp::min(swift_data.len(), 100)])
        )
    })?;
    let rust_error: CaErrorResponse =
        serde_cbor::from_slice(&rust_data).context("Failed to deserialize Rust CaErrorResponse")?;

    if swift_error == rust_error {
        println!("✅ CaErrorResponse validation passed");
    } else {
        anyhow::bail!(
            "CaErrorResponse validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_error,
            rust_error
        );
    }

    Ok(())
}

fn validate_renew_request() -> Result<()> {
    println!("🔍 Validating RenewRequest...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/renew_request_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/renew_request_basic.bin",
    ))?;

    let swift_request: RenewRequest =
        serde_cbor::from_slice(&swift_data).context("Failed to deserialize Swift RenewRequest")?;
    let rust_request: RenewRequest =
        serde_cbor::from_slice(&rust_data).context("Failed to deserialize Rust RenewRequest")?;

    if swift_request == rust_request {
        println!("✅ RenewRequest validation passed");
    } else {
        anyhow::bail!(
            "RenewRequest validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_request,
            rust_request
        );
    }

    Ok(())
}

fn validate_renew_response() -> Result<()> {
    println!("🔍 Validating RenewResponse...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/renew_response_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/renew_response_basic.bin",
    ))?;

    let swift_response: RenewResponse =
        serde_cbor::from_slice(&swift_data).context("Failed to deserialize Swift RenewResponse")?;
    let rust_response: RenewResponse =
        serde_cbor::from_slice(&rust_data).context("Failed to deserialize Rust RenewResponse")?;

    if swift_response == rust_response {
        println!("✅ RenewResponse validation passed");
    } else {
        anyhow::bail!(
            "RenewResponse validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_response,
            rust_response
        );
    }

    Ok(())
}

fn validate_revoke_request() -> Result<()> {
    println!("🔍 Validating RevokeRequest...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/revoke_request_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/revoke_request_basic.bin",
    ))?;

    let swift_request: RevokeRequest =
        serde_cbor::from_slice(&swift_data).context("Failed to deserialize Swift RevokeRequest")?;
    let rust_request: RevokeRequest =
        serde_cbor::from_slice(&rust_data).context("Failed to deserialize Rust RevokeRequest")?;

    if swift_request == rust_request {
        println!("✅ RevokeRequest validation passed");
    } else {
        anyhow::bail!(
            "RevokeRequest validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_request,
            rust_request
        );
    }

    Ok(())
}

fn validate_revoke_response() -> Result<()> {
    println!("🔍 Validating RevokeResponse...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/revoke_response_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/revoke_response_basic.bin",
    ))?;

    let swift_response: RevokeResponse = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift RevokeResponse")?;
    let rust_response: RevokeResponse =
        serde_cbor::from_slice(&rust_data).context("Failed to deserialize Rust RevokeResponse")?;

    if swift_response == rust_response {
        println!("✅ RevokeResponse validation passed");
    } else {
        anyhow::bail!(
            "RevokeResponse validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_response,
            rust_response
        );
    }

    Ok(())
}

fn validate_ca_status() -> Result<()> {
    println!("🔍 Validating CaStatus...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/ca_status_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/ffi-types-vectors/ca_status_basic.bin"))?;

    let swift_status: CaStatus =
        serde_cbor::from_slice(&swift_data).context("Failed to deserialize Swift CaStatus")?;
    let rust_status: CaStatus =
        serde_cbor::from_slice(&rust_data).context("Failed to deserialize Rust CaStatus")?;

    if swift_status == rust_status {
        println!("✅ CaStatus validation passed");
    } else {
        anyhow::bail!(
            "CaStatus validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_status,
            rust_status
        );
    }

    Ok(())
}

fn validate_chain_response() -> Result<()> {
    println!("🔍 Validating ChainResponse...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/chain_response_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/chain_response_basic.bin",
    ))?;

    let swift_response: ChainResponse =
        serde_cbor::from_slice(&swift_data).context("Failed to deserialize Swift ChainResponse")?;
    let rust_response: ChainResponse =
        serde_cbor::from_slice(&rust_data).context("Failed to deserialize Rust ChainResponse")?;

    if swift_response == rust_response {
        println!("✅ ChainResponse validation passed");
    } else {
        anyhow::bail!(
            "ChainResponse validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_response,
            rust_response
        );
    }

    Ok(())
}

// CrlLite validation removed - type not available

fn check_directories_exist() -> Result<()> {
    let swift_dir = Path::new("../../runar-swift/swift-ffi/target/ffi-types-vectors-swift");
    let rust_dir = Path::new("target/ffi-types-vectors");

    if !swift_dir.exists() {
        anyhow::bail!(
            "Swift FFI types vectors directory not found: {}. Run Swift FFI types vectors first.",
            swift_dir.display()
        );
    }

    if !rust_dir.exists() {
        anyhow::bail!(
            "Rust FFI types vectors directory not found: {}. Run Rust FFI types vectors first.",
            rust_dir.display()
        );
    }

    println!("📁 Found FFI types vector directories:");
    println!("   Swift: {}", swift_dir.display());
    println!("   Rust:  {}", rust_dir.display());

    Ok(())
}

fn validate_quic_transport_options_config() -> Result<()> {
    println!("🔍 Validating QuicTransportOptionsConfig...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/quic_transport_options_config_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/quic_transport_options_config_basic.bin",
    ))?;

    // Deserialize both Swift and Rust data
    let swift_value: runar_ffi::QuicTransportOptionsConfig = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift QuicTransportOptionsConfig")?;
    let rust_value: runar_ffi::QuicTransportOptionsConfig = serde_cbor::from_slice(&rust_data)
        .context("Failed to deserialize Rust QuicTransportOptionsConfig")?;

    // Compare the values
    if swift_value == rust_value {
        println!("✅ QuicTransportOptionsConfig validation passed");
    } else {
        anyhow::bail!(
            "QuicTransportOptionsConfig validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_value,
            rust_value
        );
    }

    Ok(())
}

fn main() -> Result<()> {
    println!("🔬 FFI Types CBOR Cross-Platform Validation");
    println!("===========================================");

    // Check that both directories exist
    check_directories_exist()?;

    println!("\n🚀 Running FFI types validation tests...");

    // Run all validation tests
    let tests = vec![
        validate_enrollment_token_body,
        validate_enrollment_token,
        validate_setup_token,
        validate_csr_enroll_request,
        validate_csr_enroll_response,
        validate_renew_request,
        validate_renew_response,
        validate_revoke_request,
        validate_revoke_response,
        validate_ca_status,
        validate_chain_response,
        validate_ca_error_response,
        // Transport types validation (task11.md requirement)
        // Note: QuicTransportOptions doesn't implement Serialize, so we skip it for now
        validate_peer_info,
        validate_transport_request_params,
        validate_transport_publish_params,
        validate_transport_complete_request_params,
        // Network Message types validation (task13.md requirement)
        validate_network_message_payload_item,
        validate_network_message,
        // Typed Transport Events validation (task18.md requirement)
        validate_peer_connected_event,
        validate_transport_request_event,
        validate_transport_event_event,
        validate_transport_response_event,
        // Transport Config validation (task23.md requirement)
        validate_quic_transport_options_config,
    ];

    let mut passed = 0;
    let mut failed = 0;

    for test in tests {
        match test() {
            Ok(()) => passed += 1,
            Err(e) => {
                println!("❌ Test failed: {e}");
                failed += 1;
            }
        }
    }

    println!("\n📊 FFI Types Validation Results");
    println!("================================");
    println!("✅ Passed: {passed}");
    println!("❌ Failed: {failed}");
    println!(
        "📈 Success Rate: {:.1}%",
        (passed as f64 / (passed + failed) as f64) * 100.0
    );

    if failed == 0 {
        println!("\n🎉 All FFI types validations passed! Swift and Rust CBOR are compatible!");
    } else {
        println!("\n⚠️  Some FFI types validations failed. Check the output above for details.");
        std::process::exit(1);
    }

    Ok(())
}

// QuicTransportOptions doesn't implement Serialize, so we skip it for now

fn validate_peer_info() -> Result<()> {
    println!("🔍 Validating PeerInfo...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/peer_info_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/ffi-types-vectors/peer_info_basic.bin"))?;

    let swift_peer: PeerInfo =
        serde_cbor::from_slice(&swift_data).context("Failed to deserialize Swift PeerInfo")?;
    let rust_peer: PeerInfo =
        serde_cbor::from_slice(&rust_data).context("Failed to deserialize Rust PeerInfo")?;

    if swift_peer == rust_peer {
        println!("✅ PeerInfo validation passed");
    } else {
        anyhow::bail!(
            "PeerInfo validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_peer,
            rust_peer
        );
    }

    Ok(())
}

fn validate_transport_request_params() -> Result<()> {
    println!("🔍 Validating TransportRequestParams...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/transport_request_params_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/transport_request_params_basic.bin",
    ))?;

    let swift_request: TransportRequestParams = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift TransportRequestParams")?;
    let rust_request: TransportRequestParams = serde_cbor::from_slice(&rust_data)
        .context("Failed to deserialize Rust TransportRequestParams")?;

    if swift_request == rust_request {
        println!("✅ TransportRequestParams validation passed");
    } else {
        anyhow::bail!(
            "TransportRequestParams validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_request,
            rust_request
        );
    }

    Ok(())
}

fn validate_transport_publish_params() -> Result<()> {
    println!("🔍 Validating TransportPublishParams...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/transport_publish_params_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/transport_publish_params_basic.bin",
    ))?;

    let swift_publish: TransportPublishParams = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift TransportPublishParams")?;
    let rust_publish: TransportPublishParams = serde_cbor::from_slice(&rust_data)
        .context("Failed to deserialize Rust TransportPublishParams")?;

    if swift_publish == rust_publish {
        println!("✅ TransportPublishParams validation passed");
    } else {
        anyhow::bail!(
            "TransportPublishParams validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_publish,
            rust_publish
        );
    }

    Ok(())
}

fn validate_transport_complete_request_params() -> Result<()> {
    println!("🔍 Validating TransportCompleteRequestParams...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/transport_complete_request_params_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/transport_complete_request_params_basic.bin",
    ))?;

    let swift_complete: TransportCompleteRequestParams = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift TransportCompleteRequestParams")?;
    let rust_complete: TransportCompleteRequestParams = serde_cbor::from_slice(&rust_data)
        .context("Failed to deserialize Rust TransportCompleteRequestParams")?;

    if swift_complete == rust_complete {
        println!("✅ TransportCompleteRequestParams validation passed");
    } else {
        anyhow::bail!(
            "TransportCompleteRequestParams validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_complete,
            rust_complete
        );
    }

    Ok(())
}

fn validate_network_message_payload_item() -> Result<()> {
    println!("🔍 Validating NetworkMessagePayloadItem...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/network_message_payload_item_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/network_message_payload_item_basic.bin",
    ))?;

    let swift_payload: NetworkMessagePayloadItem = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift NetworkMessagePayloadItem")?;
    let rust_payload: NetworkMessagePayloadItem = serde_cbor::from_slice(&rust_data)
        .context("Failed to deserialize Rust NetworkMessagePayloadItem")?;

    if swift_payload == rust_payload {
        println!("✅ NetworkMessagePayloadItem validation passed");
    } else {
        anyhow::bail!(
            "NetworkMessagePayloadItem validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_payload,
            rust_payload
        );
    }

    Ok(())
}

fn validate_network_message() -> Result<()> {
    println!("🔍 Validating NetworkMessage...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/network_message_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/network_message_basic.bin",
    ))?;

    let swift_message: NetworkMessage = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift NetworkMessage")?;
    let rust_message: NetworkMessage =
        serde_cbor::from_slice(&rust_data).context("Failed to deserialize Rust NetworkMessage")?;

    if swift_message == rust_message {
        println!("✅ NetworkMessage validation passed");
    } else {
        anyhow::bail!(
            "NetworkMessage validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_message,
            rust_message
        );
    }

    Ok(())
}

// MARK: - Typed Transport Events Validation (task18.md requirement)

fn validate_peer_connected_event() -> Result<()> {
    println!("🔍 Validating PeerConnectedEvent...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/peer_connected_event_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/peer_connected_event_basic.bin",
    ))?;

    let swift_event: PeerConnectedEvent = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift PeerConnectedEvent")?;
    let rust_event: PeerConnectedEvent = serde_cbor::from_slice(&rust_data)
        .context("Failed to deserialize Rust PeerConnectedEvent")?;

    if swift_event == rust_event {
        println!("✅ PeerConnectedEvent validation passed");
    } else {
        anyhow::bail!(
            "PeerConnectedEvent validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_event,
            rust_event
        );
    }

    Ok(())
}

fn validate_transport_request_event() -> Result<()> {
    println!("🔍 Validating TransportRequestEvent...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/transport_request_event_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/transport_request_event_basic.bin",
    ))?;

    let swift_event: TransportRequestEvent = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift TransportRequestEvent")?;
    let rust_event: TransportRequestEvent = serde_cbor::from_slice(&rust_data)
        .context("Failed to deserialize Rust TransportRequestEvent")?;

    if swift_event == rust_event {
        println!("✅ TransportRequestEvent validation passed");
    } else {
        anyhow::bail!(
            "TransportRequestEvent validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_event,
            rust_event
        );
    }

    Ok(())
}

fn validate_transport_event_event() -> Result<()> {
    println!("🔍 Validating TransportEventEvent...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/transport_event_event_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/transport_event_event_basic.bin",
    ))?;

    let swift_event: TransportEventEvent = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift TransportEventEvent")?;
    let rust_event: TransportEventEvent = serde_cbor::from_slice(&rust_data)
        .context("Failed to deserialize Rust TransportEventEvent")?;

    if swift_event == rust_event {
        println!("✅ TransportEventEvent validation passed");
    } else {
        anyhow::bail!(
            "TransportEventEvent validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_event,
            rust_event
        );
    }

    Ok(())
}

fn validate_transport_response_event() -> Result<()> {
    println!("🔍 Validating TransportResponseEvent...");

    let swift_data = read_bytes(Path::new(
        "../../runar-swift/swift-ffi/target/ffi-types-vectors-swift/transport_response_event_basic.bin",
    ))?;
    let rust_data = read_bytes(Path::new(
        "target/ffi-types-vectors/transport_response_event_basic.bin",
    ))?;

    let swift_event: TransportResponseEvent = serde_cbor::from_slice(&swift_data)
        .context("Failed to deserialize Swift TransportResponseEvent")?;
    let rust_event: TransportResponseEvent = serde_cbor::from_slice(&rust_data)
        .context("Failed to deserialize Rust TransportResponseEvent")?;

    if swift_event == rust_event {
        println!("✅ TransportResponseEvent validation passed");
    } else {
        anyhow::bail!(
            "TransportResponseEvent validation failed:\nSwift: {:?}\nRust: {:?}",
            swift_event,
            rust_event
        );
    }

    Ok(())
}
