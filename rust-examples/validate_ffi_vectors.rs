use anyhow::{Context, Result};
use runar_keys::ca_node_types::{CaErrorResponse, CsrEnrollRequest, CsrEnrollResponse};
use runar_keys::enrollment_token::{EnrollmentToken, EnrollmentTokenBody};
use runar_keys::mobile::SetupToken;
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
        validate_ca_error_response,
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
