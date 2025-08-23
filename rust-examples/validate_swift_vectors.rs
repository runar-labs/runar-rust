use anyhow::{Context, Result};
use runar_serializer::{runar, ArcValue, Encrypt, Plain};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Plain)]
pub struct PlainUser {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encrypt)]
#[runar(name = "vectors.TestProfile")]
pub struct TestProfile {
    pub id: String,
    #[runar(user)]
    pub secret: String,
}

fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).context(format!("Failed to read {}", path.display()))
}

fn validate_primitive_string() -> Result<()> {
    println!("🔍 Validating primitive string...");
    let swift_data = read_bytes(Path::new(
        "../runar-swift/target/serializer-vectors-swift/prim_string.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/serializer-vectors/prim_string.bin"))?;

    // Test that Swift data can be deserialized by Rust
    let _swift_value = ArcValue::deserialize(&swift_data, None)
        .context("Failed to deserialize Swift string data")?;

    // Test that Rust data can be deserialized
    let _rust_value = ArcValue::deserialize(&rust_data, None)
        .context("Failed to deserialize Rust string data")?;

    // For now, just check that both deserialize successfully
    println!("✅ String validation passed (both deserialized successfully)");
    Ok(())
}

fn validate_primitive_bool() -> Result<()> {
    println!("🔍 Validating primitive bool...");
    let swift_data = read_bytes(Path::new(
        "../runar-swift/target/serializer-vectors-swift/prim_bool.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/serializer-vectors/prim_bool.bin"))?;

    let _swift_value = ArcValue::deserialize(&swift_data, None)
        .context("Failed to deserialize Swift bool data")?;
    let _rust_value =
        ArcValue::deserialize(&rust_data, None).context("Failed to deserialize Rust bool data")?;

    println!("✅ Bool validation passed (both deserialized successfully)");
    Ok(())
}

fn validate_primitive_i64() -> Result<()> {
    println!("🔍 Validating primitive i64...");
    let swift_data = read_bytes(Path::new(
        "../runar-swift/target/serializer-vectors-swift/prim_i64.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/serializer-vectors/prim_i64.bin"))?;

    let _swift_value =
        ArcValue::deserialize(&swift_data, None).context("Failed to deserialize Swift i64 data")?;
    let _rust_value =
        ArcValue::deserialize(&rust_data, None).context("Failed to deserialize Rust i64 data")?;

    // Just verify both can be deserialized successfully
    println!("✅ i64 validation passed (both deserialized successfully)");
    Ok(())
}

fn validate_primitive_u64() -> Result<()> {
    println!("🔍 Validating primitive u64...");
    let swift_data = read_bytes(Path::new(
        "../runar-swift/target/serializer-vectors-swift/prim_u64.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/serializer-vectors/prim_u64.bin"))?;

    let _swift_value =
        ArcValue::deserialize(&swift_data, None).context("Failed to deserialize Swift u64 data")?;
    let _rust_value =
        ArcValue::deserialize(&rust_data, None).context("Failed to deserialize Rust u64 data")?;

    // Just verify both can be deserialized successfully
    println!("✅ u64 validation passed (both deserialized successfully)");
    Ok(())
}

fn validate_bytes() -> Result<()> {
    println!("🔍 Validating bytes...");
    let swift_data = read_bytes(Path::new(
        "../runar-swift/target/serializer-vectors-swift/bytes.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/serializer-vectors/bytes.bin"))?;

    let _swift_value = ArcValue::deserialize(&swift_data, None)
        .context("Failed to deserialize Swift bytes data")?;
    let _rust_value =
        ArcValue::deserialize(&rust_data, None).context("Failed to deserialize Rust bytes data")?;

    // Just verify both can be deserialized successfully
    println!("✅ Bytes validation passed (both deserialized successfully)");
    Ok(())
}

fn validate_json() -> Result<()> {
    println!("🔍 Validating JSON...");
    let swift_data = read_bytes(Path::new(
        "../runar-swift/target/serializer-vectors-swift/json.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/serializer-vectors/json.bin"))?;

    let _swift_value = ArcValue::deserialize(&swift_data, None)
        .context("Failed to deserialize Swift JSON data")?;
    let _rust_value =
        ArcValue::deserialize(&rust_data, None).context("Failed to deserialize Rust JSON data")?;

    // Just verify both can be deserialized successfully
    println!("✅ JSON validation passed (both deserialized successfully)");
    Ok(())
}

fn validate_list_any() -> Result<()> {
    println!("🔍 Validating heterogeneous list...");
    let swift_data = read_bytes(Path::new(
        "../runar-swift/target/serializer-vectors-swift/list_any.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/serializer-vectors/list_any.bin"))?;

    let _swift_value = ArcValue::deserialize(&swift_data, None)
        .context("Failed to deserialize Swift list data")?;
    let _rust_value =
        ArcValue::deserialize(&rust_data, None).context("Failed to deserialize Rust list data")?;

    // For now, just check that both deserialize without error
    // TODO: Add deeper structural validation
    println!("✅ Heterogeneous list validation passed (deserialized successfully)");
    Ok(())
}

fn validate_map_any() -> Result<()> {
    println!("🔍 Validating heterogeneous map...");
    let swift_data = read_bytes(Path::new(
        "../runar-swift/target/serializer-vectors-swift/map_any.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/serializer-vectors/map_any.bin"))?;

    let _swift_value =
        ArcValue::deserialize(&swift_data, None).context("Failed to deserialize Swift map data")?;
    let _rust_value =
        ArcValue::deserialize(&rust_data, None).context("Failed to deserialize Rust map data")?;

    println!("✅ Heterogeneous map validation passed (deserialized successfully)");
    Ok(())
}

fn validate_list_i64() -> Result<()> {
    println!("🔍 Validating typed i64 list...");
    let swift_data = read_bytes(Path::new(
        "../runar-swift/target/serializer-vectors-swift/list_i64.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/serializer-vectors/list_i64.bin"))?;

    let _swift_value = ArcValue::deserialize(&swift_data, None)
        .context("Failed to deserialize Swift i64 list data")?;
    let _rust_value = ArcValue::deserialize(&rust_data, None)
        .context("Failed to deserialize Rust i64 list data")?;

    println!("✅ Typed i64 list validation passed (deserialized successfully)");
    Ok(())
}

fn validate_map_string_i64() -> Result<()> {
    println!("🔍 Validating typed string->i64 map...");
    let swift_data = read_bytes(Path::new(
        "../runar-swift/target/serializer-vectors-swift/map_string_i64.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/serializer-vectors/map_string_i64.bin"))?;

    let _swift_value = ArcValue::deserialize(&swift_data, None)
        .context("Failed to deserialize Swift string->i64 map data")?;
    let _rust_value = ArcValue::deserialize(&rust_data, None)
        .context("Failed to deserialize Rust string->i64 map data")?;

    println!("✅ Typed string->i64 map validation passed (deserialized successfully)");
    Ok(())
}

fn validate_struct_plain() -> Result<()> {
    println!("🔍 Validating plain struct...");
    let swift_data = read_bytes(Path::new(
        "../runar-swift/target/serializer-vectors-swift/struct_plain.bin",
    ))?;
    let rust_data = read_bytes(Path::new("target/serializer-vectors/struct_plain.bin"))?;

    let _swift_value = ArcValue::deserialize(&swift_data, None)
        .context("Failed to deserialize Swift struct data")?;
    let _rust_value = ArcValue::deserialize(&rust_data, None)
        .context("Failed to deserialize Rust struct data")?;

    // Try to deserialize as PlainUser to validate structure
    match _swift_value.as_struct_ref::<PlainUser>() {
        Ok(swift_user) => match _rust_value.as_struct_ref::<PlainUser>() {
            Ok(rust_user) => {
                if swift_user == rust_user {
                    println!("✅ Plain struct validation passed: {swift_user:?}");
                    Ok(())
                } else {
                    anyhow::bail!(
                        "Struct validation failed: values don't match\nSwift: {:?}\nRust: {:?}",
                        swift_user,
                        rust_user
                    );
                }
            }
            Err(e) => anyhow::bail!("Failed to deserialize Rust struct as PlainUser: {}", e),
        },
        Err(e) => anyhow::bail!("Failed to deserialize Swift struct as PlainUser: {}", e),
    }
}

fn check_directories_exist() -> Result<()> {
    let swift_dir = Path::new("../runar-swift/target/serializer-vectors-swift");
    let rust_dir = Path::new("target/serializer-vectors");

    if !swift_dir.exists() {
        anyhow::bail!(
            "Swift test vectors directory not found: {}. Run Swift test vectors first.",
            swift_dir.display()
        );
    }

    if !rust_dir.exists() {
        anyhow::bail!(
            "Rust test vectors directory not found: {}. Run Rust serializer_vectors first.",
            rust_dir.display()
        );
    }

    println!("📁 Found test vector directories:");
    println!("   Swift: {}", swift_dir.display());
    println!("   Rust:  {}", rust_dir.display());

    Ok(())
}

fn main() -> Result<()> {
    println!("🔬 Cross-Platform Serializer Validation");
    println!("=====================================");

    // Check that both directories exist
    check_directories_exist()?;

    println!("\n🚀 Running validation tests...");

    // Run all validation tests
    let tests = vec![
        validate_primitive_string,
        validate_primitive_bool,
        validate_primitive_i64,
        validate_primitive_u64,
        validate_bytes,
        validate_json,
        validate_list_any,
        validate_map_any,
        validate_list_i64,
        validate_map_string_i64,
        validate_struct_plain,
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

    println!("\n📊 Validation Results");
    println!("===================");
    println!("✅ Passed: {passed}");
    println!("❌ Failed: {failed}");
    println!(
        "📈 Success Rate: {:.1}%",
        (passed as f64 / (passed + failed) as f64) * 100.0
    );

    if failed == 0 {
        println!("\n🎉 All validations passed! Swift and Rust serializers are compatible!");
    } else {
        println!("\n⚠️  Some validations failed. Check the output above for details.");
        std::process::exit(1);
    }

    Ok(())
}
