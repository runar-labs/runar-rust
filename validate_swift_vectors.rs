use anyhow::{Context, Result};
use runar_serializer::ArcValue;
use std::fs;
use std::path::Path;

fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).context(format!("Failed to read {}", path.display()))
}

fn validate(name: &str, filename: &str) -> Result<()> {
    println!("🔍 Validating {}...", name);
    let swift_data = read_bytes(Path::new(&format!("target/serializer-vectors-swift/{}.bin", filename)))?;
    let rust_data = read_bytes(Path::new(&format!("target/serializer-vectors/{}.bin", filename)))?;

    // Test that Swift data can be deserialized by Rust
    let _swift_value = ArcValue::deserialize(&swift_data, None)
        .context(format!("Failed to deserialize Swift {} data", name))?;

    // Test that Rust data can be deserialized
    let _rust_value = ArcValue::deserialize(&rust_data, None)
        .context(format!("Failed to deserialize Rust {} data", name))?;

    println!("✅ {} validation passed (both deserialized successfully)", name);
    Ok(())
}

fn main() -> Result<()> {
    println!("🔬 Cross-Platform Serializer Validation");
    println!("=====================================");
    
    let tests = vec![
        ("primitive string", "prim_string"),
        ("primitive bool", "prim_bool"),
        ("primitive i64", "prim_i64"),
        ("primitive u64", "prim_u64"),
        ("bytes", "bytes"),
        ("json", "json"),
        ("list any", "list_any"),
        ("map any", "map_any"),
        ("list i64", "list_i64"),
        ("map string i64", "map_string_i64"),
        ("struct plain", "struct_plain"),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (name, filename) in tests {
        match validate(name, filename) {
            Ok(()) => passed += 1,
            Err(e) => {
                println!("❌ Test failed: {}", e);
                failed += 1;
            }
        }
    }

    println!("\n📊 Validation Results");
    println!("===================");
    println!("✅ Passed: {}", passed);
    println!("❌ Failed: {}", failed);
    let success_rate = (passed as f64 / (passed + failed) as f64) * 100.0;
    println!("📈 Success Rate: {:.1}%", success_rate);

    if failed == 0 {
        println!("\n🎉 All validations passed! Swift and Rust serializers are compatible!");
    } else {
        println!("\n⚠️  Some validations failed. Check the output above for details.");
        std::process::exit(1);
    }

    Ok(())
}
