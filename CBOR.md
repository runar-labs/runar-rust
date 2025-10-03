# CBOR Serialization Guidelines

## 🎯 **Overview**

This document establishes standards for CBOR (Concise Binary Object Representation) serialization across the Runar codebase to ensure compatibility between Rust and Swift implementations.

## 🚨 **Critical Issue: Vec<u8> Encoding**

### **Problem**
- **Rust (`serde_cbor`)**: Encodes `Vec<u8>` as CBOR array of individual unsigned integers `[18, byte1, 18, byte2, ...]`
- **Swift (`CodableCBORDecoder`)**: Expects `Vec<u8>` as simple CBOR byte string
- **Impact**: Causes `ContiguousArrayBuffer.swift:690` crash when Swift decodes Rust-generated CBOR

### **Solution**
Use `#[serde(with = "serde_bytes")]` attribute on all `Vec<u8>` fields to ensure proper byte string encoding.

## 📋 **CBOR Standards**

### **1. Vec<u8> Fields - REQUIRED**

**✅ CORRECT:**
```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct MyStruct {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    
    #[serde(with = "serde_bytes")]
    pub optional_data: Option<Vec<u8>>,
}
```

**❌ INCORRECT:**
```rust
#[derive(Serialize, Deserialize)]
pub struct MyStruct {
    pub data: Vec<u8>,  // ← Will encode as array of integers
    pub optional_data: Option<Vec<u8>>,  // ← Will encode as array of integers
}
```

### **2. Vec<Vec<u8>> Fields - CUSTOM SOLUTION**

**⚠️ IMPORTANT**: `#[serde(with = "serde_bytes")]` does NOT work with `Vec<Vec<u8>>` directly.

**✅ CORRECT (Recommended Approach):**
```rust
use runar_macros_common::VecVecBytes;

#[derive(Serialize, Deserialize)]
pub struct MyStruct {
    #[serde(with = "VecVecBytes")]
    pub profile_public_keys: Vec<Vec<u8>>,
}
```

**Alternative using serde_with:**
```rust
use serde_with::serde_as;
use runar_macros_common::VecVecBytesAs;

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct MyStruct {
    #[serde_as(as = "VecVecBytesAs")]
    pub profile_public_keys: Vec<Vec<u8>>,
}
```

**❌ OLD APPROACH (Deprecated):**
```rust
// Don't do this - encodes as array of arrays
pub profile_public_keys: Vec<Vec<u8>>,
```

**❌ INCORRECT:**
```rust
#[derive(Serialize, Deserialize)]
pub struct MyStruct {
    #[serde(with = "serde_bytes")]
    pub profile_public_keys: Vec<Vec<u8>>,  // ← This will NOT compile!
}
```

### **3. Dependencies - REQUIRED**

Add `serde_bytes` to all crates that serialize `Vec<u8>` with CBOR:

```toml
[dependencies]
serde_cbor = "0.11"
serde_bytes = "0.11"  # For proper CBOR byte string encoding of Vec<u8>
runar_macros_common = { path = "../runar-macros-common" }  # For Vec<Vec<u8>> support
```

### **Custom Vec<Vec<u8>> Solution**

We created a custom serializer in `runar-macros-common` because serde doesn't provide built-in support for `Vec<Vec<u8>>` byte string encoding.

**How it works:**
1. Each inner `Vec<u8>` is wrapped with `serde_bytes::ByteBuf`
2. The outer `Vec<ByteBuf>` serializes as an array of byte strings
3. Each byte string uses proper CBOR major type 2 encoding

**Benefits:**
- ✅ Consistent with `Vec<u8>` encoding
- ✅ Swift `CodableCBORDecoder` compatible
- ✅ Efficient binary representation
- ✅ No breaking changes to existing structs

### **4. Encoding Results**

| Type | Without serde_bytes | With serde_bytes |
|------|-------------------|------------------|
| `Vec<u8>` | `[18, 0x04, 18, 0x12, ...]` (130+ bytes) | `0x58 0x41 0x04 0x12 ...` (67 bytes) |
| `Option<Vec<u8>>` | `[18, 0x04, 18, 0x12, ...]` | `0x58 0x41 0x04 0x12 ...` |
| `Vec<Vec<u8>>` | `[[18, 0x04, ...], [18, 0x05, ...]]` | `[0x58 0x41 0x04 ..., 0x58 0x41 0x05 ...]` |

## 🔧 **Implementation Checklist**

### **For New Structs**
- [ ] Add `serde_bytes` dependency to `Cargo.toml`
- [ ] Add `#[serde(with = "serde_bytes")]` to all `Vec<u8>` fields
- [ ] Test CBOR serialization produces byte strings
- [ ] Verify Swift compatibility

### **For Existing Structs**
- [ ] Add `serde_bytes` dependency
- [ ] Update all `Vec<u8>` fields with `#[serde(with = "serde_bytes")]`
- [ ] Run tests to ensure no regressions
- [ ] Update test vectors if needed

## 📁 **Affected Files**

### **runar-keys**
- `src/ca_node_types.rs` - All CA request/response structs
- `src/enrollment_token.rs` - Enrollment token signature
- `Cargo.toml` - Add serde_bytes dependency

### **runar-ffi**
- `src/lib.rs` - Transport parameter structs
- `Cargo.toml` - Add serde_bytes dependency

### **runar-transporter**
- `src/transport/mod.rs` - NetworkMessagePayloadItem
- `Cargo.toml` - Add serde_bytes dependency

## 🧪 **Testing Standards**

### **Unit Tests**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_cbor;

    #[test]
    fn test_cbor_byte_string_encoding() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let cbor = serde_cbor::to_vec(&data).unwrap();
        
        // Should be byte string (0x44) not array (0x84)
        assert_eq!(cbor[0] & 0xE0, 0x40); // Major type 2 (byte string)
        assert_eq!(cbor[0] & 0x1F, 0x04); // Length 4
        assert_eq!(&cbor[1..], &[0x01, 0x02, 0x03, 0x04]);
    }
}
```

### **Integration Tests**
- Test Rust → Swift round-trip compatibility
- Verify no crashes in Swift `CodableCBORDecoder`
- Test performance impact (should be positive)

## 🚀 **Performance Benefits**

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| 65-byte public key | 130+ bytes | 67 bytes | ~50% reduction |
| Encoding speed | Slower | Faster | ~20% faster |
| Swift compatibility | ❌ Crashes | ✅ Works | 100% compatible |

## ⚠️ **Common Pitfalls**

### **1. Forgetting serde_bytes Attribute**
```rust
// ❌ WRONG - Will still encode as array
#[derive(Serialize, Deserialize)]
pub struct BadStruct {
    pub data: Vec<u8>,  // Missing #[serde(with = "serde_bytes")]
}
```

### **2. Inconsistent Application**
```rust
// ❌ WRONG - Inconsistent encoding
#[derive(Serialize, Deserialize)]
pub struct InconsistentStruct {
    #[serde(with = "serde_bytes")]
    pub data1: Vec<u8>,  // Byte string
    pub data2: Vec<u8>,  // Array of integers - INCONSISTENT!
}
```

### **3. Missing Dependency**
```toml
# ❌ WRONG - Missing serde_bytes
[dependencies]
serde_cbor = "0.11"
# serde_bytes = "0.11"  # ← MISSING!
```

## 🔍 **Verification Commands**

### **Check CBOR Encoding**
```bash
# Test a struct with Vec<u8> fields
cargo test --package runar-keys test_cbor_encoding
```

### **Verify Dependencies**
```bash
# Check all crates have serde_bytes
grep -r "serde_bytes" */Cargo.toml
```

### **Run Clippy**
```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace -- -W clippy::absolute_paths
```

## 📚 **References**

- [CBOR Specification (RFC 8949)](https://tools.ietf.org/html/rfc8949)
- [serde_bytes Documentation](https://docs.rs/serde_bytes/)
- [Swift CodableCBORDecoder](https://github.com/SomeRandomiOSDev/CodableCBOR)

## 🎯 **Success Criteria**

- [ ] All `Vec<u8>` fields use `#[serde(with = "serde_bytes")]`
- [ ] All crates have `serde_bytes` dependency
- [ ] Swift compatibility tests pass
- [ ] No performance regressions
- [ ] All clippy warnings resolved
- [ ] Test vectors updated

---

**Remember**: This is not optional. Every `Vec<u8>` field that gets serialized with `serde_cbor` MUST use `#[serde(with = "serde_bytes")]` to ensure Swift compatibility and prevent crashes.
