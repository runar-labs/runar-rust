# Serde Format Integration - Implementation Plan

## Overview

This document provides a detailed step-by-step implementation plan for integrating encryption directly into serde's data format, eliminating the custom `Serializable` trait while preserving the existing label-based encryption mechanism.

## Phase 1: Remove Serializable Trait (Week 1)

### Step 1.1: Remove Serializable Trait

**File**: `src/traits.rs`

```rust
// Remove this trait completely
// pub trait Serializable { ... }

// Keep only the essential traits:
pub trait RunarSerializer {
    fn from_plain_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self>;
    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&Arc<KeyStore>>) -> Result<Self>;
    fn to_binary(&self, context: Option<&SerializationContext>) -> Result<Vec<u8>>;
}
```

### Step 1.2: Create Unified Serialization Functions

**File**: `src/lib.rs` (add to public API)

```rust
// Unified API - works for both encrypted and non-encrypted data
pub fn serialize_with_context<T: Serialize>(
    value: &T,
    context: SerializationContext,
) -> Result<Vec<u8>> {
    // For Encrypted* types: use existing serde_cbor serialization
    // For regular types: use serde_cbor directly
    serde_cbor::to_vec(value).map_err(anyhow::Error::from)
}

pub fn deserialize_with_context<T: DeserializeOwned>(
    data: &[u8],
    keystore: Option<Arc<KeyStore>>,
) -> Result<T> {
    // For Encrypted* types: deserialize then decrypt
    // For regular types: use serde_cbor directly
    serde_cbor::from_slice(data).map_err(anyhow::Error::from)
}

// Users can always use this unified API:
// let data = serialize_with_context(&my_struct, context)?;
// let my_struct: MyStruct = deserialize_with_context(&data, Some(keystore))?;
```

### Step 1.3: Update ArcValue Integration

**File**: `src/arc_value.rs`

```rust
impl ArcValue {
    pub fn serialize(&self, context: Option<&SerializationContext>) -> Result<Vec<u8>> {
        // Use existing SerializedArcValue format with serde_cbor
        let serialized = self.to_serializable(context)?;
        serde_cbor::to_vec(&serialized).map_err(anyhow::Error::from)
    }
    
    pub fn deserialize(bytes: &[u8], keystore: Option<Arc<KeyStore>>) -> Result<Self> {
        // Use existing deserialization mechanism
        // Lazy deserialization preserved
        // ... existing implementation ...
    }
}
```

## Phase 2: Update Macros (Week 2)

### Step 2.1: Remove Serializable Macro

**File**: `runar-serializer-macros/src/lib.rs`

```rust
// Remove this entire function
// #[proc_macro_derive(Serializable)]
// pub fn derive_serializable(input: TokenStream) -> TokenStream { ... }
```

### Step 2.2: Keep Encrypt Macro Unchanged

**File**: `runar-serializer-macros/src/lib.rs`

```rust
// Keep existing Encrypt macro exactly as-is
// It already generates:
// - Encrypted* structs with serde_cbor serialization
// - Label groups with envelope encryption
// - All encryption/decryption logic

#[proc_macro_derive(Encrypt, attributes(runar))]
pub fn derive_encrypt(input: TokenStream) -> TokenStream {
    // Existing implementation - NO CHANGES NEEDED
    // This already works perfectly with serde_cbor
}
```

### Step 2.3: Update Generated Code to Use Serde

**File**: `runar-serializer-macros/src/lib.rs` (update generated code)

```rust
// Update the generated RunarSerializer implementations to use serde_cbor
impl runar_serializer::RunarSerializer for #struct_name {
    fn from_plain_bytes(bytes: &[u8], keystore: Option<&std::sync::Arc<runar_serializer::KeyStore>>) -> anyhow::Result<Self> {
        // For regular structs: use serde_cbor directly
        serde_cbor::from_slice(bytes).map_err(anyhow::Error::from)
    }

    fn from_encrypted_bytes(bytes: &[u8], keystore: Option<&std::sync::Arc<runar_serializer::KeyStore>>) -> anyhow::Result<Self> {
        // For encrypted structs: deserialize Encrypted* type then decrypt
        let ks = keystore.ok_or(anyhow::anyhow!("KeyStore required for decryption"))?;
        let encrypted = serde_cbor::from_slice::<#encrypted_name>(bytes)?;
        encrypted.decrypt_with_keystore(ks)
    }

    fn to_binary(&self, context: Option<&runar_serializer::SerializationContext>) -> anyhow::Result<Vec<u8>> {
        // For regular structs: use serde_cbor directly
        serde_cbor::to_vec(self).map_err(anyhow::Error::from)
    }
}
```

## Phase 3: Integration & Testing (Week 3)

### Step 3.1: Update Test Infrastructure

**File**: `tests/serde_integration_test.rs`

```rust
#[test]
fn test_label_based_encryption() {
    #[derive(Serialize, Deserialize, Debug, PartialEq, Encrypt)]
    struct UserProfile {
        id: String,                    // Plain text
        #[runar("user")]               // Grouped with other "user" fields
        private_data: String,
        #[runar("user")]               // Same group as private_data
        email: String,
        #[runar("system")]             // Different group
        system_metadata: String,
    }
    
    let original = UserProfile {
        id: "123".to_string(),
        private_data: "secret".to_string(),
        email: "user@example.com".to_string(),
        system_metadata: "sys_data".to_string(),
    };
    
    // Test encryption (creates EncryptedUserProfile)
    let context = build_test_context();
    let encrypted = original.encrypt_with_keystore(&context.keystore, context.resolver.as_ref())?;
    
    // Test serialization (uses serde_cbor)
    let data = serde_cbor::to_vec(&encrypted)?;
    
    // Test deserialization and decryption
    let encrypted_deserialized: EncryptedUserProfile = serde_cbor::from_slice(&data)?;
    let decrypted = encrypted_deserialized.decrypt_with_keystore(&context.keystore)?;
    
    assert_eq!(original, decrypted);
}
```

### Step 3.2: Test ArcValue Integration

**File**: `tests/arc_value_serde_test.rs`

```rust
#[test]
fn test_arc_value_with_serde() {
    // Test that ArcValue works with new serde-based serialization
    let profile = UserProfile { /* ... */ };
    let arc_value = ArcValue::new_struct(profile);
    
    let context = build_test_context();
    let data = arc_value.serialize(Some(&context))?;
    
    let deserialized = ArcValue::deserialize(&data, Some(context.keystore))?;
    let recovered: UserProfile = deserialized.as_struct_ref()?.as_ref().clone();
    
    assert_eq!(profile, recovered);
}
```

### Step 3.3: Test Nested Types

**File**: `tests/nested_types_test.rs`

```rust
#[test]
fn test_nested_arc_value_serialization() {
    // Test HashMap<String, ArcValue> and Vec<ArcValue>
    let mut map = HashMap::new();
    map.insert("user1".to_string(), ArcValue::new_struct(UserProfile { /* ... */ }));
    map.insert("user2".to_string(), ArcValue::new_struct(UserProfile { /* ... */ }));
    
    let arc_value = ArcValue::new_map(map);
    let context = build_test_context();
    let data = arc_value.serialize(Some(&context))?;
    
    let deserialized = ArcValue::deserialize(&data, Some(context.keystore))?;
    let recovered_map = deserialized.as_map_ref()?;
    
    // Verify all fields are correctly deserialized
    assert_eq!(recovered_map.len(), 2);
}
```

## Phase 4: Migration & Cleanup (Week 4)

### Step 4.1: Update All Existing Tests

**Files to update**:
- `tests/basic_serialization_test.rs`
- `tests/composite_container_test.rs`
- `tests/proto_macro_test.rs`
- `tests/arc_value_test.rs`
- `tests/encryption_test.rs`

**Changes**:
- Remove `#[derive(Serializable)]`
- Add `#[derive(Serialize, Deserialize)]`
- Keep `#[derive(Encrypt)]` unchanged
- Update test assertions to use new API

### Step 4.2: Update Documentation

**File**: `README.md`

```markdown
## Quick Start

```rust
use runar_serializer::{Serialize, Deserialize, Encrypt};

#[derive(Serialize, Deserialize, Encrypt)]
struct UserProfile {
    id: String,
    #[runar("user")]               // Label-based encryption
    private_data: String,
    #[runar("user")]               // Same group as private_data
    email: String,
}

// Serialize with encryption context
let context = SerializationContext::new(keystore, resolver);
let encrypted = profile.encrypt_with_keystore(&context.keystore, context.resolver.as_ref())?;
let data = serde_cbor::to_vec(&encrypted)?;

// Deserialize and decrypt
let encrypted_profile: EncryptedUserProfile = serde_cbor::from_slice(&data)?;
let profile = encrypted_profile.decrypt_with_keystore(&keystore)?;
```
```

### Step 4.3: Create Migration Guide

**File**: `MIGRATION_GUIDE.md`

```markdown
# Migration Guide: Serializable to Serde

## Before (Old API)
```rust
#[derive(Serializable, Encrypt)]
struct MyStruct {
    #[runar("user")]
    field: String,
}

let data = my_struct.to_binary(&context)?;
```

## After (New API)
```rust
#[derive(Serialize, Deserialize, Encrypt)]
struct MyStruct {
    #[runar("user")]
    field: String,
}

// Use existing label-based encryption mechanism
let encrypted = my_struct.encrypt_with_keystore(&keystore, resolver)?;
let data = serde_cbor::to_vec(&encrypted)?;
```

## Key Changes
- Remove `Serializable` trait - use `Serialize`/`Deserialize` instead
- Keep `Encrypt` macro unchanged - label-based encryption preserved
- Use `serde_cbor` for serialization of Encrypted* types
- Envelope encryption mechanism unchanged
```

### Step 4.4: Finalize Clean API

**Files to finalize**:
- Remove `Serializable` trait from `src/traits.rs`
- Remove `Serializable` macro from `runar-serializer-macros`
- Ensure all dependent code uses new API
- Update workspace dependencies

## Testing Checklist

### Unit Tests
- [ ] Label-based encryption (existing mechanism)
- [ ] Encrypted* struct serialization with serde_cbor
- [ ] Context propagation
- [ ] Error handling

### Integration Tests
- [ ] End-to-end label encryption workflows
- [ ] ArcValue integration and lazy deserialization
- [ ] Macro-generated code
- [ ] Type-erased serialization

### Performance Tests
- [ ] Serialization speed comparison
- [ ] Memory usage analysis
- [ ] Encryption overhead measurement
- [ ] Benchmark against old API

## Success Metrics

### Functional Requirements
- [ ] All existing tests pass
- [ ] No regression in label-based encryption functionality
- [ ] ArcValue and lazy deserialization work perfectly
- [ ] New API is clean and modern

### Performance Requirements
- [ ] No more than 10% performance regression
- [ ] Memory usage remains stable
- [ ] Encryption overhead minimized

### Code Quality
- [ ] Reduced code complexity
- [ ] Better maintainability
- [ ] Improved documentation
- [ ] No clippy warnings

## Quality Assurance

To ensure robust implementation:

1. **Comprehensive testing**: All edge cases covered
2. **Performance validation**: Benchmark against requirements
3. **Error handling**: Robust error propagation and recovery

## Timeline Summary

- **Week 1**: Remove Serializable trait and create unified API
- **Week 2**: Update macros and preserve label-based encryption
- **Week 3**: Testing and performance optimization
- **Week 4**: Documentation and migration guide

This implementation plan provides a clear path to eliminate the custom `Serializable` trait while preserving the existing label-based encryption mechanism through elegant serde integration. 