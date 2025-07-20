# Serde Format Integration Design

## Overview

Integrate encryption directly into serde's serialization framework, eliminating the custom `Serializable` trait while preserving `Encrypt` macro and ArcValue functionality.

## Requirements

### Core Requirements
- ✅ **Eliminate `Serializable` macro** - Use pure serde `Serialize`/`Deserialize`
- ✅ **Keep `Encrypt` macro** - Preserve label-based encryption mechanism
- ✅ **Unified API** - Single `serialize_with_context()` for all data types
- ✅ **ArcValue compatibility** - Preserve lazy deserialization and type erasure
- ✅ **Nested types support** - `HashMap<String, ArcValue>`, `Vec<ArcValue>` work seamlessly
- ✅ **No backward compatibility** - Clean, modern design without legacy baggage

### Functional Requirements
- **Label-based encryption** - `#[runar("user")]` groups fields by label
- **Automatic context handling** - No manual `SerializationContext` management
- **Lazy deserialization** - ArcValue performance characteristics preserved
- **Type-erased serialization** - ArcValue continues to work with complex nested structures

## Design Decisions

### 1. Leverage Existing Serde Integration
```rust
// Existing system ALREADY uses serde_cbor:
// - Encrypted* structs serialize with serde_cbor
// - Label groups serialize with serde_cbor  
// - Envelope encryption works with serde_cbor bytes
// - Only need to eliminate Serializable trait
```

### 2. Unified API
```rust
// Single API for all serialization - encrypted and non-encrypted
let data = serialize_with_context(&my_struct, context)?;
let my_struct: MyStruct = deserialize_with_context(&data, Some(keystore))?;
```

### 3. Preserve Label-Based Encryption
```rust
#[derive(Serialize, Deserialize, Encrypt)]
struct UserProfile {
    id: String,                    // Plain text
    #[runar("user")]               // Grouped with other "user" fields
    private_data: String,
    #[runar("user")]               // Same group as private_data
    email: String,
    #[runar("system")]             // Different group
    system_metadata: String,
}

// Generates: EncryptedUserProfile with label groups
// Each group: serde_cbor → envelope encryption
```

## Implementation Architecture

### Core Components

#### 1. **Unified Serialization Functions**
```rust
pub fn serialize_with_context<T: Serialize>(
    value: &T,
    context: SerializationContext,
) -> Result<Vec<u8>>;

pub fn deserialize_with_context<T: DeserializeOwned>(
    data: &[u8],
    keystore: Option<Arc<KeyStore>>,
) -> Result<T>;
```

#### 2. **ArcValue Integration**
- ArcValue uses `SerializedArcValue` format internally
- Lazy deserialization triggers new serde format
- Nested types serialize automatically

### Data Flow

#### **Serialization**
```
User Struct → Encrypt macro → Encrypted* struct → serde_cbor → envelope encryption
ArcValue → SerializedArcValue → serde_cbor
```

#### **Deserialization**
```
Raw bytes → ArcValue::deserialize() → LazyDataWithOffset → as_type_ref<T>() → serde format (keystore only)
```

#### **Deserialization**
```
Raw bytes → ArcValue::deserialize() → LazyDataWithOffset → as_type_ref<T>() → serde format (keystore only)
```

## Key Implementation Points

### 1. **Remove Serializable Trait**
```rust
// Remove this trait completely
// pub trait Serializable { ... }

// Use serde traits instead
#[derive(Serialize, Deserialize, Encrypt)]
struct MyStruct { ... }
```

### 2. **Update Encrypt Macro**
```rust
// Keep existing label-based encryption mechanism
// Only change: remove Serializable trait dependency
// Keep: serde_cbor serialization, envelope encryption
```

### 3. **ArcValue Serialization**
```rust
impl ArcValue {
    pub fn serialize(&self, context: Option<&SerializationContext>) -> Result<Vec<u8>> {
        let serialized = self.to_serializable(context)?;
        serde_cbor::to_vec(&serialized).map_err(anyhow::Error::from)
    }
}
```

### 4. **Lazy Deserialization**
```rust
pub fn as_type_ref<T>(&self) -> Result<Arc<T>> {
    if inner.is_lazy {
        let lazy = inner.get_lazy_data()?;
        let bytes = extract_and_decrypt(lazy)?;
        
        // Use new serde format for deserialization (keystore only)
        let decoded = deserialize_with_context::<T>(&bytes, lazy.keystore)?;
        Ok(Arc::new(decoded))
    } else {
        inner.as_arc::<T>()
    }
}
```

## Compatibility Matrix

| Component | Status | Notes |
|-----------|--------|-------|
| ArcValue | ✅ Compatible | Uses serde format internally |
| Lazy Deserialization | ✅ Preserved | Performance characteristics maintained |
| Nested Types | ✅ Supported | `HashMap<String, ArcValue>` works |
| Label Encryption | ✅ Preserved | Existing mechanism unchanged |
| Type Erasure | ✅ Maintained | `ErasedArc` continues to work |

## Implementation Phases

### Phase 1: Remove Serializable Trait
1. Remove `Serializable` trait from codebase
2. Update all structs to use `Serialize`/`Deserialize` only
3. Keep `Encrypt` macro unchanged

### Phase 2: Unified API
1. Create `serialize_with_context()` and `deserialize_with_context()`
2. Update ArcValue to use new API internally
3. Test with existing encrypted types

### Phase 3: Integration
1. Update macros to remove Serializable dependency
2. Ensure all existing functionality preserved
3. Comprehensive testing

## Success Criteria

1. **API Simplification** - Single `serialize_with_context()` API
2. **Performance** - No regression in serialization speed
3. **Functionality** - All encryption features preserved
4. **ArcValue** - Lazy deserialization and nested types work perfectly
5. **Clean Design** - No legacy baggage, modern Rust patterns

## Risk Mitigation

- **Label encryption preservation** - Keep existing Encrypt macro mechanism
- **Performance optimization** - Leverage existing serde_cbor usage
- **ArcValue compatibility** - Extensive testing of lazy deserialization
- **Nested type support** - Test complex `HashMap<String, ArcValue>` structures

This design leverages the existing serde_cbor integration and label-based encryption mechanism, only removing the unnecessary `Serializable` trait. 