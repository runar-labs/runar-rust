# Swift Serializer Requirements and Design

## Overview

The Swift Serializer must provide the same API and features as the Rust `runar-serializer`, adapted for Swift's language characteristics. The core goal is to enable zero-copy data containers that support lazy deserialization and selective field encryption.

## Core Requirements

### 1. Zero-Copy Data Container (Swift Equivalent of ArcValue)

**Goal**: Pass parameters and results around in memory without copying or cloning, while supporting lazy deserialization.

**Rust Approach**: Uses `Arc<T>` with type erasure via `ErasedArc` and `ArcValue` categories.

**Swift Design**: Generic Wrapper with Type Erasure
```swift
protocol AnyValue: AnyObject {
    var typeName: String { get }
    var category: ValueCategory { get }
    func serialize(context: SerializationContext?) throws -> Data
}

class AnyValue {
    private let box: AnyValueBox
    let category: ValueCategory
}

private class AnyValueBox {
    let typeName: String
    func serialize(context: SerializationContext?) throws -> Data
    func asType<T>() -> T?
}
```

### 2. Lazy Deserialization

**Goal**: Only deserialize data when actually accessing the contents.

**Rust Approach**: Stores serialized bytes with offset information in `LazyDataWithOffset`.

**Swift Design**:
```swift
struct LazyData {
    let typeName: String
    let data: Data
    let keystore: KeyStore?
    let encrypted: Bool
}

class AnyValue {
    private var materializedValue: AnyValue?
    private var lazyData: LazyData?
    
    func asType<T>() throws -> T {
        if let value = materializedValue {
            return value as! T
        }
        // Deserialize from lazyData
        let value = try deserializeLazyData()
        materializedValue = value
        return value as! T
    }
}
```

### 3. Selective Field Encryption

**Goal**: Encrypt specific fields based on labels while keeping others plaintext.

**Rust Approach**: Uses derive macros (`#[derive(Encrypt)]`) with field attributes (`#[runar(user)]`).

**Swift Design**: Property Wrapper Macros
```swift
struct TestProfile {
    let id: String
    @Encrypted(label: "user") var private: String
    @Encrypted(label: "system") var name: String
    @Encrypted(label: "search") var email: String
}
```

### 4. Value Categories

**Goal**: Support different data types with appropriate serialization strategies.

**Swift Implementation**:
```swift
enum ValueCategory: UInt8 {
    case null = 0
    case primitive = 1
    case list = 2
    case map = 3
    case struct = 4
    case bytes = 5
    case json = 6
}
```

### 5. CBOR Serialization

**Goal**: Use CBOR (Concise Binary Object Representation) for serialization to maintain compatibility with Rust implementation.

**Rust Approach**: Uses `serde_cbor` for binary serialization.

**Swift Design**: Use CBOR library for binary serialization
```swift
// CBOR serialization for binary compatibility with Rust
func serialize(context: SerializationContext?) throws -> Data {
    // Use CBOR encoding for binary format
    let cborData = try CBOR.encode(value)
    // Apply encryption if context provided
    if let context = context {
        return try encryptData(cborData, context: context)
    }
    return cborData
}
```

### 6. Serialization Context

**Goal**: Provide encryption context during serialization.

**Swift Design**:
```swift
struct SerializationContext {
    let keystore: KeyStore
    let resolver: LabelResolver
    let networkId: String
    let profileId: String
}
```

## Language-Specific Design Decisions

### Memory Management

**Rust**: Uses `Arc<T>` for shared ownership with automatic reference counting.

**Swift**: Use `AnyObject` protocol and reference counting. Swift's ARC provides similar guarantees.

### Type Erasure

**Rust**: Uses `dyn Any` and `TypeId` for runtime type information.

**Swift**: Use `Any` protocol and `Mirror` for reflection, or custom type erasure patterns.

### Error Handling

**Rust**: Uses `Result<T, E>` with `anyhow::Error`.

**Swift**: Use `throws` functions with custom error types:
```swift
enum SerializerError: Error {
    case deserializationFailed(String)
    case encryptionFailed(String)
    case typeMismatch(String)
}
```

### Concurrency

**Rust**: Uses `Send + Sync` traits for thread safety.

**Swift**: Use `@Sendable` closures and actor-based concurrency where needed.

## API Design

### Core Types

```swift
// Main container type
class AnyValue {
    let category: ValueCategory
    func serialize(context: SerializationContext?) throws -> Data
    func asType<T>() throws -> T
    static func deserialize(_ data: Data, keystore: KeyStore?) throws -> AnyValue
}

// Type conversion protocol
protocol AsAnyValue {
    func intoAnyValue() -> AnyValue
    static func fromAnyValue(_ value: AnyValue) throws -> Self
}

// Encryption traits
protocol RunarEncryptable {
    associatedtype Encrypted: RunarDecrypt where Encrypted.Decrypted == Self
    func encryptWithKeystore(_ keystore: KeyStore, resolver: LabelResolver) throws -> Encrypted
}

protocol RunarDecrypt {
    associatedtype Decrypted: RunarEncryptable where Decrypted.Encrypted == Self
    func decryptWithKeystore(_ keystore: KeyStore) throws -> Decrypted
}
```

### Macro System

**Property Wrapper Approach**:
```swift
@propertyWrapper
struct Encrypted {
    private let label: String
    private var value: String
    
    init(label: String) {
        self.label = label
        self.value = ""
    }
    
    var wrappedValue: String {
        get { value }
        set { value = newValue }
    }
}
```

## Implementation Phases

### Phase 1: Core Infrastructure
- Implement `AnyValue` with basic categories (null, primitive, bytes)
- Create type erasure system
- Basic CBOR serialization/deserialization

### Phase 2: Lazy Deserialization
- Implement `LazyData` structure
- Add lazy deserialization logic
- Memory-efficient data handling

### Phase 3: Encryption System
- Implement property wrapper macros
- Create encryption/decryption traits
- Label resolution system

### Phase 4: Advanced Features
- Complex types (lists, maps, structs)
- CBOR integration for full Rust compatibility
- Performance optimizations

## Key Differences from Rust

1. **Macro System**: Swift's macro system is more limited than Rust's proc macros
2. **Type Erasure**: Swift requires more explicit type erasure patterns
3. **Memory Management**: Swift's ARC vs Rust's ownership system
4. **Concurrency**: Swift's actor model vs Rust's Send/Sync traits
5. **Error Handling**: Swift's throws vs Rust's Result types

## Performance Considerations

- Use `Data` instead of `[UInt8]` for better performance
- Leverage Swift's value semantics where appropriate
- Consider using `UnsafeBufferPointer` for zero-copy operations
- Use CBOR for binary serialization to match Rust performance and compatibility

## Testing Strategy

- Unit tests for each value category
- Integration tests with encryption/decryption
- Performance benchmarks comparing with Rust implementation
- Cross-platform compatibility tests (iOS, macOS, Linux) 