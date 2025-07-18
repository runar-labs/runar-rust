# Runar Serializer Refactoring Goals & Current State

## Overview
This document summarizes the comprehensive refactoring goals for the Runar serializer system and the current state of implementation as of the latest conversation.

## Primary Goals

### 4. **Immutable Network Transport**
- **Goal**: Remove `RwLock` from network transport and make it immutable
- **Approach**: Use `Arc<dyn NetworkTransport>` instead of `Arc<RwLock<Option<Arc<dyn NetworkTransport>>>>`
- **Status**: 🔄 **IN PROGRESS** - RemoteService updated, Node still needs completion

### 5. **Encapsulate Encryption in Transport Layer**
- **Goal**: Move all encryption/decryption logic into NetworkTransport implementations
- **Approach**: Transport owns `Arc<dyn EnvelopeCrypto>` and `Arc<dyn LabelResolver>`
- **Status**: 🔄 **IN PROGRESS** - Transport interface defined, implementation ongoing

## Current State Analysis
 
### 🔄 In Progress

#### Node Transport Refactoring
- **Current Issue**: Node still uses `Arc<RwLock<Option<Arc<dyn NetworkTransport>>>>`
- **Target**: Replace with immutable `Arc<dyn NetworkTransport>` using OnceCell
- **Blocker**: Mid-refactor state causing compilation errors

#### Remaining SerializerRegistry Usage
- **Location**: Manual serialize/deserialize calls throughout runar-node
- **Target**: Replace with new ArcValue serialization functions
- **Impact**: Many method signatures need updating

### ❌ Pending Tasks

#### Transport-Owned Encryption
- **Task**: Move KeyStore and LabelResolver into NetworkTransport implementations).map(|arc| (*arc).clone());
- **Benefit**: Services won't need to handle encryption directly
- **Dependency**: Requires completing immutable transport refactoring

#### Lock Removal
- **Task**: Remove `Arc<RwLock<Option<Box<dyn NetworkTransport>>>>` patterns
- **Target**: Use `Arc<Box<dyn NetworkTransport>>` consistently
- **Impact**: Affects RemoteService and Node initialization

#### Test Updates
- **Task**: Update runar-node-tests and examples to use new API
- **Scope**: All dependent crates need updating
- **Priority**: Required for validation

#### Clippy Compliance
- **Task**: Ensure all code passes `cargo clippy --workspace --all-targets --all-features -D warnings`
- **Standard**: Follow strict formatting rules (e.g., `format!("error: {e}")` not `format!("error: {}", e)`)

## Technical Architecture

### Before (Problematic)
```rust
// Registry-based serialization
let registry = SerializerRegistry::new();
registry.register_serializer::<MyStruct>(|s| s.serialize());
let bytes = registry.serialize_value(&arc_value)?;

// RwLock-heavy transport
let transport: Arc<RwLock<Option<Arc<dyn NetworkTransport>>>> = ...;
let guard = transport.read().await;
```

### After (Target)
```rust
// Self-contained ArcValue
let arc_value = ArcValue::from_struct(my_struct);
let bytes = arc_value.serialize(Some(&keystore), Some(&resolver))?;

// Immutable transport
let transport: Arc<dyn NetworkTransport> = ...;
transport.send_message(message).await?;
```

### Key Design Principles

1. **Compile-time Generation**: Use macros to generate serialization code at compile time
2. **Zero-Copy Local Operations**: ArcValue remains plaintext until serialization
3. **Lazy Encryption**: Encryption only happens during serialization/network boundaries
4. **Immutable Shared State**: Avoid RwLock where possible, use Arc for sharing
5. **Transport-Owned Crypto**: NetworkTransport handles all encryption/decryption

## Current Blocking Issues

### 1. Node Transport Initialization
- **Problem**: Node.network_transport field is mid-refactor
- **Impact**: Compilation errors preventing progress
- **Solution**: Complete OnceCell-based immutable transport pattern

### 2. Manual Serialization Calls
- **Problem**: Many places still call registry methods directly
- **Impact**: Code doesn't compile with new ArcValue API
- **Solution**: Replace with ArcValue.serialize() calls

### 3. Test Compatibility
- **Problem**: Tests written for old registry-based API
- **Impact**: Cannot validate new implementation
- **Solution**: Update test suites to use new API

## Next Steps Priority

1. **Fix Node compilation** - Complete immutable transport refactoring
2. **Update manual serialization** - Replace registry calls with ArcValue methods
3. **Update imports** - Ensure all crates use new serializer traits
4. **Fix logging placeholders** - Address undefined variable references
5. **Update tests** - Make all test suites pass with new API
6. **Clippy compliance** - Ensure code meets style standards

## Success Metrics

- [ ] All code compiles without warnings
- [ ] All tests pass (runar-node-tests, integration tests)
- [ ] Clippy passes with `-D warnings`
- [ ] No RwLock usage for transport (immutable Arc pattern)
- [ ] No SerializerRegistry references anywhere
- [ ] Transport handles all encryption/decryption
- [ ] Performance maintains or improves (zero-copy local operations)
