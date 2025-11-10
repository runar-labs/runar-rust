NodeInfo Should Be Transport-Scoped, Not Keys-Scoped

### The Architectural Problem

**Current (Incorrect) Design:**
- `rn_keys_set_local_node_info` - NodeInfo is stored in the **keys** object
- Multiple key manager instances = multiple NodeInfo storage locations
- Transport reads from keys-scoped shared holder
- When testing multiple transports, they all read from different keys instances

**Correct Design Should Be:**
- `rn_transport_set_local_node_info` - NodeInfo should be stored in the **transport** object
- Each transport has its own NodeInfo storage
- Transport reads from its own NodeInfo storage
- Multiple transports can have different NodeInfo independently

### Key Discovery: Key Manager Does NOT Use NodeInfo

**Critical Finding**: After thorough codebase analysis, the `NodeKeyManager` struct has **zero references** to `NodeInfo`:
- No `local_node_info` field in `NodeKeyManager` struct
- No NodeInfo-related methods in key manager
- Key manager only provides cryptographic keys, not network metadata
- NodeInfo is **exclusively consumed by the transport layer** for handshakes and peer communication

**Transport Layer Usage**:
- **Handshake Protocol**: NodeInfo exchanged during peer handshakes for service discovery
- **Peer Discovery**: NodeInfo used for service announcements and peer capabilities
- **Service Metadata**: NodeInfo contains node's service metadata that peers need to know
- **Multi-Transport Support**: Each transport needs its own NodeInfo (different addresses, capabilities)

### Detailed Analysis of Current Implementation

#### 1. **Current FFI Function (WRONG)**
```rust
// runar-rust/runar-ffi/src/lib.rs:4393
pub unsafe extern "C" fn rn_keys_set_local_node_info(
    transport: *mut c_void,  // ← This is actually a transport handle, not keys!
    node_info_cbor: *const u8,
    len: usize,
    err: *mut RnError,
) -> i32 {
    // ...
    let handle = &mut *(transport as *mut FfiTransportHandle);  // ← Transport handle
    // ...
    inner_ref.local_node_info.store(Arc::new(Some(node_info.clone())));  // ← Keys storage
}
```

**Problem**: The function name says `rn_keys_` but it takes a **transport handle** and updates **keys storage**.

#### 2. **Current Swift Usage (WRONG)**
```swift
// swift-node/Sources/SwiftNode/SwiftNode.swift:2034
let keyManager: FFIKeys = try config.getKeyManager()
let nodeInfoCbor = try CodableCBOREncoder().encode(ffiNodeInfo)
try await keyManager.setLocalNodeInfo(nodeInfoCbor)  // ← Calls keys method
```

**Problem**: Swift calls `keyManager.setLocalNodeInfo()` but this should be `transport.setLocalNodeInfo()`.

#### 3. **Current Transport Creation (WRONG)**
```rust
// runar-rust/runar-ffi/src/lib.rs:3936-3948
let holder = keys_inner.local_node_info.clone();  // ← Reads from keys
let get_local_node_info_cb: GetLocalNodeInfoCallback = Arc::new(move || {
    let holder = holder.clone();
    Box::pin(async move {
        let cur = holder.load();  // ← Reads from keys storage
        // ...
    })
});
```

**Problem**: Transport callback reads from keys storage instead of transport storage.

### The Multi-Transport Testing Issue

When testing multiple transports (like in `RemoteNetworkTests`):

1. **Node1**: Creates `FFIKeys1` → Creates `Transport1` → `Transport1` reads from `FFIKeys1.local_node_info`
2. **Node2**: Creates `FFIKeys2` → Creates `Transport2` → `Transport2` reads from `FFIKeys2.local_node_info`
3. **Node1** calls `FFIKeys1.setLocalNodeInfo()` → Updates `FFIKeys1.local_node_info`
4. **Node2** calls `FFIKeys2.setLocalNodeInfo()` → Updates `FFIKeys2.local_node_info`
5. **Handshake**: `Transport1` reads from `FFIKeys1.local_node_info` (correct)
6. **Handshake**: `Transport2` reads from `FFIKeys2.local_node_info` (correct)

But the current implementation has the wrong function name and wrong storage location.

### Evidence from Code Analysis

#### 1. **Function Signature Mismatch**
```rust
// Function name suggests it's for keys
pub unsafe extern "C" fn rn_keys_set_local_node_info(
    transport: *mut c_void,  // But takes transport handle
    // ...
)
```

#### 2. **Swift FFI Method (WRONG)**
```swift
// swift-ffi/Sources/SwiftFFI/SwiftFFI.swift:3068
public func setLocalNodeInfo(_ nodeInfoCbor: Data) async throws {
    // This is on FFIKeys, but should be on QuicTransport
}
```

#### 3. **Transport Callback Reads Wrong Storage**
```rust
// runar-rust/runar-transporter/src/transport/quic_transport.rs:1230
let local_node_info = (self.get_local_node_info)()  // Reads from keys storage
    .await
    .map_err(|e| NetworkError::TransportError(e.to_string()))?;
```

### The Correct Architecture Should Be

#### 1. **Transport-Scoped NodeInfo Storage**
```rust
// In QuicTransport struct
pub struct QuicTransport {
    // ... existing fields ...
    local_node_info: Arc<AtomicRefCell<Option<NodeInfo>>>,  // ← Transport-scoped storage
}
```

#### 2. **Transport-Scoped FFI Function**
```rust
// Correct function name and scope
pub unsafe extern "C" fn rn_transport_set_local_node_info(
    transport: *mut c_void,
    node_info_cbor: *const u8,
    len: usize,
    err: *mut RnError,
) -> i32 {
    // Update transport.local_node_info, not keys.local_node_info
}
```

#### 3. **Transport-Scoped Swift Method**
```swift
// In QuicTransport class
public func setLocalNodeInfo(_ nodeInfoCbor: Data) async throws {
    // Call rn_transport_set_local_node_info
}
```

#### 4. **Transport-Scoped Callback**
```rust
// In transport creation
let local_node_info = self.local_node_info.clone();  // ← Transport storage
let get_local_node_info_cb: GetLocalNodeInfoCallback = Arc::new(move || {
    let holder = local_node_info.clone();  // ← Transport storage
    Box::pin(async move {
        let cur = holder.borrow();  // ← Read from transport storage
        // ...
    })
});
```

### Why This Fixes the Issue

1. **Isolation**: Each transport has its own NodeInfo storage
2. **Correct Scope**: NodeInfo belongs to transport, not keys
3. **Multi-Transport Support**: Multiple transports can have different NodeInfo
4. **Proper Lifecycle**: NodeInfo is updated when transport is updated, not when keys are updated

### Summary for FFI Fix

**Current Problem:**
- `rn_keys_set_local_node_info` stores NodeInfo in keys object
- Multiple key instances = multiple NodeInfo storage locations
- Transport reads from keys storage instead of its own storage
- Function name is misleading (says keys but takes transport handle)
- Key manager has no business storing NodeInfo (architectural violation)

**Required Changes (FFI Crate Only):**
1. **Remove**: `rn_keys_set_local_node_info` function entirely
2. **Add**: `rn_transport_set_local_node_info` function
3. **Add**: `rn_transport_get_local_node_info` function
4. **Move Storage**: NodeInfo storage from `keys_inner.local_node_info` to `transport.local_node_info`
5. **Update Callback**: Transport callback reads from transport storage, not keys storage
6. **Update Tests**: All FFI tests to use new transport-based API

**Files to Modify (FFI Crate Only):**
- `runar-ffi/src/lib.rs` - Remove keys function, add transport functions, update storage
- `runar-ffi/tests/ffi_transport_test.rs` - Update tests to use transport API
- `runar-ffi/tests/ffi_keys_test.rs` - Remove NodeInfo tests from keys tests

**Architecture Benefits:**
- **Correct Scope**: NodeInfo belongs to transport, not keys
- **Multi-Transport Support**: Each transport has independent NodeInfo
- **Clean Separation**: Key manager only handles cryptography, transport handles networking
- **No Backward Compatibility**: Clean break from incorrect architecture

This architectural fix will resolve the service announcement issue by ensuring each transport has its own NodeInfo storage that gets updated correctly.