Our FFI Transporter API is missing critical informtion.. source_node_id and destination_node_id

GOAL fix this and add the mnissing source and destination ids.

Udpate all tests to validate this information is properly provided


## **CRITICAL ARCHITECTURAL FLAW DISCOVERED**

Now I have the complete picture. This is a **massive security vulnerability** and architectural failure. Here's the deep analysis:

### **🔴 ROOT CAUSE: FFI Layer Strips Source Peer Information**

The issue is in the **Rust FFI layer** (`runar-rust/runar-ffi/src/lib.rs`). When the transport layer receives a `NetworkMessage` with full source/destination information, the FFI callbacks **deliberately strip out the source peer information**:

#### **1. NetworkMessage Contains Source Information**
```rust
// In runar-transporter/src/transport/mod.rs
pub struct NetworkMessage {
    pub source_node_id: String,        // ✅ SOURCE PEER ID IS AVAILABLE
    pub destination_node_id: String,   // ✅ DESTINATION PEER ID IS AVAILABLE
    pub message_type: u32,
    pub payload: NetworkMessagePayloadItem,
}
```

#### **2. Transport Layer Has Access to Source Information**
```rust
// In quic_transport.rs - the transport logs the source information
log_debug!(self.logger, "[read_message] Decoded message: type={type}, source={source}, dest={dest}",
     type=msg.message_type, source=msg.source_node_id, dest=msg.destination_node_id);
```

#### **3. FFI Layer DELIBERATELY STRIPS Source Information**
```rust
// In runar-ffi/src/lib.rs:3964-3975
let _ = req_tx.send(TransportRequestEvent {
    request_id,
    path: req.payload.path.clone(),
    correlation_id: req.payload.correlation_id.clone(),
    payload: req.payload.payload_bytes.clone(),
    profile_public_key: req.payload.profile_public_keys.first().cloned().unwrap_or_default(),
    // ❌ MISSING: source_node_id = req.source_node_id
    // ❌ MISSING: destination_node_id = req.destination_node_id
}).await;
```

```rust
// In runar-ffi/src/lib.rs:4001-4005
let _ = ev_tx.send(TransportEventEvent {
    path: ev.payload.path.clone(),
    correlation_id: ev.payload.correlation_id.clone(),
    payload: ev.payload.payload_bytes.clone(),
    // ❌ MISSING: source_node_id = ev.source_node_id
    // ❌ MISSING: destination_node_id = ev.destination_node_id
}).await;
```

### **🚨 SECURITY IMPLICATIONS**

This is a **critical security vulnerability** because:

1. **No Access Control**: The Swift layer cannot validate which peer sent a request
2. **No Audit Trail**: Cannot log which peer performed which actions
3. **No Rate Limiting**: Cannot implement per-peer rate limiting
4. **No Peer Management**: Cannot track or manage peer connections
5. **No Security Policies**: Cannot enforce peer-specific security policies

### **🔧 THE FIX**

The FFI layer needs to be updated to include source peer information:

```rust
// TransportRequestEvent should include:
pub struct TransportRequestEvent {
    pub request_id: String,
    pub source_peer_id: String,        // ✅ ADD THIS
    pub path: String,
    pub correlation_id: String,
    pub payload: Vec<u8>,
    pub profile_public_key: Vec<u8>,
}

// TransportEventEvent should include:
pub struct TransportEventEvent {
    pub source_peer_id: String,        // ✅ ADD THIS
    pub path: String,
    pub correlation_id: String,
    pub payload: Vec<u8>,
}
```
