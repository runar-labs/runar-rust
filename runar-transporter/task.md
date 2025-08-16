The goal is to split the quic transporter (/home/rafael/Development/runar-rust/runar-node/src/network/transport/quic_transport.rs) from the code crate.. to this crate to stay on  its own.

## 🔍 **PHASE 1 ANALYSIS: Moving Peer Directory from Node to Transporter**

### **Current State Analysis**

#### **1. Peer Directory Location & Usage**
- **File**: `runar-node/src/network/peer_directory.rs` (81 lines)
- **Struct**: `PeerDirectory` - single source of truth for known peers
- **Usage in Node**: 
  - Field: `peer_directory: Arc<PeerDirectory>` in Node struct
  - Initialization: `Arc::new(PeerDirectory::new())` in Node constructor
  - Methods called: `is_connected()`, `mark_connected()`, `mark_disconnected()`, `set_node_info()`, `get_node_info()`, `take_node_info()`

#### **2. Core Types Required**
- **`PeerDirectory`**: Main struct managing peer state
- **`PeerRecord`**: Internal struct for peer data (connected status, capabilities version, node info)
- **`NodeInfo`**: type containing peer node metadata (public key, network IDs, addresses, services, version)
- **`PeerInfo`**: Multicast discovery type (public key, addresses)

#### **3. Dependencies Analysis**
- **`dashmap::DashMap`**: Concurrent hash map for peer storage
- **`std::sync::Arc`**: Reference counting for shared ownership
- **`crate::network::discovery::NodeInfo`**: Discovery module type dependency

#### **4. Discovery Module Dependencies**
- **`runar_schemas::NodeMetadata`**: Service metadata for nodes
- **`runar_common::compact_ids::compact_id`**: Utility for compact ID generation
- **`runar_common::logging::{Component, Logger}`**: Logging infrastructure
- **`serde::{Serialize, Deserialize}`**: Serialization traits
- **`async_trait::async_trait`**: Async trait support
- **`anyhow::Result`**: Error handling

#### **Type Ownership Strategy**
- **`NodeInfo`, `PeerInfo`, `PeerRecord`**: Will move to `runar-schemas` crate (common to both node and transporter)
- **`PeerDirectory`**: Will move to `runar-transporter` crate
- **Discovery Module**: Will move to `runar-transporter` crate 
  
#### **Dependency Flow**
```
runar-schemas (types) ← runar-node (consumes types)
runar-schemas (types) ← runar-transporter (consumes types)
runar-transporter (PeerDirectory + Discovery) ← runar-node (consumes functionality)
```

### **Detailed PeerDirectory Usage Analysis - 10 Locations**

#### **1. Node Struct Field (Line 407)**
```rust
peer_directory: Arc<PeerDirectory>,
```
**Action**: Remove field from Node struct

#### **2. Node Constructor (Line 603)**
```rust
peer_directory: Arc::new(PeerDirectory::new()),
```
**Action**: Remove initialization, will be provided by transporter

#### **3. Public Test Method (Line 477)**
```rust
pub fn is_connected(&self, peer_id: &str) -> bool {
    self.peer_directory.is_connected(peer_id)
}
```
**Action**: Move to the transporter..

#### **4. Connection Callback (Line 1479)**
```rust
node.peer_directory.mark_connected(&peer_node_id);
```
**Action**: Move to the transporter..

#### **5. Discovery Handler (Line 1567)**
```rust
if self.peer_directory.is_connected(&discovered_peer_id) {
    // ... existing logic
}
```
**Action**: Move this call to the discovery object itself.. it uses the transporter to check if a peer is already connected or not and not even call the handle_discovered_node() if is already connected..

#### **6. Peer Cleanup (Line 1715)**
```rust
if let Some(prev_info) = self.peer_directory.take_node_info(peer_node_id) {
    // ... cleanup logic
}
```
**Action**: Remove this completely.. add to the node a Dashmap<> to store remote_node_info by peer id .. so in cleanup_disconnected_peer instead of calling self.peer_directory.take_node_info(peer_node_id) .. use this cache to get the peer node info and do this clean up.. and after the clean up in the service_registry remove the entry from this cache. This cache will be populated during process_remote_capabilities calls.

#### **7. Peer Disconnection (Line 1728)**
```rust
self.peer_directory.mark_disconnected(peer_node_id);
```
**Action**: Remove that from the node cleanup_disconnected_peer method... the transporter should call this after it calls the cleanup_disconnected_peer call back in the node.. so node does not need to do this.. transporter does this.

#### **8. Peer Capabilities Update (Line 2322)**
```rust
if let Some(existing_peer) = self.peer_directory.get_node_info(&new_peer_node_id) {
    // ... update logic
}
self.peer_directory.set_node_info(&new_peer_node_id, new_peer.clone());
```
**Action**: With the new cache of remote peers we created above .. use it here instead of self.peer_directory.get_node_info(&new_peer_node_id) and it's here also at process_remote_capabilities that we store the remote peer info in the new Dashmap cache of peers node info. so in this method you get a remote peer node info. and when you need to check if an existing one exists check version.. all the same rules but using the new local node cache.. not the peer_directory and self.peer_directory.set_node_info(&new_peer_node_id, new_peer.clone()); also should be removed.. that is where we store in the cache instead.. we need to check if the transporter needs peer node info at all.. if it does then the transporter keeps it and calls peer_directory.set_node_info(&new_peer_node_id, new_peer.clone()) at the same time it calls the process_remote_capabilities in the node.. if not we just completely remove the node info from the peer_directory.

#### **9. Peer Connection Marking (Line 2349)**
```rust
self.peer_directory.mark_connected(&new_peer_node_id);
```
**Action**: Remove from Node.. the transporter should call that when doing a handshake (confirming a peer connection)

#### **10. Node Clone (Line 3414)**
```rust
peer_directory: self.peer_directory.clone(),
```
**Action**: Remove from clone implementation

### **Architecture Decisions - CONFIRMED ✅**

#### **1. Type Ownership - RESOLVED ✅**
- **`NodeInfo`, `PeerInfo`, `PeerRecord`**: Move to `runar-schemas` crate
- **`PeerDirectory`**: Move to `runar-transporter` crate
- **Discovery Module**: Move to `runar-transporter` crate 

#### **2. PeerDirectory Simplification**
- **`PeerRecord`**: Remove `node_info` field, keep only:
  - `connected: bool`
  - `last_capabilities_version: i64`
- **Purpose**: Use `last_capabilities_version` to decide if peer info changed and whether to notify node

#### **3. Node Local Cache**
- **New Field**: `remote_node_info: Arc<DashMap<String, NodeInfo>>` (peer_id → NodeInfo)
- **Population**: Only during `process_remote_capabilities` calls
- **Purpose**: Store remote peer info for cleanup operations

#### **4. Discovery Integration**
- **Discovery Object**: Should have access to transporter's peer directory via delegate interface
- **Connection Check**: Discovery should check `is_connected` before calling `handle_discovered_node`
- **Local Node Info**: Replace `local_node: NodeInfo` with `local_peer_info: PeerInfo` in discovery

#### **5. Transporter Responsibilities**
- **Peer State Management**: Transporter calls `peer_directory.mark_connected()` internally
- **Node Notification**: Transporter calls `node.process_remote_capabilities()` when peer info changes
- **Cleanup Coordination**: Transporter calls `node.cleanup_disconnected_peer()` callback, then manages peer directory state

#### **6. Interface Design**
```rust
// Transporter provides minimal interface to discovery
pub trait PeerDirectoryDelegate: Send + Sync {
    fn is_connected(&self, peer_id: &str) -> bool;
}

// Discovery uses this to check connection status
// Node uses local cache sfor peer info, transporter manages connection state
```

### **Impact Analysis**

#### **1. Direct Dependencies**
- **Node struct**: Must be updated to remove `peer_directory` field
- **Node constructor**: Must be updated to remove PeerDirectory initialization
- **Node methods**: 10 method calls must be updated to use transporter interface

#### **2. Type Dependencies**
- **`NodeInfo`**: Used by PeerDirectory, discovery module, and node (CHECK THAT based on my comments about.. after these recommended changes.. NodeInfo should only be used in the Node..) We can also remove it from discovery.. which has the field local_node but uses only the node_id, node public key and addresses.. node id can be derived from node public key.. and node public key and addresses can both be stored in the PeerInfo .. so we replace the field local_node with local_peer_info of type PeerInfo and now Discovery does not need NodeInfo anymore.
- **`PeerInfo`**: Used by discovery module and multicast discovery
- **`DiscoveryOptions`**: Configuration for discovery mechanisms
- **`DiscoveryEvent`**: Events emitted by discovery

---

Phase 2, move all the code to a separate crate and keep the same interface..

udpate tests here /home/rafael/Development/runar-rust/runar-node-tests/src/network to refelct the change..

and run tests to make sure no regression happens after the move.

move also /home/rafael/Development/runar-rust/runar-node/src/network/peer_directory.rs with the transpoerter.

 move also alongise the QUIC transporter the discovery /home/rafael/Development/runar-rust/runar-node/src/network/discovery to the same crate. discovery is tighly related to the transporter and peer disrectoty (next phase) so we need to remove all that from the node.




as we do this.. we need to redefine the interface between transporter and the node.
