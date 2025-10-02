# Discovery vs Transport Architecture Analysis

## GOAL
Fix the discovery APIs in FFI. Discovery events should have their own channel and not be using transport channels. Discovery can be used independently from transport.

## COMPREHENSIVE LINE-BY-LINE ANALYSIS

### 1. CURRENT ARCHITECTURAL PROBLEMS

#### 1.1 Discovery Events Polled Through Transport (CRITICAL ISSUE)
**Location**: `runar-ffi/src/lib.rs:4177-4220`
```rust
#[no_mangle]
pub unsafe extern "C" fn rn_transport_poll_discovery_discovered(
    transport: *mut c_void,
    out_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Discovery events are polled through transport handle!
    let Some(inner) = with_transport_inner(transport) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "invalid transport handle");
        return RN_ERROR_INVALID_HANDLE;
    };
    // Polls from transport's discovery_discovered_rx channel
    let mut rx = runtime().block_on(inner.discovery_discovered_rx.lock());
    match rx.try_recv() {
        Ok(peer) => match serde_cbor::to_vec(&peer) {
            // ... serializes PeerInfo to CBOR
        }
    }
}
```

**Problem**: Discovery events are polled through transport handle, making discovery dependent on transport.

#### 1.2 Discovery Events Stored in TransportInner (ARCHITECTURAL VIOLATION)
**Location**: `runar-ffi/src/lib.rs:372-404`
```rust
struct TransportInner {
    transport: Arc<QuicTransport>,
    // per-type channels
    #[allow(dead_code)]
    peer_connected_tx: mpsc::Sender<PeerConnectedEvent>,
    peer_connected_rx: Mutex<mpsc::Receiver<PeerConnectedEvent>>,
    #[allow(dead_code)]
    peer_disconnected_tx: mpsc::Sender<String>,
    peer_disconnected_rx: Mutex<mpsc::Receiver<String>>,
    // DISCOVERY EVENTS STORED IN TRANSPORT! (WRONG)
    discovery_discovered_tx: mpsc::Sender<runar_transporter::discovery::PeerInfo>,
    discovery_discovered_rx: Mutex<mpsc::Receiver<runar_transporter::discovery::PeerInfo>>,
    discovery_updated_tx: mpsc::Sender<runar_transporter::discovery::PeerInfo>,
    discovery_updated_rx: Mutex<mpsc::Receiver<runar_transporter::discovery::PeerInfo>>,
    discovery_lost_tx: mpsc::Sender<String>,
    discovery_lost_rx: Mutex<mpsc::Receiver<String>>,
    // ... other transport channels
}
```

**Problem**: Discovery channels are embedded in `TransportInner`, violating separation of concerns.

#### 1.3 Discovery Events Bound to Transport Channels (TIGHT COUPLING)
**Location**: `runar-ffi/src/lib.rs:2683-2739`
```rust
#[no_mangle]
pub unsafe extern "C" fn rn_discovery_bind_events_to_transport(
    discovery: *mut c_void,
    transport: *mut c_void,
    err: *mut RnError,
) -> i32 {
    // ... validation ...
    
    // Subscribe discovery events to emit into transport typed channels
    let discovery_discovered = unsafe { &*t.inner }.discovery_discovered_tx.clone();
    let discovery_updated = unsafe { &*t.inner }.discovery_updated_tx.clone();
    let discovery_lost = unsafe { &*t.inner }.discovery_lost_tx.clone();
    
    let listener: runar_transporter::discovery::DiscoveryListener = Arc::new(move |ev| {
        // Discovery events are forwarded to transport channels
        match ev {
            DiscoveryEvent::Discovered(peer) => {
                let _ = discovery_discovered.send(peer).await;
            }
            DiscoveryEvent::Updated(peer) => {
                let _ = discovery_updated.send(peer).await;
            }
            DiscoveryEvent::Lost(node_id) => {
                let _ = discovery_lost.send(node_id).await;
            }
        }
    });
}
```

**Problem**: Discovery events are forwarded to transport channels, creating tight coupling.

### 2. CORRECT ARCHITECTURE (TRANSPORTER & NODE CRATES - DO NOT CHANGE)

**IMPORTANT**: The transporter and node crates are already correctly designed. We will NOT change anything outside the FFI crate.

#### 2.1 Discovery is Independent (TRANSPORTER CRATE - CORRECT)
**Location**: `runar-transporter/src/discovery/mod.rs:1-85`
```rust
// Node Discovery Interface
//
// INTENTION: Define interfaces for node discovery mechanisms. Discovery is responsible
// for finding and announcing node presence on the network, but NOT maintaining
// a registry of nodes or managing connections.

#[derive(Clone, Debug)]
pub enum DiscoveryEvent {
    Discovered(PeerInfo),
    Updated(PeerInfo),
    Lost(String), // peer_id
}

/// Callback function type for discovery events (async)
pub type DiscoveryListener = Arc<dyn Fn(DiscoveryEvent) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

#[async_trait]
pub trait NodeDiscovery: Send + Sync {
    /// Subscribe a listener for discovery events
    async fn subscribe(&self, listener: DiscoveryListener) -> Result<()>;
    // ... other methods
}
```

**Status**: ✅ CORRECT - Discovery has its own event system and is independent. **DO NOT CHANGE**.

#### 2.2 Transport Uses Discovery (NODE CRATE - CORRECT)
**Location**: `runar-node/src/node.rs:1454-1473`
```rust
discovery_provider
    .subscribe(Arc::new(move |event| {
        let node_arc = node_arc.clone();
        let provider_type_clone = provider_type_clone.clone();
        Box::pin(async move {
            match event {
                DiscoveryEvent::Discovered(peer_info)
                | DiscoveryEvent::Updated(peer_info) => {
                    if let Err(e) = node_arc.handle_discovered_node(peer_info).await {
                        log_error!(node_arc.logger, "Failed to handle node discovered by {provider_type_clone} provider: {e}");
                    }
                }
                DiscoveryEvent::Lost(peer_id) => {
                    // Treat as disconnect cleanup hint
                    let _ = node_arc.cleanup_disconnected_peer(&peer_id).await;
                }
            }
        })
    }))
    .await?;
```

**Status**: ✅ CORRECT - Node subscribes to discovery events and uses them to connect via transport. **DO NOT CHANGE**.

### 3. FFI API DESIGN PROBLEMS (FFI CRATE ONLY - NEEDS FIXING)

#### 3.1 Discovery Poll Functions Missing (FFI CRATE)
**Current FFI Header**: `runar-ffi/include/runar_ffi.h:268-295`
```c
// Discovery creation and control functions exist:
int32_t rn_discovery_new_with_multicast(void *keys, ...);
int32_t rn_discovery_init(void *discovery, ...);
int32_t rn_discovery_bind_events_to_transport(void *discovery, void *transport, ...);
int32_t rn_discovery_start_announcing(void *discovery, ...);
int32_t rn_discovery_stop_announcing(void *discovery, ...);
int32_t rn_discovery_shutdown(void *discovery, ...);

// BUT NO DISCOVERY POLL FUNCTIONS!
// Missing:
// int32_t rn_discovery_poll_discovered(void *discovery, ...);
// int32_t rn_discovery_poll_updated(void *discovery, ...);
// int32_t rn_discovery_poll_lost(void *discovery, ...);
```

**Problem**: No way to poll discovery events directly from discovery handle. **FIX IN FFI CRATE**.

#### 3.2 Discovery Events Polled Through Transport (FFI CRATE)
**Current FFI Header**: `runar-ffi/include/runar_ffi.h:374-397`
```c
// Discovery events are polled through transport!
int32_t rn_transport_poll_discovery_discovered(void *transport, ...);
int32_t rn_transport_poll_discovery_updated(void *transport, ...);
int32_t rn_transport_poll_discovery_lost(void *transport, ...);
```

**Problem**: Discovery events require transport handle, violating independence. **FIX IN FFI CRATE**.

### 4. TESTING PROBLEMS (FFI CRATE ONLY - NEEDS FIXING)

#### 4.1 Discovery Tests Don't Test Event Polling (FFI CRATE)
**Location**: `runar-ffi/tests/ffi_discovery_test.rs:16-164`
```rust
#[test]
fn test_ffi_discovery_ttl_lost_and_debounce() {
    // ... setup discovery ...
    
    // Start announcing on both nodes
    assert_eq!(unsafe { rn_discovery_start_announcing(discovery_a, &mut error) }, 0);
    assert_eq!(unsafe { rn_discovery_start_announcing(discovery_b, &mut error) }, 0);
    
    // Wait for discovery to work
    std::thread::sleep(Duration::from_millis(500));
    
    // Stop announcing on node A to simulate TTL loss
    assert_eq!(unsafe { rn_discovery_stop_announcing(discovery_a, &mut error) }, 0);
    
    // NO EVENT POLLING TESTED!
    // Tests only test announcement/control, not event consumption
}
```

**Problem**: Discovery tests don't verify event polling functionality. **FIX IN FFI CRATE**.

### 5. ARCHITECTURAL VIOLATIONS SUMMARY (FFI CRATE ONLY)

#### 5.1 Separation of Concerns Violation (FFI CRATE)
- **Discovery events stored in `TransportInner`** (should be in `DiscoveryInner`) - **FIX IN FFI**
- **Discovery events polled through transport handle** (should be through discovery handle) - **FIX IN FFI**
- **Discovery tightly coupled to transport** (should be independent) - **FIX IN FFI**

#### 5.2 API Design Violation (FFI CRATE)
- **Missing discovery poll functions** (`rn_discovery_poll_*`) - **FIX IN FFI**
- **Discovery events require transport handle** (should use discovery handle) - **FIX IN FFI**
- **Inconsistent with transporter crate design** (discovery is independent there) - **FIX IN FFI**

#### 5.3 Testing Violation (FFI CRATE)
- **Discovery tests don't test event polling** (incomplete coverage) - **FIX IN FFI**
- **No independent discovery usage tests** (always requires transport) - **FIX IN FFI**

### 6. REQUIRED FIXES (FFI CRATE ONLY)

**SCOPE**: All fixes are within the `runar-ffi` crate only. No changes to transporter, node, or any other crates.

#### 6.1 Move Discovery Channels to DiscoveryInner (FFI CRATE)
```rust
// In runar-ffi/src/lib.rs
struct DiscoveryInner {
    discovery: Arc<MulticastDiscovery>,
    // Add discovery event channels here
    discovered_tx: mpsc::Sender<PeerInfo>,
    discovered_rx: Mutex<mpsc::Receiver<PeerInfo>>,
    updated_tx: mpsc::Sender<PeerInfo>,
    updated_rx: Mutex<mpsc::Receiver<PeerInfo>>,
    lost_tx: mpsc::Sender<String>,
    lost_rx: Mutex<mpsc::Receiver<String>>,
}
```

#### 6.2 Add Discovery Poll Functions (FFI CRATE)
```c
// In runar-ffi/include/runar_ffi.h
int32_t rn_discovery_poll_discovered(void *discovery, uint8_t **out_cbor, size_t *out_len, struct RnError *err);
int32_t rn_discovery_poll_updated(void *discovery, uint8_t **out_cbor, size_t *out_len, struct RnError *err);
int32_t rn_discovery_poll_lost(void *discovery, uint8_t **out_cbor, size_t *out_len, struct RnError *err);
```

#### 6.3 Remove Discovery Channels from TransportInner (FFI CRATE)
```rust
// In runar-ffi/src/lib.rs
struct TransportInner {
    transport: Arc<QuicTransport>,
    // Remove discovery channels
    // discovery_discovered_tx/rx: REMOVE
    // discovery_updated_tx/rx: REMOVE  
    // discovery_lost_tx/rx: REMOVE
    // Keep only transport-specific channels
    peer_connected_tx/rx: ...,
    peer_disconnected_tx/rx: ...,
    request_tx/rx: ...,
    event_tx/rx: ...,
    response_tx/rx: ...,
}
```

#### 6.4 Update Discovery Binding (FFI CRATE)
```rust
// In runar-ffi/src/lib.rs
// Discovery should bind to its own channels, not transport channels
// Transport can subscribe to discovery events if needed
```

#### 6.5 Add Discovery Event Polling Tests (FFI CRATE)
```rust
// In runar-ffi/tests/ffi_discovery_test.rs
#[test]
fn test_ffi_discovery_event_polling() {
    // Test independent discovery event polling
    // Test discovery without transport
    // Test discovery event round-trips
}
```

### 7. IMPACT ASSESSMENT (FFI CRATE ONLY)

#### 7.1 Complete Refactor Required (FFI CRATE)
- **Remove discovery poll functions from transport** (complete refactor in FFI)
- **Add discovery poll functions to discovery** (new proper API in FFI)
- **Update all discovery event polling code** (complete refactor in FFI)

#### 7.2 No Backward Compatibility (FFI CRATE)
- **Complete refactor to proper architecture** (new codebase, no legacy support needed)
- **Replace all incorrect patterns** (fix everything to proper design)

#### 7.3 Testing Impact (FFI CRATE)
- **All discovery tests need complete rewrite** (new proper polling functions in FFI)
- **Transport tests need complete rewrite** (remove discovery polling in FFI)
- **Integration tests need complete rewrite** (new proper discovery usage patterns in FFI)

### 8. CONCLUSION

The current **FFI implementation** violates the fundamental architectural principle that **Discovery should be independent from Transport**. Discovery events are incorrectly stored in `TransportInner`, polled through transport handles, and tightly coupled to transport channels.

**IMPORTANT**: The transporter and node crates are already correctly designed. We only need to fix the FFI layer.

**COMPLETE REFACTOR REQUIRED (FFI CRATE ONLY):**
1. **Move discovery channels to `DiscoveryInner`** (complete refactor in FFI)
2. **Add discovery poll functions** (`rn_discovery_poll_*`) (new proper API in FFI)
3. **Remove discovery channels from `TransportInner`** (complete refactor in FFI)
4. **Replace all discovery event polling code** (complete refactor in FFI)
5. **Rewrite all discovery tests** (complete refactor in FFI)

This is a **complete refactor of the FFI crate** to implement the proper architecture. No backward compatibility needed - fix everything to the correct design.