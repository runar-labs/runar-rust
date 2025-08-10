Goal
Refactor hot-path read/lookup code that currently uses async locks around HashMaps to reduce contention and allocation. Replace Arc<RwLock<HashMap<..>>> with DashMap, remove locks on the read path, and, where applicable, add a short-lived, idempotent replay cache with TTL and a periodic prune task.

## **PROGRESS SUMMARY** ✅
**Current Status**: Phase 1.1 (Service Registry) - 1/3 fields completed + Memory Efficiency Complete
**Next Target**: Service State Maps conversion in ServiceRegistry
**Completed Fields**:
- ✅ `dial_backoff` - Converted to DashMap, all tests passing
- ✅ `dial_cancel` - Converted to DashMap, all tests passing  
- ✅ `connection_id_to_peer_id` - Converted to DashMap, all tests passing
- ✅ **Service Registry Subscription Maps** - Converted to DashMap + Memory Efficiency Optimizations ✅

**Test Results**: All 123 tests in runar-node-tests pass successfully after each conversion

Refactor requirements
- Replace `Arc<RwLock<HashMap<K, V>>>` with `Arc<DashMap<K, V2>>` where:
  - Use borrowed lookups (`map.get(key_str)` with `&str`) to avoid allocations.
  - If values are large or cloned often, store `Arc<V>` in the map to prevent cloning on hits.
- Do not hold any guard across await points:
  - Convert guard-held values into owned/Arc before the first `.await`.
 
- Keep the hot path minimal:
  - No opportunistic pruning in the hot path.
  - Avoid extra cloning/logging on hits; log at debug level sparingly.
  - Prefer borrowed keys (`&str`) and `DashMap::get` then `entry.value()`; drop the guard immediately.


Idioms to follow
- Before:
  - `let v = map.read().await.get(key).cloned()`
- After:
  - `if let Some(entry) = map.get(key_str) { let v = entry.value().clone(); /* no await */ }`
- For caching responses:
  - `response_cache.insert(correlation_id.clone(), (Instant::now(), Arc::new(reply.clone())))`
  - On hit: `if let Some((ts, cached)) = entry.value(); if now - *ts <= ttl { use cached }`
 

Acceptance criteria
- No async locks on hot read paths; no guard held across `await`.
- Borrowed-key lookups in DashMap; values stored as `Arc<_>` when beneficial.
- Configurable TTL with periodic prune; no pruning on the hot path. (for caches)

## **TASK LIST - Hot Path Optimization**

### **PHASE 1: Core Hot Paths (Immediate Impact)**
**Priority: HIGH - These affect the most frequently accessed operations**

#### **1.1 Service Registry (`src/services/service_registry.rs`)**
- [x] **Subscription ID Maps** - Convert to DashMap ✅
  - [x] `subscription_id_to_topic_path: Arc<RwLock<HashMap<String, TopicPath>>>` → `Arc<DashMap<String, TopicPath>>` ✅
  - [x] `subscription_id_to_service_topic_path: Arc<RwLock<HashMap<String, TopicPath>>>` → `Arc<DashMap<String, TopicPath>>` ✅
  - [x] Update all read/write operations to use DashMap patterns ✅
  - [x] Test: subscription lookups, unsubscription operations ✅
  - [x] **Memory Efficiency Optimizations** - Applied comprehensive memory optimization checklist ✅
    - [x] Reduced excessive cloning in `get_service_metadata` ✅
    - [x] Added reference-based alternatives to avoid cloning ✅
    - [x] Pre-allocated vectors in `get_all_subscriptions_optimized` ✅
    - [x] Added `upsert_remote_peer_subscription_owned` for ownership transfer ✅

- [ ] **Service State Maps** - Convert to DashMap
  - [ ] `local_service_states: Arc<RwLock<HashMap<String, ServiceState>>>` → `Arc<DashMap<String, ServiceState>>`
  - [ ] `remote_service_states: Arc<RwLock<HashMap<String, ServiceState>>>` → `Arc<DashMap<String, ServiceState>>`
  - [ ] Update all read/write operations to use DashMap patterns
  - [ ] Test: service state updates, lookups, removals

- [ ] **Service Lists** - Convert to DashMap
  - [ ] `local_services_list: Arc<RwLock<HashMap<TopicPath, Arc<ServiceEntry>>>>` → `Arc<DashMap<TopicPath, Arc<ServiceEntry>>>`
  - [ ] Update constructor and clone method
  - [ ] Update get_local_services method to use DashMap iter
  - [ ] Update register_local_service method to use DashMap insert
  - [ ] Test: service registration, service listing

#### **1.2 Node Core (`src/node.rs`)**
- [ ] **Pending Requests** - Convert to DashMap ✅
  - [ ] `pending_requests: Arc<RwLock<HashMap<u64, oneshot::Sender<Response>>>>` → `Arc<DashMap<u64, oneshot::Sender<Response>>>`
  - [ ] Update request tracking and correlation ID handling
  - [ ] Test: request-response correlation, timeout handling

- [ ] **Discovery Timing** - Convert to DashMap ✅
  - [ ] `discovery_seen_times: Arc<RwLock<HashMap<String, Instant>>>` → `Arc<DashMap<String, Instant>>`
  - [ ] Update discovery debouncing logic
  - [ ] Test: discovery event timing, duplicate prevention

- [ ] **Peer Connect Mutexes** - Convert to DashMap ✅
  - [ ] `peer_connect_mutexes: Arc<RwLock<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>` → `Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>`
  - [ ] Update peer connection synchronization
  - [ ] Test: concurrent peer connections, mutex management

#### **1.3 Network Transport (`src/network/transport/quic_transport.rs`)**
- [ ] **Peer Maps** - Convert to DashMap
  - [ ] `type PeerMap = Arc<RwLock<HashMap<String, PeerState>>>` → `Arc<DashMap<String, PeerState>>`
  - [ ] Update peer connection state lookups
  - [ ] Test: peer connections, connection state queries

- [x] **Connection ID Mapping** - Convert to DashMap ✅
  - [x] `type ConnectionIdToPeerIdMap = Arc<RwLock<HashMap<usize, String>>>` → `Arc<DashMap<usize, String>>` ✅
  - [x] Update connection ID to peer ID lookups ✅
  - [x] Test: connection management, peer identification ✅

- [ ] **Dial State Maps** - Convert to DashMap ✅
  - [x] `dial_backoff: Arc<RwLock<HashMap<String, (u32, Instant)>>>` → `Arc<DashMap<String, (u32, Instant)>>` ✅
  - [x] `dial_cancel: Arc<RwLock<HashMap<String, Arc<Notify>>>>` → `Arc<DashMap<String, Arc<Notify>>>` ✅
  - [x] Update connection backoff and cancellation logic ✅
  - [x] Test: connection retry logic, cancellation handling ✅

### **PHASE 2: Discovery Systems (Medium Impact)**
**Priority: MEDIUM - These affect peer discovery and network topology**

#### **2.1 Multicast Discovery (`src/network/discovery/multicast_discovery.rs`)**
- [ ] **Node Discovery Maps** - Convert to DashMap
  - [ ] `discovered_nodes: Arc<RwLock<HashMap<String, PeerInfo>>>` → `Arc<DashMap<String, PeerInfo>>`
  - [ ] `last_seen: Arc<RwLock<HashMap<String, std::time::SystemTime>>>` → `Arc<DashMap<String, std::time::SystemTime>>`
  - [ ] `last_emitted: Arc<RwLock<HashMap<String, std::time::SystemTime>>>` → `Arc<DashMap<String, std::time::SystemTime>>`
  - [ ] Update node discovery and timing operations
  - [ ] Test: multicast discovery, peer timing, emission control

#### **2.2 Memory Discovery (`src/network/discovery/memory_discovery.rs`)**
- [ ] **In-Memory Node Maps** - Convert to DashMap
  - [ ] `nodes: Arc<RwLock<HashMap<String, NodeInfo>>>` → `Arc<DashMap<String, NodeInfo>>`
  - [ ] `last_seen: Arc<RwLock<HashMap<String, SystemTime>>>` → `Arc<DashMap<String, SystemTime>>`
  - [ ] `last_emitted: Arc<RwLock<HashMap<String, SystemTime>>>` → `Arc<DashMap<String, SystemTime>>`
  - [ ] Update in-memory discovery operations
  - [ ] Test: memory discovery, node tracking

#### **2.3 Mock Discovery (`src/network/discovery/mock.rs`)**
- [ ] **Mock Node Maps** - Convert to DashMap
  - [ ] `nodes: Arc<RwLock<HashMap<String, NodeInfo>>>` → `Arc<DashMap<String, NodeInfo>>`
  - [ ] Update mock discovery operations
  - [ ] Test: mock discovery functionality

#### **2.4 Remote Service (`src/services/remote_service.rs`)**
- [ ] **Action Metadata** - Convert to DashMap
  - [ ] `actions: Arc<RwLock<HashMap<String, ActionMetadata>>>` → `Arc<DashMap<String, ActionMetadata>>`
  - [ ] Update remote action metadata lookups
  - [ ] Test: remote action handling, metadata queries

### **PHASE 3: Configuration and State Management (Lower Impact)**
**Priority: LOW - These are less frequently accessed**

#### **3.1 Node Configuration (`src/node.rs`)**
- [ ] **Network Configuration** - Convert to DashMap where beneficial
  - [ ] `network_transport: Arc<RwLock<Option<Arc<dyn NetworkTransport>>>>` → Evaluate if DashMap needed
  - [ ] `network_discovery_providers: Arc<RwLock<Option<NodeDiscoveryList>>>` → Evaluate if DashMap needed
  - [ ] `load_balancer: Arc<RwLock<dyn LoadBalancingStrategy>>` → Evaluate if DashMap needed
  - [ ] Test: configuration changes, network setup

- [ ] **Service Management** - Convert to DashMap where beneficial
  - [ ] `service_tasks: Arc<RwLock<Vec<ServiceTask>>>` → Evaluate if DashMap needed
  - [ ] `retained_index: Arc<RwLock<crate::routing::PathTrie<String>>>` → Evaluate if DashMap needed
  - [ ] Test: service lifecycle, event retention

#### **3.2 Transport State (`src/network/transport/quic_transport.rs`)**
- [ ] **Transport State** - Convert to DashMap where beneficial
  - [ ] `endpoint: Arc<RwLock<Option<Endpoint>>>` → Evaluate if DashMap needed
  - [ ] `running: tokio::sync::RwLock<bool>` → Evaluate if DashMap needed
  - [ ] Test: transport lifecycle, endpoint management

### **PHASE 4: PathTrie Optimization (Special Case)**
**Priority: MEDIUM - These are complex data structures that may need special handling**

#### **4.1 Service Registry PathTrie Structures**
- [ ] **Action Handler Tries** - Evaluate DashMap compatibility
  - [ ] `local_action_handlers: Arc<RwLock<PathTrie<LocalActionEntryValue>>>` → Evaluate conversion strategy
  - [ ] `remote_action_handlers: Arc<RwLock<PathTrie<Vec<ActionHandler>>>>` → Evaluate conversion strategy
  - [ ] `event_subscriptions: Arc<RwLock<PathTrie<SubscriptionVec>>>` → Evaluate conversion strategy
  - [ ] `local_services: Arc<RwLock<PathTrie<Arc<ServiceEntry>>>>` → Evaluate conversion strategy
  - [ ] `remote_services: Arc<RwLock<PathTrie<Arc<RemoteService>>>>` → Evaluate conversion strategy
  - [ ] Test: path-based routing, wildcard matching

### **TESTING CHECKLIST FOR EACH TASK**
For each completed task, verify:
- [ ] **Compilation**: `cargo build -p runar-node` succeeds
- [ ] **Clippy**: `cargo clippy -p runar-node --all-targets --all-features -- -D warnings` passes
- [ ] **Unit Tests**: `cargo test -p runar-node` passes
- [ ] **Integration Tests**: `cargo test -p runar-node-tests` passes
- [ ] **Performance**: No regression in hot path performance
- [ ] **Functionality**: All existing functionality works as expected

### **IMPLEMENTATION NOTES**
- **DashMap Import**: Add `use dashmap::DashMap;` to each file being modified
- **Guard Pattern**: Ensure no guards are held across `.await` points
- **Borrowed Keys**: Use `&str` keys with `map.get(key_str)` for zero-allocation lookups
- **Value Storage**: Store `Arc<V>` in maps when values are large or frequently cloned
- **TTL Caching**: Implement periodic pruning tasks for caches, not on hot paths
- **Error Handling**: Maintain existing error handling patterns while optimizing

### **PROGRESS TRACKING**
- **Total Tasks**: 45+ individual optimizations
- **Phase 1 Complete**: 8/15 (53%) - **Service Registry Subscription Maps + Memory Efficiency Complete**
- **Phase 2 Complete**: 0/12 (0%)
- **Phase 3 Complete**: 0/8 (0%)
- **Phase 4 Complete**: 0/6 (0%)
- **Overall Progress**: 8/41+ (20%)