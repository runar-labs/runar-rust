# NodeKeyManager Redesign Analysis and Design Document

## Current State Analysis

### Current Field Usage in Node

The `runar-node/src/node.rs` currently has two separate fields for key management:

```rust
keys_manager: Arc<NodeKeyManager>,
keys_manager_mut: Arc<Mutex<NodeKeyManager>>,
```

### Usage Patterns Analysis

#### 1. Read-Only Operations (using `keys_manager`)
- **Certificate retrieval**: `get_quic_certificate_config()` - called during transport creation
- **Keystore access**: Passed to serialization contexts for encryption/decryption
- **Public key access**: `get_node_public_key()` - called during node creation

**Locations:**
- Line 1507: Transport creation
- Line 1529: QUIC transport configuration
- Lines 1787, 1948: Message deserialization
- Lines 1820, 1840, 2333, 2467, 2560, 2672: Serialization contexts
- Line 3364: Node cloning

#### 2. Write Operations (using `keys_manager_mut`)
- **Key generation**: `ensure_symmetric_key()` - called in `KeysDelegate::ensure_symmetric_key`

**Locations:**
- Line 3225-3226: Symmetric key generation in `KeysDelegate` implementation
- Line 3365: Node cloning

#### 3. Initialization Pattern
```rust
// Current problematic pattern in Node::new()
let key_manager_state_bytes = config.key_manager_state.clone()
    .ok_or_else(|| anyhow::anyhow!("Failed to load node credentials."))?;

let key_manager_state: NodeKeyManagerState = bincode::deserialize(&key_manager_state_bytes)
    .context("Failed to deserialize node keys state")?;

let keys_manager = NodeKeyManager::from_state(key_manager_state.clone(), logger.clone())?;
let keys_manager_mut = NodeKeyManager::from_state(key_manager_state, logger.clone())?;

let keys_manager = Arc::new(keys_manager);
let keys_manager_mut = Arc::new(Mutex::new(keys_manager_mut));
```

**Problems:**
1. **Duplicate instances**: Creating two separate `NodeKeyManager` instances from the same state
2. **Memory waste**: Storing the same data twice
3. **State inconsistency**: If one instance is modified, the other becomes stale
4. **Complex cloning**: Both fields need to be cloned when the Node is cloned

## Proposed Design Changes

### 1. Single NodeKeyManager Instance with Arc<RwLock>

Replace the dual-field approach with a single field using `Arc<RwLock<NodeKeyManager>>`:

```rust
// Before
keys_manager: Arc<NodeKeyManager>,
keys_manager_mut: Arc<Mutex<NodeKeyManager>>,

// After
keys_manager: Arc<RwLock<NodeKeyManager>>, // Single shared instance with read/write locks
```

### 2. Updated NodeConfig Structure

Remove `key_manager_state` from `NodeConfig` and add the initialized `NodeKeyManager` wrapped in `Arc<RwLock>`:

```rust
// Before
pub struct NodeConfig {
    // ... other fields ...
    key_manager_state: Option<Vec<u8>>, // Serialized state
}

// After
pub struct NodeConfig {
    // ... other fields ...
    key_manager: Arc<RwLock<NodeKeyManager>>, // Shared instance ready for Node usage
}
```

### 3. CLI Lifecycle Management

The CLI becomes responsible for the complete lifecycle of `NodeKeyManager`:

#### Initialization Flow
```rust
// 1. CLI creates empty NodeKeyManager
let mut key_manager = NodeKeyManager::new(logger.clone())?;

// 2. Configure persistence and keystore
key_manager.set_persistence_dir(config_dir.join("keys"))?;
key_manager.register_device_keystore(Arc::new(OsKeyStore::new())?)?;
key_manager.enable_auto_persist(true);

// 3. Attempt to load existing state
if !key_manager.probe_and_load_state()? {
    // No existing state - enter setup mode
    let setup_token = key_manager.generate_setup_token()?;
    // ... setup server and mobile app interaction ...
}

// 4. Create NodeConfig with key_manager wrapped in Arc<RwLock>
let node_config = NodeConfig::new("my-network")
    .with_key_manager(Arc::new(RwLock::new(key_manager)))
    .with_network_config(network_config);

// 5. Create Node with config (key_manager is already Arc<RwLock inside)
let node = Node::new(node_config).await?;
```
```

#### Setup Mode Flow
```rust
// When no existing credentials exist
if !key_manager.probe_and_load_state()? {
    // Generate setup token for mobile app
    let setup_token = key_manager.generate_setup_token()?;
    
    // Start setup server
    let setup_server = SetupServer::new(setup_config)?;
    
    // Wait for mobile app to complete setup
    let certificate = setup_server.wait_for_certificate().await?;
    
    // Install certificate
    key_manager.install_certificate(certificate)?;
    
    // State is now automatically persisted
}
```

### 4. Updated Node Implementation

#### Constructor Changes
```rust
// Before
pub async fn new(config: NodeConfig) -> Result<Self> {
    let key_manager_state_bytes = config.key_manager_state
        .ok_or_else(|| anyhow::anyhow!("Failed to load node credentials."))?;
    // ... deserialization and duplicate creation ...
}

// After
pub async fn new(config: NodeConfig) -> Result<Self> {
    let key_manager = config.key_manager; // Extract Arc<RwLock<NodeKeyManager>>
    let node_public_key = key_manager.read().await.get_node_public_key();
    let node_id = compact_id(&node_public_key);
    
    let node = Self {
        // ... other fields ...
        keys_manager: key_manager, // Already Arc<RwLock, just move ownership
    };
    // ... rest of initialization ...
}
```

#### Usage Pattern Updates
```rust
// Read operations (shared lock)
let cert_config = self.keys_manager.read().await
    .get_quic_certificate_config()
    .context("Failed to get QUIC certificates")?;

// Write operations (exclusive lock)
let mut keys_manager = self.keys_manager.write().await;
let key = keys_manager.ensure_symmetric_key(key_name)?;
```

#### Cloning Simplification
```rust
// Before
impl Clone for Node {
    fn clone(&self) -> Self {
        Self {
            // ... other fields ...
            keys_manager: self.keys_manager.clone(),
            keys_manager_mut: self.keys_manager_mut.clone(),
        }
    }
}

// After
impl Clone for Node {
    fn clone(&self) -> Self {
        Self {
            // ... other fields ...
            keys_manager: self.keys_manager.clone(), // Clone the Arc (cheap operation)
        }
    }
}
```

### 5. Benefits of the New Design

1. **Single source of truth**: Only one `NodeKeyManager` instance
2. **Memory efficiency**: No duplicate data storage
3. **State consistency**: All operations work on the same instance
4. **Efficient sharing**: Arc cloning is cheap, no data duplication
5. **Better separation of concerns**: CLI handles key lifecycle, Node handles usage
6. **Cleaner API**: No need to manage two separate fields
7. **Easier testing**: Single instance to mock or control
8. **Proper async support**: RwLock provides safe concurrent access
9. **Flexible cloning**: Node can be cloned without duplicating key data

### 6. Migration Impact

#### Files to Modify
1. **`runar-node/src/node.rs`**
   - Remove `keys_manager_mut` field
   - Change `keys_manager` to `Arc<RwLock<NodeKeyManager>>`
   - Update all usage patterns to use read()/write() locks
   - Simplify constructor and clone implementation

2. **`runar-node/src/node.rs` - NodeConfig**
   - Remove `key_manager_state` field
   - Add `key_manager: Arc<RwLock<NodeKeyManager>>` field
   - Update builder methods

3. **`runar-cli/src/init.rs`**
   - Enhance initialization flow to handle `NodeKeyManager` lifecycle
   - Add setup mode handling
   - Create `NodeConfig` with initialized `NodeKeyManager`

4. **`runar-cli/src/start.rs`**
   - Load and validate `NodeConfig` with `NodeKeyManager`
   - Pass to `Node::new()`

#### Breaking Changes
- `NodeConfig::with_key_manager_state()` becomes `NodeConfig::with_key_manager()`
- Node constructor no longer accepts serialized state
- CLI must provide initialized `NodeKeyManager` wrapped in `Arc<RwLock>`
- All key manager access in Node requires read()/write() lock operations

### 7. Implementation Phases

#### Phase 1: Core Changes
1. Update `NodeConfig` structure
2. Modify `Node` constructor and fields
3. Update all usage patterns in `Node`

#### Phase 2: CLI Updates
1. Enhance `InitCommand` to handle complete key lifecycle
2. Update `StartCommand` to work with new config structure
3. Add setup mode handling

#### Phase 3: Testing and Validation
1. Update existing tests to use new structure
2. Add integration tests for CLI initialization flow
3. Validate that all existing functionality works

### 8. Testing Considerations

#### Unit Tests
- Test `NodeKeyManager` lifecycle methods
- Test Node with new single-field approach
- Test read/write lock patterns for concurrent access
- Test Arc cloning behavior

#### Integration Tests
- Test complete CLI initialization flow
- Test setup mode and certificate exchange
- Test Node startup with new config structure

#### Performance Tests
- Verify no performance regression from lock contention
- Test concurrent access patterns
- Test Arc cloning performance vs data duplication
- Test read vs write lock contention scenarios

## Conclusion

This redesign addresses the current architectural issues by:
1. Eliminating duplicate `NodeKeyManager` instances
2. Simplifying the Node structure and cloning
3. Moving key lifecycle management to the CLI layer
4. Providing a cleaner separation of concerns
5. Making the system more maintainable and testable

The changes maintain backward compatibility at the API level while significantly improving the internal architecture and reducing complexity.
