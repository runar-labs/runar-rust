
## Current Key Manager Decision Patterns

I've identified **4 different decision patterns** across the 36 FFI functions:

### **Pattern 1: Complex Mixed Logic (FLAWED)**
These functions have complex fallback chains that mix mobile and node managers inappropriately:

1. **`rn_keys_encrypt_with_envelope`** - Uses `use_mobile = (profiles_count > 0 || network_id_opt.is_some()) && inner.mobile.is_some()`
2. **`rn_keys_decrypt_envelope`** - Uses `prefer_mobile = eed.network_id.is_none() || eed.network_encrypted_key.is_empty()`

**Decision Chain:**
```rust
if prefer_mobile {
    mobile -> node_owned -> node_shared -> ERROR
} else {
    node_owned -> node_shared -> mobile -> ERROR
}
```

### **Pattern 2: Node-Only (Clean)**
These functions only use node managers:

3. **`rn_keys_encrypt_local_data`** - `node_owned || node_shared`
4. **`rn_keys_decrypt_local_data`** - `node_owned || node_shared`  
5. **`rn_keys_encrypt_message_for_mobile`** - `node_owned || node_shared`
6. **`rn_keys_decrypt_message_from_mobile`** - `node_owned || node_shared`
7. **`rn_keys_encrypt_for_public_key`** - `node_owned || node_shared`
8. **`rn_keys_encrypt_for_network`** - `node_owned || node_shared`
9. **`rn_keys_decrypt_network_data`** - `node_owned || node_shared`

### **Pattern 3: Mobile-Only (Clean)**
These functions only use mobile manager:

10. **`rn_keys_mobile_initialize_user_root_key`** - `mobile`
11. **`rn_keys_mobile_derive_user_profile_key`** - `mobile`
12. **`rn_keys_mobile_install_network_public_key`** - `mobile`
13. **`rn_keys_mobile_generate_network_data_key`** - `mobile`
14. **`rn_keys_mobile_get_network_public_key`** - `mobile`
15. **`rn_keys_mobile_create_network_key_message`** - `mobile`
16. **`rn_keys_mobile_process_setup_token`** - `mobile`

### **Pattern 4: Node-Owned-Only (Clean)**
These functions only work with owned node managers:

17. **`rn_keys_node_install_network_key`** - `node_owned only`
18. **`rn_keys_ensure_symmetric_key`** - `node_owned only`

## Key Manager Types in Use

From the `KeysInner` structure:
- **`node_owned: Option<NodeKeyManager>`** - Owned instance, mutable operations allowed
- **`node_shared: Option<Arc<NodeKeyManager>>`** - Shared instance, read-only operations  
- **`mobile: Option<MobileKeyManager>`** - Mobile-specific operations



## The Problems

### **1. Inconsistent Decision Logic**
- `rn_keys_encrypt_with_envelope`: Uses complex `use_mobile` condition
- `rn_keys_decrypt_envelope`: Uses different `prefer_mobile` condition
- No clear semantic meaning to these conditions

### **2. Ambiguous Semantics**
- When should mobile vs node be used?
- What does "prefer mobile" actually mean?
- Why fallback from mobile to node or vice versa?

### **3. Mixed Responsibility**
- Functions mix encryption/decryption logic with manager selection logic
- Hard to understand which manager is actually being used
- Difficult to test and maintain

## Recommended Fix: Separate APIs

1)
There should not be this distinction and duplciation of owned and shared.
there shuold always be just one instance of key store per instance of the FFI API.
so if the some code tried to start a NodeKeyManager, but a MobileKeyManager alreduy excists.. that shuold return an error and vice versa. no code shuold be able to have both.
For our tests we need mnultipe instances odf the FFI .. when we need to simulate the cenweiron with multiple key stores.
The key store should always be shared (Arc).. because is will be use for encryption and also used for transporter certs and for services taht need to create and use symetric keys for encryption.
and it will also be used to create new keys.. or genrate certs so it needs to be shared and also be mutable. so we need a Lock.
Option<Arc<RwLock<NodeKeyManager>>>
Option<Arc<RwLock<MobileKeyManager>>>

2) the methods taht deal with both.. envelop encryption for example needs to be specific for mobile and node.. like we have the toher methods. 


Instead of mixed logic, create **separate function pairs**:

### **Node-Specific Functions:**
- `rn_keys_node_encrypt_with_envelope()`
- `rn_keys_node_decrypt_envelope()`
- `rn_keys_node_encrypt_local_data()`
- `rn_keys_node_decrypt_local_data()`

### **Mobile-Specific Functions:**
- `rn_keys_mobile_encrypt_with_envelope()`
- `rn_keys_mobile_decrypt_envelope()`
- `rn_keys_mobile_encrypt_local_data()`
- `rn_keys_mobile_decrypt_local_data()`

NO LEGACY NO BACKWARDS COMPAT> THIS IS A NEW CODEBASES>> ALL wrong funcotins will be removed or replaced. keep it clean and only the new API


## **CRITICAL: Key Store Initialization Patterns**

## **How Key Stores Are Initialized**

### **Pattern A: NodeKeyManager Creation (Single Point)**
**Primary Initialization:**
- **`rn_keys_new()`** → `keys_new_impl()` → `NodeKeyManager::new()`
  - Creates `node_owned: Some(NodeKeyManager)`
  - Sets `node_shared: None` and `mobile: None`
  - **Always creates NodeKeyManager by default**

### **Pattern B: MobileKeyManager Creation (Lazy/On-Demand)**
**8+ locations where MobileKeyManager is created on-demand:**

1. **`rn_keys_mobile_initialize_user_root_key()`** - Full initialization with device keystore, persistence, auto-persist
2. **`rn_keys_mobile_derive_user_profile_key()`** - Full initialization
3. **`rn_keys_mobile_install_network_public_key()`** - Full initialization
4. **`rn_keys_mobile_generate_network_data_key()`** - Full initialization
5. **`rn_keys_mobile_get_network_public_key()`** - Full initialization
6. **`rn_keys_mobile_create_network_key_message()`** - Simple creation
7. **`rn_keys_mobile_process_setup_token()`** - Full initialization
8. **`rn_keys_get_keystore_state()`** - Full initialization


### **Pattern C: NodeKeyManager Sharing (Transport Creation)**
- **`rn_transport_new_with_keys()`** → Converts `node_owned` → `node_shared`
  - `let arc = Arc::new(n); keys_inner.node_shared = Some(arc.clone())`
  - **Moves from owned to shared state**

### **Pattern D: Mixed State Detection**
- **`rn_keys_get_keystore_caps()`** - Checks both node and mobile managers
- **`rn_keys_flush_state()`** - Operates on both managers

SOLUTION.. 
we need a specific method to create either a Mobile or a Node key store..
need sto be explicity.
No laze initialization.. no hiden behaviour.
all mehods that needs them cvaldiate and return an error when does not exist.

instead of rn_keys_new() we need -> rn_keys_init_as_mobile() and rn_keys_init_as_node()


### **1. Single Key Store Per FFI Instance**
```rust
pub struct KeysInner {
    logger: Arc<Logger>,
    key_manager: Option<KeyManagerType>,  // Either Node OR Mobile, never both
    
    // Supporting fields...
    label_resolver: Option<Arc<dyn LabelResolver>>,
    local_node_info: Arc<ArcSwap<Option<NodeInfo>>>,
    device_keystore: Option<Arc<dyn keystore::DeviceKeystore>>,
    persistence_dir: Option<std::path::PathBuf>,
    auto_persist: bool,
}

pub enum KeyManagerType {
    Node(Arc<RwLock<NodeKeyManager>>),
    Mobile(Arc<RwLock<MobileKeyManager>>),
}
```


### **4. Single Responsibility**
- **Initialization functions**: Handle key manager creation and setup
- **Operation functions**: Use the already-initialized key manager or return error when not initialized.
- **No decision logic needed** - the choice was made at initialization time


### **🚨 CRITICAL: Additional Code Smells Found**

## **Pattern E: Massive Code Duplication**
**8 IDENTICAL MobileKeyManager initialization blocks:**

```rust
if inner.mobile.is_none() {
    match MobileKeyManager::new(inner.logger.clone()) {
        Ok(mut m) => {
            if let Some(ks) = inner.device_keystore.clone() {
                m.register_device_keystore(ks);
            }
            if let Some(dir) = inner.persistence_dir.clone() {
                m.set_persistence_dir(dir);
            }
            m.enable_auto_persist(inner.auto_persist);
            inner.mobile = Some(m)
        }
        Err(e) => return error
    }
}
```

**Found in 8 functions:**
1. `rn_keys_mobile_initialize_user_root_key()`
2. `rn_keys_mobile_derive_user_profile_key()`
3. `rn_keys_mobile_install_network_public_key()`
4. `rn_keys_mobile_generate_network_data_key()`
5. `rn_keys_mobile_get_network_public_key()`
6. `rn_keys_mobile_create_network_key_message()`
7. `rn_keys_mobile_process_setup_token()`
8. `rn_keys_get_keystore_state()`

THIS WILL BE FIXED BY THE PREVIOUS TASKS


## **Pattern F: Mixed Responsibility Functions**
**Functions that do too many things:**

1. **`rn_keys_wipe_persistence()`** - Wipes both node AND mobile persistence + direct file system operations
2. **`rn_keys_set_persistence_dir()`** - Sets persistence on both managers + updates internal state
3. **`rn_keys_enable_auto_persist()`** - Updates both managers + internal state
4. **`rn_keys_flush_state()`** - Flushes both managers
5. **`rn_keys_get_keystore_caps()`** - Checks capabilities of both managers


there is no BOTH anymore.. so rn_keys_set_persistence_dir() will set just one dir.. 
which will be use by whatever key manger is bein used. either mobile or node.

rn_keys_wipe_persistence() will just remove the current dir. no both anymore just one,.

same for all other methods..

## **Pattern G: Inconsistent Error Codes**
**Mixed error code usage:**
- **Error Code 1**: "keys handle is null", "null argument", "invalid keys handle"
- **Error Code 2**: Serialization errors, keystore creation failures, operation failures
- **Error Code 3**: Memory allocation failures
- **Error Code 4**: Used inconsistently (only in `rn_keys_node_install_certificate()`)

**Inconsistent patterns:**
- Some functions use `return 1` for "null argument"
- Others use different codes for similar errors
- No clear error code hierarchy or documentation

Error codes just be unique for each error description
Errot codes must be properly documented.

NO FUCNTION beside the init fucntins shuold craete key stores. functions that needs key store shuold validate and retrun error when the expected key store is not avialabnle.

NO FALLBACKS of ANY KIND'
