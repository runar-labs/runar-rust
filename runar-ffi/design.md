# **FFI Key Management Refactoring - Final Design**

## **🎯 OBJECTIVE**
Complete redesign of the FFI key management system to eliminate all decision logic, code duplication, and mixed responsibilities while maintaining clear separation between mobile and node key managers.

---

## **📋 CORE DESIGN DECISIONS**

### **1. Separate Key Manager Fields**
Keep both manager types as separate fields, but with strict validation:

```rust
pub struct KeysInner {
    logger: Arc<Logger>,

    // Separate fields for each manager type
    mobile_key_manager: Option<Arc<RwLock<MobileKeyManager>>>,
    node_key_manager: Option<Arc<RwLock<NodeKeyManager>>>,

    // Supporting fields...
    label_resolver: Option<Arc<dyn LabelResolver>>,
    local_node_info: Arc<ArcSwap<Option<NodeInfo>>>,
    device_keystore: Option<Arc<dyn keystore::DeviceKeystore>>,
    persistence_dir: Option<std::path::PathBuf>,
    auto_persist: bool,
}
```

### **2. Function-Specific Validation Logic**
Each function type validates upfront and exits early on errors, leaving the main logic clean:

**Mobile Functions:**
```rust
// Validate upfront - exit early on errors
if inner.node_key_manager.is_some() {
    return error("wrong key manager type: expected mobile, found node");
}
if inner.mobile_key_manager.is_none() {
    return error("key manager not initialized");
}

// Main logic - mobile manager is guaranteed to exist here
let manager = inner.mobile_key_manager.as_ref().unwrap();
// ... perform mobile-specific operations
```

**Node Functions:**
```rust
// Validate upfront - exit early on errors
if inner.mobile_key_manager.is_some() {
    return error("wrong key manager type: expected node, found mobile");
}
if inner.node_key_manager.is_none() {
    return error("key manager not initialized");
}

// Main logic - node manager is guaranteed to exist here
let manager = inner.node_key_manager.as_ref().unwrap();
// ... perform node-specific operations
```

### **3. Explicit Initialization Functions**
Clear, separate initialization functions:

```rust
// Initialize as mobile - returns error if already initialized with different type
rn_keys_init_as_mobile() -> Result<(), Error>

// Initialize as node - returns error if already initialized with different type
rn_keys_init_as_node() -> Result<(), Error>
```

### **4. No Decision Logic, No Fallbacks**
- **Mobile functions** only use `mobile_key_manager`
- **Node functions** only use `node_key_manager`
- **Error if wrong type** is initialized
- **Error if not initialized** at all

---

## **🔧 IMPLEMENTATION PHASES**

### **PHASE 1: Core Structure Update**

#### **1.1 Update KeysInner Structure**
**File:** `src/lib.rs`

```rust
pub struct KeysInner {
    logger: Arc<Logger>,
    mobile_key_manager: Option<Arc<RwLock<MobileKeyManager>>>,
    node_key_manager: Option<Arc<RwLock<NodeKeyManager>>>,
    // ... existing supporting fields
}
```

#### **1.2 Create Validation Helpers**
**File:** `src/lib.rs`

```rust
/// Validate mobile key manager exists and node manager doesn't, return manager or error
fn validate_mobile_manager(inner: &KeysInner) -> Result<&Arc<RwLock<MobileKeyManager>>, RnError> {
    // Check for wrong manager type first
    if inner.node_key_manager.is_some() {
        return Err(RnError::WrongManagerType("expected mobile manager, found node manager".into()));
    }

    // Check if mobile manager exists
    inner.mobile_key_manager.as_ref()
        .ok_or_else(|| RnError::NotInitialized)
}

/// Validate node key manager exists and mobile manager doesn't, return manager or error
fn validate_node_manager(inner: &KeysInner) -> Result<&Arc<RwLock<NodeKeyManager>>, RnError> {
    // Check for wrong manager type first
    if inner.mobile_key_manager.is_some() {
        return Err(RnError::WrongManagerType("expected node manager, found mobile manager".into()));
    }

    // Check if node manager exists
    inner.node_key_manager.as_ref()
        .ok_or_else(|| RnError::NotInitialized)
}

/// Helper to work with validated mobile manager
fn with_validated_mobile_manager<F>(inner: &KeysInner, f: F) -> Result<(), RnError>
where F: FnOnce(&mut MobileKeyManager) -> Result<(), RnError> {
    let manager = validate_mobile_manager(inner)?;
    let mut mgr = manager.write().map_err(|_| RnError::LockError)?;
    f(&mut mgr)
}

/// Helper to work with validated node manager
fn with_validated_node_manager<F>(inner: &KeysInner, f: F) -> Result<(), RnError>
where F: FnOnce(&mut NodeKeyManager) -> Result<(), RnError> {
    let manager = validate_node_manager(inner)?;
    let mut mgr = manager.write().map_err(|_| RnError::LockError)?;
    f(&mut mgr)
}
```

#### **1.3 Create Initialization Functions**
**File:** `src/lib.rs`

```rust
/// Initialize FFI instance as mobile manager
/// Returns error if already initialized with different type
#[no_mangle]
pub unsafe extern "C" fn rn_keys_init_as_mobile(
    keys: *mut c_void,
    err: *mut RnError
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Check if already initialized with wrong type
    if inner.node_key_manager.is_some() {
        set_error(err, RN_ERROR_WRONG_MANAGER_TYPE,
                 "already initialized as node manager");
        return RN_ERROR_WRONG_MANAGER_TYPE;
    }

    // Check if already initialized as mobile
    if inner.mobile_key_manager.is_some() {
        return 0; // Already initialized correctly
    }

    // Initialize mobile manager
    match MobileKeyManager::new(inner.logger.clone()) {
        Ok(mut manager) => {
            // Apply existing configuration
            if let Some(ks) = &inner.device_keystore {
                manager.register_device_keystore(ks.clone());
            }
            if let Some(dir) = &inner.persistence_dir {
                manager.set_persistence_dir(dir.clone());
            }
            manager.enable_auto_persist(inner.auto_persist);

            inner.mobile_key_manager = Some(Arc::new(RwLock::new(manager)));
            0
        }
        Err(e) => {
            set_error(err, RN_ERROR_KEYSTORE_FAILED, &format!("failed to create mobile manager: {e}"));
            RN_ERROR_KEYSTORE_FAILED
        }
    }
}

/// Initialize FFI instance as node manager
/// Returns error if already initialized with different type
#[no_mangle]
pub unsafe extern "C" fn rn_keys_init_as_node(
    keys: *mut c_void,
    err: *mut RnError
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Check if already initialized with wrong type
    if inner.mobile_key_manager.is_some() {
        set_error(err, RN_ERROR_WRONG_MANAGER_TYPE,
                 "already initialized as mobile manager");
        return RN_ERROR_WRONG_MANAGER_TYPE;
    }

    // Check if already initialized as node
    if inner.node_key_manager.is_some() {
        return 0; // Already initialized correctly
    }

    // Initialize node manager
    match NodeKeyManager::new(inner.logger.clone()) {
        Ok(manager) => {
            // Apply existing configuration
            if let Some(ks) = &inner.device_keystore {
                manager.register_device_keystore(ks.clone());
            }
            if let Some(dir) = &inner.persistence_dir {
                manager.set_persistence_dir(dir.clone());
            }
            manager.enable_auto_persist(inner.auto_persist);

            inner.node_key_manager = Some(Arc::new(RwLock::new(manager)));
            0
        }
        Err(e) => {
            set_error(err, RN_ERROR_KEYSTORE_FAILED, &format!("failed to create node manager: {e}"));
            RN_ERROR_KEYSTORE_FAILED
        }
    }
}
```

---

### **PHASE 2: Standardize Error Codes**

#### **2.1 Define Error Constants**
**File:** `src/lib.rs`

```rust
// Error code constants - unique for each error type
const RN_ERROR_NULL_ARGUMENT: i32 = 1;
const RN_ERROR_INVALID_HANDLE: i32 = 2;
const RN_ERROR_NOT_INITIALIZED: i32 = 3;
const RN_ERROR_WRONG_MANAGER_TYPE: i32 = 4;
const RN_ERROR_OPERATION_FAILED: i32 = 5;
const RN_ERROR_SERIALIZATION_FAILED: i32 = 6;
const RN_ERROR_KEYSTORE_FAILED: i32 = 7;
const RN_ERROR_MEMORY_ALLOCATION: i32 = 8;
const RN_ERROR_LOCK_ERROR: i32 = 9;
const RN_ERROR_INVALID_UTF8: i32 = 10;
```

---

### **PHASE 3: Function-Specific Updates**

#### **3.1 Split Decision-Logic Functions**

**Replace:** `rn_keys_encrypt_with_envelope()`
**With:**
```rust
#[no_mangle]
pub unsafe extern "C" fn rn_keys_node_encrypt_with_envelope(
    keys: *mut c_void,
    data: *const u8,
    data_len: usize,
    network_id: *const c_char,
    profile_pks: *const *const u8,
    profile_lens: *const usize,
    profiles_count: usize,
    out_eed_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if data.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "data pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if data_len == 0 {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "data length is zero");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_eed_cbor.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output EED CBOR pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    // Additional validation for profile keys if provided
    if profiles_count > 0 {
        if profile_pks.is_null() {
            set_error(err, RN_ERROR_NULL_ARGUMENT, "profile public keys pointer is null but count > 0");
            return RN_ERROR_NULL_ARGUMENT;
        }
        if profile_lens.is_null() {
            set_error(err, RN_ERROR_NULL_ARGUMENT, "profile key lengths pointer is null but count > 0");
            return RN_ERROR_NULL_ARGUMENT;
        }
    }

    // Validate handle upfront
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Validate manager upfront - exit early on errors
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code, &e.message);
            return e.code;
        }
    };

    // Main logic - manager is guaranteed to exist
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let network_id_opt = if network_id.is_null() {
        None
    } else {
        match std::ffi::CStr::from_ptr(network_id).to_str() {
            Ok(s) => Some(s.to_string()),
            Err(_) => {
                set_error(err, RN_ERROR_INVALID_UTF8, "invalid utf8 network id");
                return RN_ERROR_INVALID_UTF8;
            }
        }
    };

    // Process profile keys
    let mut profiles: Vec<Vec<u8>> = Vec::new();
    if profiles_count > 0 && !profile_pks.is_null() && !profile_lens.is_null() {
        for i in 0..profiles_count {
            let pk_ptr = unsafe { *profile_pks.add(i) };
            let len = unsafe { *profile_lens.add(i) };
            if !pk_ptr.is_null() {
                let pk = unsafe { std::slice::from_raw_parts(pk_ptr, len) };
                profiles.push(pk.to_vec());
            }
        }
    }

    let mut node_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    match node_manager.encrypt_with_envelope(data_slice, network_id_opt.as_deref(), profiles) {
        Ok(eed) => {
            let cbor = match serde_cbor::to_vec(&eed) {
                Ok(v) => v,
                Err(e) => {
                    set_error(err, RN_ERROR_SERIALIZATION_FAILED, &format!("encode EED failed: {e}"));
                    return RN_ERROR_SERIALIZATION_FAILED;
                }
            };
            if !alloc_bytes(out_eed_cbor, out_len, &cbor) {
                set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
                RN_ERROR_MEMORY_ALLOCATION
            } else {
                0
            }
        }
        Err(e) => {
            set_error(err, RN_ERROR_OPERATION_FAILED, &format!("encrypt_with_envelope failed: {e}"));
            RN_ERROR_OPERATION_FAILED
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_encrypt_with_envelope(
    keys: *mut c_void,
    data: *const u8,
    data_len: usize,
    network_id: *const c_char,
    profile_pks: *const *const u8,
    profile_lens: *const usize,
    profiles_count: usize,
    out_eed_cbor: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if data.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "data pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if data_len == 0 {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "data length is zero");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_eed_cbor.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output EED CBOR pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    // Additional validation for profile keys if provided
    if profiles_count > 0 {
        if profile_pks.is_null() {
            set_error(err, RN_ERROR_NULL_ARGUMENT, "profile public keys pointer is null but count > 0");
            return RN_ERROR_NULL_ARGUMENT;
        }
        if profile_lens.is_null() {
            set_error(err, RN_ERROR_NULL_ARGUMENT, "profile key lengths pointer is null but count > 0");
            return RN_ERROR_NULL_ARGUMENT;
        }
    }

    // Validate handle upfront
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Validate manager upfront - exit early on errors
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code, &e.message);
            return e.code;
        }
    };

    // Main logic - manager is guaranteed to exist
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let network_id_opt = if network_id.is_null() {
        None
    } else {
        match std::ffi::CStr::from_ptr(network_id).to_str() {
            Ok(s) => Some(s.to_string()),
            Err(_) => {
                set_error(err, RN_ERROR_INVALID_UTF8, "invalid utf8 network id");
                return RN_ERROR_INVALID_UTF8;
            }
        }
    };

    // Process profile keys
    let mut profiles: Vec<Vec<u8>> = Vec::new();
    if profiles_count > 0 && !profile_pks.is_null() && !profile_lens.is_null() {
        for i in 0..profiles_count {
            let pk_ptr = unsafe { *profile_pks.add(i) };
            let len = unsafe { *profile_lens.add(i) };
            if !pk_ptr.is_null() {
                let pk = unsafe { std::slice::from_raw_parts(pk_ptr, len) };
                profiles.push(pk.to_vec());
            }
        }
    }

    let mut mobile_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    match mobile_manager.encrypt_with_envelope(data_slice, network_id_opt.as_deref(), profiles) {
        Ok(eed) => {
            let cbor = match serde_cbor::to_vec(&eed) {
                Ok(v) => v,
                Err(e) => {
                    set_error(err, RN_ERROR_SERIALIZATION_FAILED, &format!("encode EED failed: {e}"));
                    return RN_ERROR_SERIALIZATION_FAILED;
                }
            };
            if !alloc_bytes(out_eed_cbor, out_len, &cbor) {
                set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
                RN_ERROR_MEMORY_ALLOCATION
            } else {
                0
            }
        }
        Err(e) => {
            set_error(err, RN_ERROR_OPERATION_FAILED, &format!("encrypt_with_envelope failed: {e}"));
            RN_ERROR_OPERATION_FAILED
        }
    }
}
```

#### **3.2 Update Node-Only Functions**
Functions like `rn_keys_encrypt_local_data()` become:

```rust
#[no_mangle]
pub unsafe extern "C" fn rn_keys_encrypt_local_data(
    keys: *mut c_void,
    data: *const u8,
    data_len: usize,
    out_cipher: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError,
) -> i32 {
    // Validate parameters upfront - specific error messages
    if keys.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if data.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "data pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if data_len == 0 {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "data length is zero");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_cipher.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output cipher pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }
    if out_len.is_null() {
        set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
        return RN_ERROR_NULL_ARGUMENT;
    }

    // Validate handle upfront
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Validate manager upfront - exit early on errors
    let manager = match validate_node_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code, &e.message);
            return e.code;
        }
    };

    // Main logic - manager is guaranteed to exist
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let mut node_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    match node_manager.encrypt_local_data(data_slice) {
        Ok(cipher) => {
            if !alloc_bytes(out_cipher, out_len, &cipher) {
                set_error(err, RN_ERROR_MEMORY_ALLOCATION, "alloc failed");
                RN_ERROR_MEMORY_ALLOCATION
            } else {
                0
            }
        }
        Err(e) => {
            set_error(err, RN_ERROR_OPERATION_FAILED, &format!("encrypt_local_data failed: {e}"));
            RN_ERROR_OPERATION_FAILED
        }
    }
}
```

#### **3.3 Update Mobile-Only Functions**
Remove the duplicated initialization code and use upfront validation:

```rust
#[no_mangle]
pub unsafe extern "C" fn rn_keys_mobile_initialize_user_root_key(
    keys: *mut c_void,
    err: *mut RnError,
) -> i32 {
    // Validate handle upfront
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Validate manager upfront - exit early on errors
    let manager = match validate_mobile_manager(inner) {
        Ok(mgr) => mgr,
        Err(e) => {
            set_error(err, e.code, &e.message);
            return e.code;
        }
    };

    // Main logic - manager is guaranteed to exist
    let mut mobile_manager = match manager.write() {
        Ok(mgr) => mgr,
        Err(_) => {
            set_error(err, RN_ERROR_LOCK_ERROR, "failed to acquire lock");
            return RN_ERROR_LOCK_ERROR;
        }
    };

    match mobile_manager.initialize_user_root_key() {
        Ok(_) => 0,
        Err(e) => {
            set_error(err, RN_ERROR_OPERATION_FAILED, &format!("initialize_user_root_key failed: {e}"));
            RN_ERROR_OPERATION_FAILED
        }
    }
}
```

---

### **PHASE 4: Update Supporting Functions**

#### **4.1 Update Persistence Functions**
```rust
#[no_mangle]
pub unsafe extern "C" fn rn_keys_set_persistence_dir(
    keys: *mut c_void,
    dir: *const c_char,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Set directory for whichever manager exists
    if let Some(manager) = &inner.node_key_manager {
        let mut mgr = manager.write().unwrap();
        mgr.set_persistence_dir(PathBuf::from(dir_str));
    }
    if let Some(manager) = &inner.mobile_key_manager {
        let mut mgr = manager.write().unwrap();
        mgr.set_persistence_dir(PathBuf::from(dir_str));
    }

    inner.persistence_dir = Some(PathBuf::from(dir_str));
    0
}
```

#### **4.2 Update Device Keystore Registration**
```rust
#[no_mangle]
pub unsafe extern "C" fn rn_keys_register_apple_device_keystore(
    keys: *mut c_void,
    label: *const c_char,
    err: *mut RnError,
) -> i32 {
    let Some(inner) = with_keys_inner(keys) else {
        set_error(err, RN_ERROR_INVALID_HANDLE, "keys handle is null");
        return RN_ERROR_INVALID_HANDLE;
    };

    // Register with whichever manager exists
    if let Some(manager) = &inner.node_key_manager {
        let mut mgr = manager.write().unwrap();
        mgr.register_device_keystore(ks.clone());
    }
    if let Some(manager) = &inner.mobile_key_manager {
        let mut mgr = manager.write().unwrap();
        mgr.register_device_keystore(ks.clone());
    }

    inner.device_keystore = Some(ks);
    0
}
```

---

## **🔍 IMPROVED VALIDATION PATTERNS**

### **Parameter Validation Examples**

#### **1. Functions with Complex Parameters (like encrypt_with_envelope)**
```rust
// Validate each parameter specifically with descriptive error messages
if keys.is_null() {
    set_error(err, RN_ERROR_NULL_ARGUMENT, "keys handle is null");
    return RN_ERROR_NULL_ARGUMENT;
}
if data.is_null() {
    set_error(err, RN_ERROR_NULL_ARGUMENT, "data pointer is null");
    return RN_ERROR_NULL_ARGUMENT;
}
if data_len == 0 {
    set_error(err, RN_ERROR_NULL_ARGUMENT, "data length is zero");
    return RN_ERROR_NULL_ARGUMENT;
}
if network_id.is_null() {
    set_error(err, RN_ERROR_NULL_ARGUMENT, "network ID pointer is null");
    return RN_ERROR_NULL_ARGUMENT;
}
if out_eed_cbor.is_null() {
    set_error(err, RN_ERROR_NULL_ARGUMENT, "output EED CBOR pointer is null");
    return RN_ERROR_NULL_ARGUMENT;
}
if out_len.is_null() {
    set_error(err, RN_ERROR_NULL_ARGUMENT, "output length pointer is null");
    return RN_ERROR_NULL_ARGUMENT;
}
```

#### **2. Functions with Array Parameters**
```rust
// Validate array parameters with additional checks
if profile_pks.is_null() {
    set_error(err, RN_ERROR_NULL_ARGUMENT, "profile public keys array is null");
    return RN_ERROR_NULL_ARGUMENT;
}
if profile_lens.is_null() {
    set_error(err, RN_ERROR_NULL_ARGUMENT, "profile key lengths array is null");
    return RN_ERROR_NULL_ARGUMENT;
}
if profiles_count > 1000 {
    set_error(err, RN_ERROR_INVALID_ARGUMENT, "too many profiles (max 1000)");
    return RN_ERROR_INVALID_ARGUMENT;
}
```

#### **3. Functions with String Parameters**
```rust
// Validate string parameters
if label.is_null() {
    set_error(err, RN_ERROR_NULL_ARGUMENT, "label string pointer is null");
    return RN_ERROR_NULL_ARGUMENT;
}
// Validate UTF-8 later when converting, but check for null here
```

#### **4. Functions with Optional Parameters**
```rust
// Check optional parameters only if they should be provided
if some_flag && optional_param.is_null() {
    set_error(err, RN_ERROR_NULL_ARGUMENT, "optional parameter required when flag is set");
    return RN_ERROR_NULL_ARGUMENT;
}
```

---

## **📋 IMPLEMENTATION CHECKLIST**

### **Phase 1: Core Architecture**
- [ ] Update `KeysInner` structure with separate fields
- [ ] Implement `with_mobile_manager()` and `with_node_manager()` helpers
- [ ] Implement `rn_keys_init_as_mobile()` and `rn_keys_init_as_node()`
- [ ] Define standardized error codes
- [ ] Replace `rn_keys_new()` with new initialization functions

### **Phase 2: Function Migration**
- [ ] Split `rn_keys_encrypt_with_envelope()` into node and mobile versions
- [ ] Split `rn_keys_decrypt_envelope()` into node and mobile versions
- [ ] Update all node-only functions to use `with_node_manager()`
- [ ] Update all mobile-only functions to use `with_mobile_manager()`
- [ ] Remove all lazy initialization code from mobile functions

### **Phase 3: Supporting Functions**
- [ ] Update persistence functions for single-manager operation
- [ ] Update device keystore registration functions
- [ ] Update state management functions
- [ ] Standardize error handling across all functions

### **Phase 4: Testing and Documentation**
- [ ] Update tests for new architecture
- [ ] Test error cases for wrong manager types
- [ ] Document all error codes and their meanings
- [ ] Update API documentation

---

## **🎯 SUCCESS CRITERIA**

### **Code Quality:**
- ✅ **Zero decision logic** - no complex if/else chains
- ✅ **Zero code duplication** - single initialization path
- ✅ **Single responsibility** - each function does exactly one thing
- ✅ **Consistent error codes** - documented error code system

### **Architecture:**
- ✅ **Separate manager fields** - clear separation between mobile and node
- ✅ **Explicit initialization** - clear functions for each manager type
- ✅ **No lazy initialization** - functions validate and return errors
- ✅ **No fallbacks** - clear errors for wrong manager types

### **API Design:**
- ✅ **Clear function names** - `rn_keys_node_*()` and `rn_keys_mobile_*()` prefixes
- ✅ **Predictable behavior** - each function's purpose is obvious
- ✅ **Proper error handling** - all error cases return appropriate error codes

---

## **🚀 IMMEDIATE NEXT STEPS**

1. **Start with Phase 1** - Update the core structure and helpers
2. **Implement initialization functions** - `rn_keys_init_as_mobile()` and `rn_keys_init_as_node()`
3. **Create validation helpers** - `with_mobile_manager()` and `with_node_manager()`
4. **Define error codes** - Standardize error code constants
5. **Begin function migration** - Start with the most critical decision-logic functions

**This design completely eliminates the architectural problems while providing clear, predictable behavior for all functions.**
