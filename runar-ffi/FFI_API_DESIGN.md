# FFI API Design Document - NodeKeyManager Dual-Role Implementation

## Overview

This document specifies the required changes to the FFI API (`runar-ffi/src/lib.rs`) to align with the latest `runar-keys` and `runar-transporter` crates while implementing the NodeKeyManager dual-role design. The FFI must expose all new APIs while preserving existing transporter callbacks that are currently working.

## Current State Analysis

### Working Components (MUST PRESERVE)
- **Transporter callbacks** - Currently working, must not break
- **Basic key manager initialization** - `rn_keys_init_as_node` and `rn_keys_init_as_mobile`
- **Core envelope encryption/decryption** - `rn_keys_node_encrypt_with_envelope`, `rn_keys_node_decrypt_envelope`
- **Network key management** - `rn_keys_mobile_*` functions for network operations
- **Transport operations** - `rn_transport_*` functions for QUIC transport

### Issues to Fix
1. **Outdated NodeKeyManager API** - Current FFI uses old `NodeKeyManager::new()` that generates keys immediately
2. **Missing new APIs** - Profile key management, CA Node operations, certificate management
3. **Type mismatches** - Some return types and parameters don't match current API
4. **Missing error handling** - New error types not exposed

## Required Changes

### 1. NodeKeyManager Lifecycle Updates (CRITICAL)

#### Current Problem
```rust
// Current FFI (WRONG)
let manager = NodeKeyManager::new(logger)?; // Generates keys immediately
```

#### Required Fix
```rust
// New FFI (CORRECT)
let manager = NodeKeyManager::new(logger)?; // No key generation
let ready = manager.probe_and_load_state()?;
if !ready {
    manager.generate_keys()?; // Generate keys only when needed
}
```

#### FFI Functions to Update
- `rn_keys_init_as_node` - Update to handle new lifecycle
- `rn_keys_node_get_keystore_state` - Update to handle `Option<String>` return types
- All functions that assume keys exist - Add proper error handling

### 2. New NodeKeyManager APIs (CRITICAL)

#### Profile Key Management
```rust
// New FFI functions needed
pub extern "C" fn rn_keys_node_derive_user_profile_key(
    keys: *mut c_void,
    label: *const c_char,
    out_public_key: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_keys_node_decrypt_with_profile(
    keys: *mut c_void,
    envelope_data: *const u8,
    envelope_len: usize,
    profile_id: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;
```

#### Certificate Management
```rust
// New FFI functions needed
pub extern "C" fn rn_keys_node_get_certificate_status(
    keys: *mut c_void,
    out_status: *mut i32,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_keys_node_get_quic_certificate_config(
    keys: *mut c_void,
    out_config: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_keys_node_validate_peer_certificate(
    keys: *mut c_void,
    peer_cert: *const u8,
    cert_len: usize,
    err: *mut RnError
) -> i32;
```

#### Network Key Management
```rust
// New FFI functions needed
pub extern "C" fn rn_keys_node_install_network_key(
    keys: *mut c_void,
    network_key_message: *const u8,
    message_len: usize,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_keys_node_get_network_agreement(
    keys: *mut c_void,
    network_public_key: *const u8,
    key_len: usize,
    out_agreement: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_keys_node_has_network_private_key(
    keys: *mut c_void,
    network_public_key: *const u8,
    key_len: usize,
    out_has_key: *mut i32,
    err: *mut RnError
) -> i32;
```

### 3. CA Node APIs (NEW)

#### CA Node Management
```rust
// New FFI functions for CA Node operations
pub extern "C" fn rn_keys_ca_node_new(
    logger: *mut c_void,
    out_ca_node: *mut *mut c_void,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_keys_ca_node_install_issuing_ca(
    ca_node: *mut c_void,
    issuing_ca_key: *const u8,
    key_len: usize,
    issuing_ca_cert: *const u8,
    cert_len: usize,
    root_ca_cert: *const u8,
    root_cert_len: usize,
    ea_public_keys: *const u8,
    ea_keys_len: usize,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_keys_ca_node_configure_enrollment_authority(
    ca_node: *mut c_void,
    ea_public_keys: *const u8,
    keys_len: usize,
    err: *mut RnError
) -> i32;
```

#### CA Node Operations
```rust
// Enrollment operations
pub extern "C" fn rn_keys_ca_node_handle_enroll(
    ca_node: *mut c_void,
    request: *const u8,
    request_len: usize,
    remote_addr: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

// Renewal operations
pub extern "C" fn rn_keys_ca_node_handle_renew(
    ca_node: *mut c_void,
    request: *const u8,
    request_len: usize,
    peer_cert: *const u8,
    cert_len: usize,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

// Revocation operations
pub extern "C" fn rn_keys_ca_node_handle_revoke(
    ca_node: *mut c_void,
    request: *const u8,
    request_len: usize,
    admin_ski: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

// Chain and status operations
pub extern "C" fn rn_keys_ca_node_handle_chain(
    ca_node: *mut c_void,
    network_id: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_keys_ca_node_handle_status(
    ca_node: *mut c_void,
    network_id: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

// CRL operations
pub extern "C" fn rn_keys_ca_node_handle_crl(
    ca_node: *mut c_void,
    network_id: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;
```

### 4. CA Server APIs (NEW)

#### CA Server Management
```rust
// CA Server creation and configuration
pub extern "C" fn rn_transport_ca_server_new(
    config: *const u8,
    config_len: usize,
    ca_node: *mut c_void,
    logger: *mut c_void,
    out_server: *mut *mut c_void,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_transport_ca_server_configure_admin_skis(
    server: *mut c_void,
    admin_skis: *const u8,
    skis_len: usize,
    err: *mut RnError
) -> i32;

// CA Server operations
pub extern "C" fn rn_transport_ca_server_start(
    server: *mut c_void,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_transport_ca_server_stop(
    server: *mut c_void,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_transport_ca_server_get_bootstrap_addr(
    server: *mut c_void,
    out_addr: *mut *mut c_char,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_transport_ca_server_get_authenticated_addr(
    server: *mut c_void,
    out_addr: *mut *mut c_char,
    err: *mut RnError
) -> i32;
```

### 5. CA Client APIs (NEW)

#### CA Client Management
```rust
// CA Client creation and operations
pub extern "C" fn rn_transport_ca_client_new(
    logger: *mut c_void,
    out_client: *mut *mut c_void,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_transport_ca_client_enroll(
    client: *mut c_void,
    bootstrap_addr: *const c_char,
    request: *const u8,
    request_len: usize,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_transport_ca_client_renew(
    client: *mut c_void,
    authenticated_addr: *const c_char,
    request: *const u8,
    request_len: usize,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_transport_ca_client_revoke(
    client: *mut c_void,
    authenticated_addr: *const c_char,
    request: *const u8,
    request_len: usize,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_transport_ca_client_get_chain(
    client: *mut c_void,
    bootstrap_addr: *const c_char,
    network_id: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_transport_ca_client_get_status(
    client: *mut c_void,
    authenticated_addr: *const c_char,
    network_id: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

pub extern "C" fn rn_transport_ca_client_get_crl(
    client: *mut c_void,
    authenticated_addr: *const c_char,
    network_id: *const c_char,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;
```

### 6. Updated Return Types and Error Handling

#### Updated Return Types
```rust
// Current (WRONG)
pub extern "C" fn rn_keys_node_get_node_id(
    keys: *mut c_void,
    out_id: *mut *mut c_char,
    err: *mut RnError
) -> i32;

// New (CORRECT)
pub extern "C" fn rn_keys_node_get_node_id(
    keys: *mut c_void,
    out_id: *mut *mut c_char,
    out_has_id: *mut i32, // 1 if has ID, 0 if not
    err: *mut RnError
) -> i32;
```

#### New Error Codes
```rust
// Add new error codes for CA operations
pub const RN_ERROR_CA_NODE_NOT_INITIALIZED: i32 = 1001;
pub const RN_ERROR_CA_SERVER_NOT_RUNNING: i32 = 1002;
pub const RN_ERROR_CA_CLIENT_CONNECTION_FAILED: i32 = 1003;
pub const RN_ERROR_CERTIFICATE_VALIDATION_FAILED: i32 = 1004;
pub const RN_ERROR_PROFILE_KEY_NOT_FOUND: i32 = 1005;
pub const RN_ERROR_ENROLLMENT_TOKEN_INVALID: i32 = 1006;
pub const RN_ERROR_RATE_LIMIT_EXCEEDED: i32 = 1007;
pub const RN_ERROR_ADMIN_NOT_AUTHORIZED: i32 = 1008;
```

### 7. Data Structures for FFI

#### New C-compatible structures
```rust
// CA Server Configuration
#[repr(C)]
pub struct CaServerConfig {
    pub bootstrap_bind: *const c_char,
    pub authenticated_bind: *const c_char,
    pub network_id: *const c_char,
    pub rate_limit_per_minute: u32,
    pub rate_limit_per_hour: u32,
}

// CA Client Configuration
#[repr(C)]
pub struct CaClientConfig {
    pub root_ca_cert: *const u8,
    pub root_ca_cert_len: usize,
    pub timeout_seconds: u32,
}

// Certificate Status
#[repr(C)]
pub struct CertificateStatus {
    pub is_valid: i32,
    pub not_before: u64,
    pub not_after: u64,
    pub serial_hex: *mut c_char,
}

// Profile Key Info
#[repr(C)]
pub struct ProfileKeyInfo {
    pub profile_id: *mut c_char,
    pub public_key: *mut u8,
    pub public_key_len: usize,
}
```

## Implementation Plan

### Phase 1: Complete FFI Rewrite (CRITICAL)
1. **Delete existing FFI** - Remove all old FFI functions
2. **Create new FFI structure** - Clean, modern API design
3. **Implement core key managers** - NodeKeyManager and MobileKeyManager
4. **Add proper error handling** - Comprehensive error codes and validation

### Phase 2: NodeKeyManager Dual-Role APIs
1. **Profile key management** - derive_user_profile_key, decrypt_with_profile
2. **Certificate management** - get_certificate_status, get_quic_certificate_config
3. **Network key management** - install_network_key, get_network_agreement
4. **Lifecycle management** - proper key generation and state loading

### Phase 3: CA Node Infrastructure
1. **CA Node creation** - new, install_issuing_ca, configure_enrollment_authority
2. **CA operations** - handle_enroll, handle_renew, handle_revoke, handle_chain, handle_status, handle_crl
3. **Error handling** - specific error codes for CA operations
4. **Memory management** - proper C-compatible data structures

### Phase 4: CA Server/Client Transport
1. **CA Server** - creation, configuration, start/stop, admin management
2. **CA Client** - creation, all CA operations (enroll, renew, revoke, chain, status, CRL)
3. **Transport integration** - proper QUIC transport handling
4. **Configuration** - server and client configuration structures

### Phase 5: Testing and Validation
1. **Unit tests** - Test each FFI function individually
2. **Integration tests** - Test end-to-end scenarios
3. **Memory tests** - Validate memory management and cleanup
4. **Performance tests** - Ensure efficient FFI design

## Full Refactor Approach

### No Backward Compatibility
- **Complete rewrite** of FFI API to align with latest design
- **Clean, modern API** following current best practices
- **No legacy support** - all APIs are new and properly designed
- **Single source of truth** - FFI directly exposes current crate APIs

### Design Principles
- **Clean API surface** - Only expose what's actually needed
- **Consistent patterns** - All functions follow the same naming and parameter conventions
- **Proper error handling** - Comprehensive error codes and validation
- **Memory safety** - Proper C-compatible memory management
- **Performance first** - Efficient FFI design with minimal overhead

## Security Considerations

### Input Validation
- All string inputs must be validated for null termination
- All buffer inputs must be validated for length
- All certificate inputs must be validated for format

### Error Handling
- Never expose internal error details to FFI
- Always return appropriate error codes
- Log detailed errors internally for debugging

### Memory Management
- All allocated memory must be freed with `rn_free`
- All string allocations must be freed with `rn_string_free`
- Prevent memory leaks in error paths

## Testing Strategy

### Unit Tests
- Test each new FFI function individually
- Test error handling and edge cases
- Test memory management and cleanup

### Integration Tests
- Test integration with existing transporter
- Test end-to-end CA operations
- Test profile key management scenarios

### Compatibility Tests
- Test that existing code continues to work
- Test migration scenarios
- Test performance impact

## Conclusion

This design provides a comprehensive update to the FFI API that:
1. Fixes existing issues with NodeKeyManager lifecycle
2. Exposes all new APIs from the dual-role design
3. Preserves working transporter callbacks
4. Maintains backward compatibility where possible
5. Provides clear migration path for breaking changes
6. Ensures security and proper error handling

The implementation should follow the phased approach to minimize risk and ensure each component is properly tested before moving to the next phase.
