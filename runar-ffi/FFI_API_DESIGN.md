# FFI API Design – Complete Surface for CA Server/Client and Keys

## Authoritative FFI API Surface (Production-Ready)

This section enumerates the complete, production-ready FFI API required for external platforms (Swift/Kotlin/etc.) to run the entire CA flow end-to-end (server and client) and to manage node keys/certificates, fully aligned with current repository design and tests. All function names and conventions follow existing patterns in `runar-ffi/src/lib.rs`.

### Memory and Error Conventions
- All functions return 0 on success; non-zero codes on failure.
- On error, `err` must be set with a human-readable message.
- Any buffer returned by FFI must be freed by the caller via `rn_free`.
- Any C string returned by FFI must be freed via `rn_string_free`.
- Complex inputs/outputs are CBOR-encoded.

### Common Utilities
- `rn_free(ptr, len)`
- `rn_string_free(cstr)`
- `rn_last_error(out_buf, out_len) -> i32`
- `rn_set_log_level(level_i32)`

---

### Keys – Node Lifecycle, CSR, Certificate Install, QUIC
- `rn_keys_new(out_keys, err) -> i32`
- `rn_keys_free(keys)`
- `rn_keys_set_persistence_dir(keys, dir_cstr, err) -> i32`
- `rn_keys_enable_auto_persist(keys, enable_i32, err) -> i32`
- `rn_keys_wipe_persistence(keys, err) -> i32`
- `rn_keys_init_as_node(keys, err) -> i32`
- `rn_keys_node_get_keystore_state(keys, out_state_cbor_ptr, out_len, err) -> i32`
- `rn_keys_node_get_public_key(keys, out_ptr, out_len, err) -> i32`
- `rn_keys_node_get_agreement_public_key(keys, out_ptr, out_len, err) -> i32`
- `rn_keys_node_get_node_id(keys, out_cstr, err) -> i32`
- `rn_keys_node_generate_csr(keys, out_csr_der_ptr, out_len, err) -> i32`
- `rn_keys_node_install_certificate(keys, cert_message_cbor_ptr, len, err) -> i32`
- `rn_keys_node_get_quic_certificate_config(keys, out_config_cbor_ptr, out_len, err) -> i32`
- `rn_keys_node_get_node_certificate(keys, out_cert_der_ptr, out_len, err) -> i32` (recommended)

### Mobile – Certificate Response Conversion
- `rn_keys_init_as_mobile(keys, err) -> i32`
- `rn_keys_mobile_from_enroll_response(mobile, enroll_response_cbor, len, out_cert_msg_cbor, out_len, err) -> i32`
- `rn_keys_mobile_from_renew_response(mobile, renew_response_cbor, len, out_cert_msg_cbor, out_len, err) -> i32`

### Profile Key Operations (NodeKeyManager frontend/mobile role)
- `rn_keys_node_derive_user_profile_key(keys, label_cstr, out_pubkey_ptr, out_len, err) -> i32`
- `rn_keys_node_decrypt_with_profile(keys, envelope_cbor, len, profile_id_cstr, out_data_ptr, out_len, err) -> i32`

### CA Node – In-Process Authority
- `rn_keys_ca_node_new(logger, out_ca_node, err) -> i32`
- `rn_keys_ca_node_free(ca_node)`
- `rn_keys_ca_node_install_issuing_ca(ca_node, issuing_key_der, key_len, issuing_cert_der, cert_len, root_ca_der, root_len, ea_public_keys_cbor, ea_len, err) -> i32`
- `rn_keys_ca_node_configure_enrollment_authority(ca_node, ea_public_keys_cbor, len, err) -> i32`
- `rn_keys_ca_node_handle_enroll(ca_node, request_cbor, len, remote_addr_cstr, out_response_cbor, out_len, err) -> i32`
- `rn_keys_ca_node_handle_renew(ca_node, request_cbor, len, peer_cert_der, peer_len, out_response_cbor, out_len, err) -> i32`
- `rn_keys_ca_node_handle_revoke(ca_node, request_cbor, len, admin_ski_cstr, out_response_cbor, out_len, err) -> i32`
- `rn_keys_ca_node_handle_chain(ca_node, network_id_cstr, out_response_cbor, out_len, err) -> i32`
- `rn_keys_ca_node_handle_status(ca_node, network_id_cstr, out_response_cbor, out_len, err) -> i32`
- `rn_keys_ca_node_handle_crl(ca_node, network_id_cstr, out_response_cbor, out_len, err) -> i32`

### CA Server – QUIC Servers (Bootstrap + Authenticated)
- `rn_transport_ca_server_new(config_cbor, len, ca_node, logger, out_server, err) -> i32`
- `rn_transport_ca_server_free(server)`
- `rn_transport_ca_server_configure_admin_skis(server, admin_skis_cbor, len, err) -> i32`
- `rn_transport_ca_server_start(server, err) -> i32`
- `rn_transport_ca_server_stop(server, err) -> i32`
- `rn_transport_ca_server_get_bootstrap_addr(server, out_cstr, err) -> i32`
- `rn_transport_ca_server_get_authenticated_addr(server, out_cstr, err) -> i32`

### CA Client – QUIC Client
- `rn_transport_ca_client_new(logger, out_client, err) -> i32`
- `rn_transport_ca_client_free(client)`
- `rn_transport_ca_client_enroll(client, bootstrap_addr_cstr, request_cbor, len, out_response_cbor, out_len, err) -> i32`
- `rn_transport_ca_client_renew(client, authenticated_addr_cstr, request_cbor, len, out_response_cbor, out_len, err) -> i32`
- `rn_transport_ca_client_revoke(client, authenticated_addr_cstr, request_cbor, len, out_response_cbor, out_len, err) -> i32`
- `rn_transport_ca_client_get_chain(client, bootstrap_addr_cstr, network_id_cstr, out_response_cbor, out_len, err) -> i32`
- `rn_transport_ca_client_get_status(client, authenticated_addr_cstr, network_id_cstr, out_response_cbor, out_len, err) -> i32`
- `rn_transport_ca_client_get_crl(client, authenticated_addr_cstr, network_id_cstr, out_response_cbor, out_len, err) -> i32`

### Certificate Helpers (Optional)
- `rn_keys_certificate_extract_ski(cert_der, len, out_hex_cstr, err) -> i32`
- `rn_keys_certificate_get_serial(cert_der, len, out_hex_cstr, err) -> i32`

### Error Codes (Additions)
- `RN_ERROR_CA_NODE_NOT_INITIALIZED`
- `RN_ERROR_CA_SERVER_NOT_RUNNING`
- `RN_ERROR_CA_CLIENT_CONNECTION_FAILED`
- `RN_ERROR_CERTIFICATE_VALIDATION_FAILED`
- `RN_ERROR_PROFILE_KEY_NOT_FOUND`

---

## FFI E2E Test Plan – QUIC CA Flow Parity

This section defines an FFI-based end-to-end test sequence that mirrors `runar-transporter/tests/full_transport_e2e_test.rs`. It validates that external platforms can perform the entire flow through the FFI API.

All payloads denoted as CBOR must follow the same Rust-side structs used by transporter/keys:
- `CsrEnrollRequest`, `CsrEnrollResponse`
- `RenewRequest`, `RenewResponse`
- `RevokeRequest`, `RevokeResponse`
- `ChainRequest`/`ChainResponse`
- `StatusResponse`
- `CrlResponse`
- `NodeCertificateMessage`

### Phase 1: Setup
1) Logging
   - Call `rn_set_log_level(LogLevel::Debug as i32)`.
2) Crypto provider (Rust internal)
   - Rust-side test harness ensures rustls crypto provider is installed.
3) Keys handles
   - `rn_keys_new(&mut node_keys, &mut err)` for the mobile node role
   - `rn_keys_new(&mut mobile_keys, &mut err)` for `MobileKeyManager`
   - `rn_keys_init_as_node(node_keys, &mut err)`
   - `rn_keys_init_as_mobile(mobile_keys, &mut err)`

### Phase 2: CA Node and Server
1) CA Node
   - `rn_keys_ca_node_new(logger, &mut ca_node, &mut err)`
   - Prepare DER bytes for Issuing CA key/cert and Root CA cert (via Rust-side builder in test harness)
   - `rn_keys_ca_node_install_issuing_ca(ca_node, issuing_key_der, ..., issuing_cert_der, ..., root_ca_der, ..., ea_pubkeys_cbor, ..., &mut err)`
2) Enrollment Authority
   - `rn_keys_ca_node_configure_enrollment_authority(ca_node, ea_pubkeys_cbor, len, &mut err)`
3) QUIC Servers (bootstrap + authenticated)
   - Build CA server config CBOR: `{ bootstrap_bind: "127.0.0.1:0", authenticated_bind: "127.0.0.1:0", network_id: "test_network", rate_limit_per_minute: 5, rate_limit_per_hour: 30 }`
   - `rn_transport_ca_server_new(config_cbor, len, ca_node, logger, &mut server, &mut err)`
   - `rn_transport_ca_server_start(server, &mut err)`
   - `rn_transport_ca_server_get_bootstrap_addr(server, &mut bootstrap_cstr, &mut err)`
   - `rn_transport_ca_server_get_authenticated_addr(server, &mut authenticated_cstr, &mut err)`

### Phase 3: Mobile Node (client role) CSR and Enrollment
1) Generate CSR on node
   - `rn_keys_node_generate_csr(node_keys, &mut csr_ptr, &mut csr_len, &mut err)`
2) Enrollment Token (Rust-side helper)
   - Construct `EnrollmentToken` using Rust helper; CBOR serialize.
3) Build `CsrEnrollRequest` CBOR: `{ network_id: "test_network", csr_der, enrollment_token }`
4) CA Client
   - `rn_transport_ca_client_new(logger, &mut client, &mut err)`
   - `rn_transport_ca_client_enroll(client, bootstrap_addr_cstr, enroll_req_cbor, len, &mut resp_ptr, &mut resp_len, &mut err)` -> CBOR `CsrEnrollResponse`
5) Convert and Install Certificate
   - `rn_keys_mobile_from_enroll_response(mobile_keys, resp_ptr, resp_len, &mut cert_msg_ptr, &mut cert_msg_len, &mut err)` -> CBOR `NodeCertificateMessage`
   - `rn_keys_node_install_certificate(node_keys, cert_msg_ptr, cert_msg_len, &mut err)`
6) QUIC Cert Config Validation (optional asserts)
   - `rn_keys_node_get_quic_certificate_config(node_keys, &mut cfg_ptr, &mut cfg_len, &mut err)`

### Phase 4: Renewal (Authenticated, mTLS)
1) Generate renewal CSR
   - `rn_keys_node_generate_csr(node_keys, &mut csr_ptr, &mut csr_len, &mut err)`
2) `RenewRequest` CBOR: `{ network_id: "test_network", csr_der }`
3) `rn_transport_ca_client_renew(client, authenticated_addr_cstr, renew_req_cbor, len, &mut resp_ptr, &mut resp_len, &mut err)` -> CBOR `RenewResponse`
4) Convert and install
   - `rn_keys_mobile_from_renew_response(mobile_keys, resp_ptr, resp_len, &mut cert_msg_ptr, &mut cert_msg_len, &mut err)`
   - `rn_keys_node_install_certificate(node_keys, cert_msg_ptr, cert_msg_len, &mut err)`

### Phase 5: Revocation + CRL-lite
1) Admin SKI configuration
   - Extract SKI from node’s installed leaf cert (optional helper or Rust-side parsing)
   - `rn_transport_ca_server_configure_admin_skis(server, admin_skis_cbor, len, &mut err)`
2) Build `RevokeRequest` CBOR: `{ network_id: "test_network", certificate_serial, reason: "testing" }`
3) Revoke via client (mTLS)
   - `rn_transport_ca_client_revoke(client, authenticated_addr_cstr, revoke_req_cbor, len, &mut resp_ptr, &mut resp_len, &mut err)` -> `RevokeResponse`
4) CRL generation and fetch
   - `rn_keys_ca_node_handle_crl(ca_node, network_id_cstr, &mut crl_ptr, &mut crl_len, &mut err)` -> `CrlResponse`
   - `rn_transport_ca_client_get_crl(client, authenticated_addr_cstr, network_id_cstr, &mut crl2_ptr, &mut crl2_len, &mut err)` -> `CrlResponse`
   - Assert equality of key fields (e.g., issuing serial hex, revoked set size).

### Phase 6: Status and Chain
- `rn_transport_ca_client_get_status(client, authenticated_addr_cstr, network_id_cstr, &mut status_ptr, &mut status_len, &mut err)` -> `StatusResponse`
- `rn_transport_ca_client_get_chain(client, bootstrap_addr_cstr, network_id_cstr, &mut chain_ptr, &mut chain_len, &mut err)` -> `ChainResponse`

### Phase 7: Profile Keys
1) Derive profile keys
   - `rn_keys_node_derive_user_profile_key(node_keys, "personal", &mut pub_ptr, &mut pub_len, &mut err)`
   - `rn_keys_node_derive_user_profile_key(node_keys, "work", &mut pub2_ptr, &mut pub2_len, &mut err)`
2) Encrypt/decrypt envelope (Rust-side building of envelope or via existing FFI encrypt if needed)
   - Use `rn_keys_node_decrypt_with_profile(node_keys, envelope_cbor, len, personal_profile_id_cstr, &mut pt_ptr, &mut pt_len, &mut err)` and assert plaintext.

### Phase 8: Rate Limiting (Bootstrap)
- Send multiple `CsrEnrollRequest` via `rn_transport_ca_client_enroll` with token reuse to trigger server rate limits; expect first 5 succeed, 6th fails per configuration. Use short sleeps between calls as in test.

### Phase 9: Token Revocation
- Rust-side: `ca_node` revoke token internally (or provide an FFI if needed later).
- Attempt to enroll with revoked token; expect error from `rn_transport_ca_client_enroll`.

### Phase 10: Negative Cases
- Invalid token (wrong network_id)
- Unauthorized renewal (new node without enrollment) via `rn_transport_ca_client_renew` -> expect error

### Cleanup
- `rn_transport_ca_server_stop(server, &mut err)`
- `rn_transport_ca_server_free(server)`
- `rn_transport_ca_client_free(client)`
- `rn_keys_free(node_keys)`
- `rn_keys_free(mobile_keys)`
- `rn_keys_ca_node_free(ca_node)`

This FFI E2E validates that all CA server and client operations, certificate lifecycle, profile keys, and rate-limiting behaviors are fully achievable through the FFI layer.

---

+# FFI API Design Document - NodeKeyManager Dual-Role Implementation

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

### 4.1. Certificate Authority Creation APIs (NEW)

#### Root CA and Issuing CA Creation
```rust
// Create Root CA certificate
pub extern "C" fn rn_keys_ca_create_root_ca(
    subject: *const c_char,
    out_ca: *mut *mut c_void,
    err: *mut RnError
) -> i32;

// Create Issuing CA certificate (signed by Root CA)
pub extern "C" fn rn_keys_ca_create_issuing_ca(
    root_ca: *mut c_void,
    subject: *const c_char,
    validity_days: u32,
    serial: u64,
    out_ca: *mut *mut c_void,
    err: *mut RnError
) -> i32;

// Get CA certificate DER bytes
pub extern "C" fn rn_keys_ca_get_certificate_der(
    ca: *mut c_void,
    out_cert: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

// Get CA certificate subject
pub extern "C" fn rn_keys_ca_get_certificate_subject(
    ca: *mut c_void,
    out_subject: *mut *mut c_char,
    err: *mut RnError
) -> i32;

// Free CA resources
pub extern "C" fn rn_keys_ca_free(ca: *mut c_void);
```

### 4.2. Enrollment Token Management APIs (NEW)

#### Enrollment Token Generation
```rust
// Generate enrollment token
pub extern "C" fn rn_keys_enrollment_token_generate(
    ea_key: *const u8,
    key_len: usize,
    token_id: *const c_char,
    network_id: *const c_char,
    subject: *const c_char,
    not_before: u64,
    expires_at: u64,
    nonce: *const u8,
    nonce_len: usize,
    permissions: *const u8,
    permissions_len: usize,
    out_token: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

// Validate enrollment token
pub extern "C" fn rn_keys_enrollment_token_validate(
    token: *const u8,
    token_len: usize,
    ea_public_key: *const u8,
    key_len: usize,
    out_valid: *mut i32,
    err: *mut RnError
) -> i32;
```

### 4.3. Mobile Key Manager Integration APIs (NEW)

#### Mobile Key Manager Response Conversion
```rust
// Convert enrollment response to certificate message
pub extern "C" fn rn_keys_mobile_from_enroll_response(
    mobile: *mut c_void,
    response: *const u8,
    response_len: usize,
    out_cert_message: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

// Convert renewal response to certificate message
pub extern "C" fn rn_keys_mobile_from_renew_response(
    mobile: *mut c_void,
    response: *const u8,
    response_len: usize,
    out_cert_message: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;
```

### 4.4. Certificate Management APIs (NEW)

#### Certificate Operations
```rust
// Get QUIC certificate configuration
pub extern "C" fn rn_keys_node_get_quic_certificate_config(
    keys: *mut c_void,
    out_config: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

// Get node certificate
pub extern "C" fn rn_keys_node_get_node_certificate(
    keys: *mut c_void,
    out_cert: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

// Install certificate from certificate message
pub extern "C" fn rn_keys_node_install_certificate_from_message(
    keys: *mut c_void,
    cert_message: *const u8,
    cert_message_len: usize,
    err: *mut RnError
) -> i32;

// Extract certificate SKI
pub extern "C" fn rn_keys_certificate_extract_ski(
    cert: *const u8,
    cert_len: usize,
    out_ski: *mut *mut c_char,
    err: *mut RnError
) -> i32;

// Get certificate serial
pub extern "C" fn rn_keys_certificate_get_serial(
    cert: *const u8,
    cert_len: usize,
    out_serial: *mut *mut c_char,
    err: *mut RnError
) -> i32;
```

### 4.5. Profile Key Operations APIs (NEW)

#### Profile Key Encryption/Decryption
```rust
// Encrypt data with envelope using profile keys
pub extern "C" fn rn_keys_node_encrypt_with_envelope(
    keys: *mut c_void,
    data: *const u8,
    data_len: usize,
    network_key: *const u8,
    network_key_len: usize,
    profile_keys: *const u8,
    profile_keys_len: usize,
    out_envelope: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

// Decrypt envelope data using profile key
pub extern "C" fn rn_keys_node_decrypt_with_profile(
    keys: *mut c_void,
    envelope: *const u8,
    envelope_len: usize,
    profile_id: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;

// Get compact ID for profile key
pub extern "C" fn rn_keys_get_compact_id(
    public_key: *const u8,
    key_len: usize,
    out_id: *mut *mut c_char,
    err: *mut RnError
) -> i32;
```

### 4.6. CA Node Admin Management APIs (NEW)

#### CA Node Admin Operations
```rust
// Add admin SKI to CA Node
pub extern "C" fn rn_keys_ca_node_add_admin_ski(
    ca_node: *mut c_void,
    ski: *const c_char,
    err: *mut RnError
) -> i32;

// Revoke enrollment token
pub extern "C" fn rn_keys_ca_node_revoke_token(
    ca_node: *mut c_void,
    token_id: *const c_char,
    err: *mut RnError
) -> i32;

// Generate CRL-lite
pub extern "C" fn rn_keys_ca_node_generate_crl_lite(
    ca_node: *mut c_void,
    out_crl: *mut *mut u8,
    out_len: *mut usize,
    err: *mut RnError
) -> i32;
```

### 4.7. CA Client Configuration APIs (NEW)

#### CA Client Configuration
```rust
// Configure CA Client with server addresses and settings
pub extern "C" fn rn_transport_ca_client_configure(
    client: *mut c_void,
    bootstrap_server: *const c_char,
    authenticated_server: *const c_char,
    network_id: *const c_char,
    request_timeout_seconds: u32,
    max_retries: u32,
    err: *mut RnError
) -> i32;

// Set root CA certificate for client
pub extern "C" fn rn_transport_ca_client_set_root_ca_cert(
    client: *mut c_void,
    cert: *const u8,
    cert_len: usize,
    err: *mut RnError
) -> i32;

// Set issuing CA certificate for client
pub extern "C" fn rn_transport_ca_client_set_issuing_ca_cert(
    client: *mut c_void,
    cert: *const u8,
    cert_len: usize,
    err: *mut RnError
) -> i32;

// Set node key manager for client
pub extern "C" fn rn_transport_ca_client_set_node_key_manager(
    client: *mut c_void,
    node_keys: *mut c_void,
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
pub const RN_ERROR_CERTIFICATE_CREATION_FAILED: i32 = 1009;
pub const RN_ERROR_CERTIFICATE_SKI_EXTRACTION_FAILED: i32 = 1010;
pub const RN_ERROR_CERTIFICATE_SERIAL_EXTRACTION_FAILED: i32 = 1011;
pub const RN_ERROR_ENROLLMENT_TOKEN_GENERATION_FAILED: i32 = 1012;
pub const RN_ERROR_MOBILE_RESPONSE_CONVERSION_FAILED: i32 = 1013;
pub const RN_ERROR_PROFILE_KEY_ENCRYPTION_FAILED: i32 = 1014;
pub const RN_ERROR_PROFILE_KEY_DECRYPTION_FAILED: i32 = 1015;
pub const RN_ERROR_CA_CLIENT_CONFIGURATION_FAILED: i32 = 1016;
pub const RN_ERROR_CRL_GENERATION_FAILED: i32 = 1017;
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
    pub bootstrap_server: *const c_char,
    pub authenticated_server: *const c_char,
    pub network_id: *const c_char,
    pub request_timeout_seconds: u32,
    pub max_retries: u32,
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

// Enrollment Token Parameters
#[repr(C)]
pub struct EnrollmentTokenParams {
    pub token_id: *const c_char,
    pub network_id: *const c_char,
    pub subject: *const c_char,
    pub not_before: u64,
    pub expires_at: u64,
    pub nonce: *const u8,
    pub nonce_len: usize,
    pub permissions: *const u8,
    pub permissions_len: usize,
}

// Certificate Information
#[repr(C)]
pub struct CertificateInfo {
    pub cert_der: *mut u8,
    pub cert_len: usize,
    pub subject: *mut c_char,
    pub serial_hex: *mut c_char,
    pub ski_hex: *mut c_char,
}

// Profile Key Encryption Parameters
#[repr(C)]
pub struct ProfileKeyEncryptionParams {
    pub data: *const u8,
    pub data_len: usize,
    pub network_key: *const u8,
    pub network_key_len: usize,
    pub profile_keys: *const u8,
    pub profile_keys_len: usize,
}
```

## Implementation Plan

### Phase 1: Core FFI Infrastructure (CRITICAL)
1. **Update existing FFI** - Fix NodeKeyManager lifecycle and existing functions
2. **Add error codes** - All new error codes for comprehensive error handling
3. **Add data structures** - C-compatible structures for complex data
4. **Memory management** - Proper C-compatible memory management

### Phase 2: Certificate Authority Creation APIs
1. **Root CA creation** - rn_keys_ca_create_root_ca
2. **Issuing CA creation** - rn_keys_ca_create_issuing_ca
3. **CA certificate access** - get_certificate_der, get_certificate_subject
4. **CA resource management** - proper cleanup and memory management

### Phase 3: Enrollment Token Management APIs
1. **Token generation** - rn_keys_enrollment_token_generate
2. **Token validation** - rn_keys_enrollment_token_validate
3. **Token parameters** - proper CBOR serialization for complex parameters
4. **Error handling** - specific error codes for token operations

### Phase 4: Mobile Key Manager Integration APIs
1. **Response conversion** - from_enroll_response, from_renew_response
2. **Mobile key manager** - proper integration with existing mobile APIs
3. **Certificate message handling** - proper CBOR serialization
4. **Error handling** - specific error codes for mobile operations

### Phase 5: Certificate Management APIs
1. **Certificate operations** - get_quic_certificate_config, get_node_certificate
2. **Certificate installation** - install_certificate_from_message
3. **Certificate analysis** - extract_ski, get_serial
4. **Certificate validation** - proper certificate handling

### Phase 6: Profile Key Operations APIs
1. **Profile key encryption** - encrypt_with_envelope
2. **Profile key decryption** - decrypt_with_profile
3. **Compact ID generation** - get_compact_id
4. **Profile key management** - proper integration with existing profile APIs

### Phase 7: CA Node Admin Management APIs
1. **Admin management** - add_admin_ski, revoke_token
2. **CRL generation** - generate_crl_lite
3. **Admin operations** - proper admin functionality
4. **Error handling** - specific error codes for admin operations

### Phase 8: CA Client Configuration APIs
1. **Client configuration** - configure, set_root_ca_cert, set_issuing_ca_cert
2. **Client setup** - set_node_key_manager
3. **Configuration management** - proper configuration handling
4. **Error handling** - specific error codes for client configuration

### Phase 9: Testing and Validation
1. **Unit tests** - Test each new FFI function individually
2. **Integration tests** - Test end-to-end scenarios matching full_transport_e2e_test.rs
3. **Memory tests** - Validate memory management and cleanup
4. **Performance tests** - Ensure efficient FFI design
5. **E2E test implementation** - Complete FFI version of full_transport_e2e_test.rs

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

## Complete E2E Test Coverage

### Full Transport E2E Test Requirements

The updated FFI API design now supports **100% of the functionality** required to implement the complete `full_transport_e2e_test.rs` test using only FFI functions. This includes:

#### Server Role (CA Node Infrastructure)
1. **Root CA Creation** - `rn_keys_ca_create_root_ca`
2. **Issuing CA Creation** - `rn_keys_ca_create_issuing_ca`
3. **CA Node Setup** - `rn_keys_ca_node_new`, `rn_keys_ca_node_install_issuing_ca`
4. **CA Server Configuration** - `rn_transport_ca_server_new`, `rn_transport_ca_server_configure_admin_skis`
5. **CA Server Operations** - `rn_transport_ca_server_start`, `rn_transport_ca_server_stop`
6. **Admin Management** - `rn_keys_ca_node_add_admin_ski`, `rn_keys_ca_node_revoke_token`
7. **CRL Generation** - `rn_keys_ca_node_generate_crl_lite`

#### Client Role (Mobile Node Operations)
1. **Mobile Key Manager** - `rn_keys_init_as_mobile`, `rn_keys_mobile_initialize_user_root_key`
2. **Node Key Manager** - `rn_keys_init_as_node`, `rn_keys_node_generate_keys`
3. **CA Client Configuration** - `rn_transport_ca_client_new`, `rn_transport_ca_client_configure`
4. **Certificate Operations** - `rn_keys_node_generate_csr_v2`, `rn_keys_node_install_certificate_from_message`
5. **Profile Key Operations** - `rn_keys_node_derive_user_profile_key`, `rn_keys_node_encrypt_with_envelope`
6. **Certificate Analysis** - `rn_keys_certificate_extract_ski`, `rn_keys_certificate_get_serial`

#### Cross-Role Operations
1. **Enrollment Token Generation** - `rn_keys_enrollment_token_generate`
2. **Mobile Response Conversion** - `rn_keys_mobile_from_enroll_response`, `rn_keys_mobile_from_renew_response`
3. **CA Client Operations** - `rn_transport_ca_client_enroll`, `rn_transport_ca_client_renew`, `rn_transport_ca_client_revoke`
4. **Certificate Management** - `rn_keys_node_get_quic_certificate_config`, `rn_keys_node_get_node_certificate`

### Test Phases Covered

All 12 phases of the `full_transport_e2e_test.rs` are now supported:

1. **Phase 1: CA Node Infrastructure Setup** ✅
2. **Phase 2: REAL QUIC Transport Setup** ✅
3. **Phase 3: Mobile Node Setup** ✅
4. **Phase 4: Enrollment Token Generation** ✅
5. **Phase 5: Mobile Node Enrollment** ✅
6. **Phase 6: Certificate Renewal** ✅
7. **Phase 7: Certificate Revocation** ✅
8. **Phase 8: CRL-lite Generation and Validation** ✅
9. **Phase 9: CA Node API Status and Chain** ✅
10. **Phase 10: Profile Key Functionality** ✅
11. **Phase 11: Rate Limiting** ✅
12. **Phase 12: Error Handling** ✅

### FFI Design Principles Followed

1. **Synchronous Operations** - All FFI functions are synchronous, following FFI best practices
2. **CBOR Serialization** - Complex parameters use CBOR serialization as specified
3. **Memory Management** - Proper C-compatible memory management with cleanup functions
4. **Error Handling** - Comprehensive error codes and validation
5. **No Builder Patterns** - Simple, single-purpose functions following FFI patterns
6. **Configuration Structs** - C-compatible structures for complex configuration
7. **Resource Management** - Proper resource creation, usage, and cleanup

## Conclusion

This design provides a comprehensive update to the FFI API that:
1. Fixes existing issues with NodeKeyManager lifecycle
2. Exposes all new APIs from the dual-role design
3. Preserves working transporter callbacks
4. Maintains backward compatibility where possible
5. Provides clear migration path for breaking changes
6. Ensures security and proper error handling
7. **Supports 100% of full_transport_e2e_test.rs functionality via FFI**

The implementation should follow the phased approach to minimize risk and ensure each component is properly tested before moving to the next phase.

## Helper Functions, Test Data Creation, Async Handling, Negative and Performance Tests

### 6.1 Test Helper Functions (Rust test harness utilities)
- `fn create_test_logger() -> *mut c_void`
  - Construct `Arc<Logger>` and return opaque pointer.
  - Used by: `rn_keys_ca_node_new`, `rn_transport_ca_server_new`, `rn_transport_ca_client_new`.
- `fn create_test_error() -> RnError`
  - Return zeroed `RnError` struct for FFI calls; pass `&mut err` everywhere.
- `fn create_test_ecdsa_key_pair() -> Vec<u8>`
  - Build P-256 keypair DER; used for Issuing CA and admin tests.
- `fn create_test_certificate() -> Vec<u8>`
  - Return DER certificate bytes (for invalid-cert negative tests).
- `fn create_test_ea_public_keys() -> Vec<u8>`
  - CBOR `Vec<Vec<u8>>` of EA public keys. Input for `rn_keys_ca_node_configure_enrollment_authority` and `rn_keys_ca_node_install_issuing_ca`.
- `fn create_cstring(s: &str) -> CString`
  - Build CStr for addresses, network_id, admin_ski, etc.

### 6.2 Test Data Creation (precise usage)
- `fn create_root_ca_certificate() -> Vec<u8>`
  - DER root CA; pass as `root_ca_der` to `rn_keys_ca_node_install_issuing_ca`.
- `fn create_issuing_ca_certificate() -> (Vec<u8>, Vec<u8>)`
  - `(issuing_key_der, issuing_cert_der)`; pass to `rn_keys_ca_node_install_issuing_ca`.
- `fn create_enrollment_token(network_id: &str, token_id: &str) -> Vec<u8>`
  - CBOR `EnrollmentToken`; embed in `CsrEnrollRequest` passed to `rn_transport_ca_client_enroll`.
- `fn create_test_csr(node_keys: *mut c_void) -> Vec<u8>`
  - Calls `rn_keys_node_generate_csr` and returns the DER.

### 6.3 Async Handling Strategy
- All FFI are synchronous; async work is executed via internal runtimes.
- Tests should call FFI serially. No external runtimes required.
- Server readiness is ensured via `rn_transport_ca_server_get_*_addr`; short sleeps used only in rate-limit loops.

### 6.4 Negative Test Cases (explicit API usage)
- `test_invalid_enrollment_token()`
  - Token: wrong `network_id` or expired.
  - Call `rn_transport_ca_client_enroll(...)` → expect error; read `rn_last_error`.
- `test_unauthorized_renewal()`
  - Fresh node (no prior install), CSR via `rn_keys_node_generate_csr`.
  - Call `rn_transport_ca_client_renew(...)` → expect error.
- `test_rate_limit_exceeded()`
  - 6 enroll calls with same token via `rn_transport_ca_client_enroll` in 1-minute window; last returns error.
- `test_invalid_certificate()`
  - Craft invalid `NodeCertificateMessage` CBOR and call `rn_keys_node_install_certificate` → expect error.

### 6.5 Performance Validation
- Time each FFI network call (enroll/renew/revoke/status/chain/crl) and assert under budget.
- Burst tests: 100 enroll calls with distinct tokens; record p50/p95.
- Memory: after each FFI that returns buffers, free via `rn_free`/`rn_string_free` and check for leaks.
- Resilience: loop start/stop server while making client calls; enforce 45s test timeouts to catch deadlocks.

All above use only the FFI APIs listed in the Authoritative Surface.
