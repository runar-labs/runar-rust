# runar_ffi: Unified FFI for Keys + Transporter

This document specifies a single FFI crate and ABI that exposes both key-management (runar-keys) and network transport (runar-transporter) to Swift/Kotlin/NodeJS. The goal is one dylib/so/dll and one header for easier embedding and to ensure the transporter always uses the exact same key manager instance created by the host.

- Crate folder: `runar-ffi`
- Crate name: `runar_ffi`
- Artifact: one shared library (plus static variant), one C header via cbindgen

## Rationale for one crate
- Single allocator/runtime/logging path avoids cross-dylib handle issues
- Mobile packaging is simpler (one `.xcframework` / one Android AAR/JNI library)
- Guarantees the same key manager instance is shared with the transporter (no duplication)

## Architecture
- Opaque handles for stateful objects (repr(C) pointers; contents private to Rust):
  - `FfiKeysHandle`: wraps `Arc<NodeKeyManager>` (and may hold/construct `MobileKeyManager` for issuer flows)
  - `FfiTransportHandle`: wraps `Arc<QuicTransport>`
  - Optional `FfiRuntimeHandle`: if we choose an owned Tokio runtime per-transport or shared

- Event Delivery
  - FFI-safe event queue inside `runar_ffi` for transport/discovery events and inbound requests
  - Two delivery strategies:
    - Polling API (`*_poll_event`) returning CBOR-encoded events
    - Callback registration (`*_set_callback`) using a single-threaded FFI dispatcher thread
  - Deferred request completion: host receives `RequestReceived {request_id,...}` and later calls `complete_request(request_id, ...)`

- Data transport
  - All complex payloads exchanged as CBOR `Vec<u8>` (canonical order, versioned maps)
  - Strings as `char*` UTF-8; binary as `uint8_t* + len`

- Memory & Errors
  - Every return buffer is owned by caller; paired `*_free` functions
  - `ErrorOut { code:int, message:const char* }`, plus `string_free` for message
  - v1 status: last-error ring (`rn_last_error`) and memory helpers implemented; panic guards via `catch_unwind` planned next (map panic to generic error code)

## Key Manager State Persistence (Device-bound, Host-encrypted)

Goal: persist `NodeKeyManager` and `MobileKeyManager` state securely across app restarts without exporting long‑lived secrets or storing large blobs in OS keystores.

- Ownership boundary
  - FFI exports/imports plaintext CBOR state blobs.
  - Host encrypts/decrypts these blobs with a device‑bound, non‑exportable symmetric key from the OS keystore and stores ciphertext in app‑private storage.

- Recommended host strategy
  - iOS/macOS: Create an AES‑256 key in Keychain (`kSecClassKey`, `kSecAttrKeyTypeAES`, `kSecAttrAccessibleWhenUnlocked`), optionally protected by `SecAccessControl` (biometry/passcode). Use CryptoKit/Security for AES‑GCM with random nonce per encryption.
  - Android: Create Android Keystore AES‑GCM key (non‑exportable). Generate a new IV per encryption; store IV+tag with ciphertext. Optionally require user authentication.
  - AEAD format suggestion: `{v:u16, alg:tstr, nonce:bstr, aad:bstr?, ct:bstr}` where `ct` includes the GCM tag. Use AAD to bind to app id/platform/schema version.
  - Rotation: create a new keystore key and re‑encrypt latest state when needed. Losing the key intentionally makes old state irrecoverable.

- Why not store state inside keystore?
  - Keystores are optimized for small keys and access control, not large/variable blobs. Encrypting externally with a keystore‑bound key provides better portability and performance.

- Optional future (not v1)
  - Provide Rust AEAD helpers that still rely on a host‑owned keystore key handle via callbacks. v1 keeps encryption host‑side to avoid cross‑platform keystore abstractions.

## CBOR Schemas (versioned)

Use canonical CBOR; top-level maps carry `v: u16`.

- PeerInfo (Transport)
  - `v:1`, `public_key: bstr`, `addresses: [tstr]`
- NodeInfo (Transport) — reuse existing from `runar-schemas`
- QuicTransportOptionsFFI
  - `v:1`
  - `bind_addr: tstr` ("ip:port")
  - `handshake_timeout_ms: u32`
  - `open_stream_timeout_ms: u32`
  - `response_cache_ttl_ms: u32`
  - `max_request_retries: u32`
  - `max_message_size: u32`
  - Optional: if not using KeysHandle directly, allow inline materials:
    - `cert_chain_der: [bstr]`, `private_key_der: bstr`, `root_certs_der: [bstr]`
  - `log_level: u8` (0=off,1=error,2=warn,3=info,4=debug)

- Transport Events
  - `PeerConnected { v:1, peer_node_id: tstr, node_info: bstr(cbor) }`
  - `PeerDisconnected { v:1, peer_node_id: tstr }`
  - `RequestReceived { v:1, request_id: tstr, path: tstr, correlation_id: tstr, payload: bstr, profile_public_key: bstr, source_peer_id: tstr }`
  - `ResponseReceived { v:1, correlation_id: tstr, payload: bstr, source_peer_id: tstr }`

- Keys Contracts (from existing runar-keys-ffi design)
  - EnvelopeEncryptedData(EED) v1
  - SetupToken(ST) v1
  - NodeCertificateMessage(NCM) v1
  - NetworkKeyMessage(NKM) v1
  - Persisted states for `MobileKeyManager` & `NodeKeyManager` as opaque CBOR blobs

## C API (v1)

Naming: `rn_` prefix (Runar).

### Common / Memory / Errors
- `RNAPI void rn_free(uint8_t* p, size_t len);`
- `RNAPI void rn_string_free(const char* s);`
- `RNAPI int rn_last_error(char* out, size_t out_len); // optional last-error ring`
- `typedef struct { int code; const char* message; } RnError;`

### Keys (subset; extend as needed)
- `RNAPI int rn_keys_new(void** out_keys, RnError* err);`
- `RNAPI void rn_keys_free(void* keys);`
- Identity/CSR/Certs (CBOR):
  - `RNAPI int rn_keys_node_get_public_key(void* keys, uint8_t** out, size_t* out_len, RnError* err);`
  - `RNAPI int rn_keys_node_get_node_id(void* keys, char** out, size_t* out_len, RnError* err);`
  - `RNAPI int rn_keys_node_generate_csr(void* keys, uint8_t** out_st_cbor, size_t* out_len, RnError* err);`
  - `RNAPI int rn_keys_mobile_process_setup_token(void* keys, const uint8_t* st_cbor, size_t st_len, uint8_t** out_ncm_cbor, size_t* out_len, RnError* err);`
  - `RNAPI int rn_keys_node_install_certificate(void* keys, const uint8_t* ncm_cbor, size_t len, RnError* err);`
- Optional encrypt/decrypt helpers via envelope CBOR (EED):
  - `RNAPI int rn_keys_encrypt_with_envelope(void* keys, const uint8_t* data, size_t data_len, const char* network_id_or_null, const uint8_t* const* profile_pks, const size_t* profile_lens, size_t profiles_count, uint8_t** out_eed_cbor, size_t* out_eed_len, RnError* err);`
  - `RNAPI int rn_keys_decrypt_envelope(void* keys, const uint8_t* eed_cbor, size_t eed_len, uint8_t** out_plain, size_t* out_len, RnError* err);`

State export/import (plaintext CBOR; host encrypts+persist):
- `RNAPI int rn_keys_node_export_state(void* keys, uint8_t** out_state_cbor, size_t* out_len, RnError* err);`
- `RNAPI int rn_keys_node_import_state(void* keys, const uint8_t* state_cbor, size_t state_len, RnError* err);`
- `RNAPI int rn_keys_mobile_export_state(void* keys, uint8_t** out_state_cbor, size_t* out_len, RnError* err);`
- `RNAPI int rn_keys_mobile_import_state(void* keys, const uint8_t* state_cbor, size_t state_len, RnError* err);`

### Transport: construction & lifecycle
- `RNAPI int rn_transport_new_with_keys(void* keys, const uint8_t* options_cbor, size_t options_len, void** out_transport, RnError* err);`
- `RNAPI void rn_transport_free(void* transport);`
- `RNAPI int rn_transport_start(void* transport, RnError* err);`
- `RNAPI int rn_transport_stop(void* transport, RnError* err);`
- `RNAPI int rn_transport_local_addr(void* transport, char** out, size_t* out_len, RnError* err);`

### Transport: connectivity and messaging
- `RNAPI int rn_transport_connect_peer(void* transport, const uint8_t* peer_info_cbor, size_t len, RnError* err);`
- `RNAPI int rn_transport_disconnect_peer(void* transport, const char* peer_node_id, RnError* err);`
- `RNAPI int rn_transport_is_connected(void* transport, const char* peer_node_id, bool* out_connected, RnError* err);`
- `RNAPI int rn_transport_request(void* transport, const char* path, const char* correlation_id, const uint8_t* payload, size_t payload_len, const char* dest_peer_id, const uint8_t* profile_pk, size_t pk_len, RnError* err); // completion via event`
- `RNAPI int rn_transport_publish(void* transport, const char* path, const char* correlation_id, const uint8_t* payload, size_t payload_len, const char* dest_peer_id, RnError* err);`
- `RNAPI int rn_transport_complete_request(void* transport, const char* request_id, const uint8_t* response_payload, size_t len, const uint8_t* profile_pk, size_t pk_len, RnError* err);`
- `RNAPI int rn_transport_update_local_node_info(void* transport, const uint8_t* node_info_cbor, size_t len, RnError* err);`

### Events (polling API)
- `typedef struct { uint8_t* ptr; size_t len; } RnBuf;`
- `RNAPI int rn_transport_poll_event(void* transport, RnBuf* out_event, RnError* err); // returns CBOR-encoded event`
- Optionally: `RNAPI int rn_transport_set_callback(void* transport, void(*cb)(void* ctx, const uint8_t* data, size_t len), void* ctx, RnError* err);`

### Logging
- `RNAPI void rn_set_log_level(int level);`
- Optional: `RNAPI void rn_set_log_callback(void(*cb)(void* ctx, int level, const char* msg), void* ctx);`

## Runtime Ownership

Decision (v1): use a single shared runtime inside `runar_ffi` (Option C), exposed as `FfiRuntimeHandle` with lazy-global initialization. This fits mobile (Swift/Kotlin) well and keeps thread usage minimal while ensuring `stop()` drains tasks deterministically.

- Defaults (mobile-friendly)
  - Lazy global runtime created on first use
  - Small worker pool (2–4 threads; configurable)
  - Dedicated callback dispatcher thread (never call back into host on worker threads)
  - Bounded event queues with backpressure
  - `stop()` drains tasks; runtime shuts down when all dependent handles are dropped

- Node/JS path (future)
  - Target Option A (adopt external runtime) for Node backends that already own a Tokio runtime (via napi/neon integration). This will be delivered either as:
    - a Node-specific integration crate that links to `runar_ffi` and adopts an existing runtime, or
    - a build feature that attempts to adopt the current Tokio runtime (`Handle::try_current()`) when present and skips creating the shared runtime.
  - Rationale: backend deployments may require higher concurrency and tighter runtime control.

- Option B (per-instance runtime)
  - Not planned for production; may be enabled only for isolated testing scenarios if needed.

## Implementation Tasks

- Bootstrapping
  - [x] Create `runar-ffi` crate (crate name `runar_ffi`, type `cdylib, staticlib`), wire workspace
  - [x] Add cbindgen config to emit a single header (build.rs emits to OUT_DIR and `include/runar_ffi.h`)
  - [ ] Add panic guard and error mapping utilities (pending)
  - [x] Add memory helpers (`rn_free`, `rn_string_free`) and `rn_last_error`

- Keys bridge
  - [x] Wrap `NodeKeyManager` (+ optional `MobileKeyManager`) into `FfiKeysHandle`
  - [x] Implement: `rn_keys_new/free`, `rn_keys_node_get_public_key`, `rn_keys_node_get_node_id`
  - [x] Implement CSR/cert flow: `rn_keys_node_generate_csr`, `rn_keys_mobile_process_setup_token`, `rn_keys_node_install_certificate`
  - [ ] (Optional) Envelope helpers: encrypt/decrypt via CBOR EED
  - [x] State persistence APIs: `rn_keys_{node,mobile}_{export,import}_state`

- Transport bridge
  - [x] Add `FfiTransportHandle` and constructor `rn_transport_new_with_keys` (consumes `FfiKeysHandle*` and options CBOR)
  - [x] Implement lifecycle: start/stop/local_addr
  - [x] Implement messaging: connect_peer/disconnect/is_connected/request/publish/update_local_node_info
  - [x] Implement deferred request completion map and request-id generation

- Events subsystem
  - [x] Internal bounded channel for events; CBOR encode `PeerConnected/PeerDisconnected/RequestReceived/ResponseReceived`
  - [x] Implement polling API `rn_transport_poll_event`
  - [ ] callback-based delivery with a single dispatcher thread (removed from v1 scope; polling is the standard)

- Discovery
  - [ ] Add `rn_discovery_*` for Rust multicast discovery provider (construction, lifecycle, subscribe via poll)

- Build and CI
  - [ ] Set up `crate-type` for Apple (xcframework slices), Android (per-ABI .so), Node (napi or plain C + node-ffi)
  - [ ] Minimal examples for Swift/Kotlin/Node using the new ABI

- Docs and Samples
  - [ ] Generate a unified C header; provide mapping notes for Swift `Data`/Kotlin `ByteArray`
  - [ ] Version all CBOR schemas; include `v` in every top-level map

- Host persistence (platform work outside Rust FFI)
  - [ ] iOS/macOS: Keystore AES‑GCM device‑bound key; encrypt state CBOR; persist blob; decrypt on restore
  - [ ] Android: Keystore AES‑GCM device‑bound key; encrypt state CBOR; persist blob; decrypt on restore
  - [ ] Node/desktop: Prefer OS keyring/DPAPI/Keychain; otherwise local key in protected storage; encrypt/persist state CBOR

## Notes
- Keep `runar-keys` and `runar-transporter` crates separate internally; `runar_ffi` just binds them
- Prefer polling events for Node; callback path for mobile if needed
- Never expose Rust types or references over the ABI
