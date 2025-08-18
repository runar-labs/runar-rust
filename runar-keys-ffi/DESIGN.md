## runar-keys FFI: Design and CBOR Contract

This document captures the FFI design for exposing `runar-keys` to Swift (iOS) and Kotlin (Android), with NodeJS later. It focuses on ABI shape, error handling, memory management, and CBOR contracts for complex payloads.

### Goals
- Expose a stable C ABI that wraps `runar-keys` functionality.
- Make it ergonomic to consume from Swift and Kotlin via thin platform wrappers.
- Use CBOR for complex value transport (consistent with our transport layer).
- Avoid common FFI pitfalls: panics across FFI, dangling references, ownership leaks, and ABI-unsafe types.

### Non-goals (for v1)
- No direct trait exposure across FFI.
- No async in the FFI surface (all functions are blocking). Future work may add async adapters.

---

## ABI Strategy

- Opaque handles for stateful objects:
  - `RkMobile` → wraps `MobileKeyManager`
  - `RkNode` → wraps `NodeKeyManager`
  - `RkCert` (optional) → wraps `X509Certificate` if needed

- Error handling:
  - Functions return an `RkErrorCode` (`repr(C)` enum). On success return `RK_OK` (0).
  - When returning data, use out-parameters for buffers and sizes.
  - Provide `rk_last_error_message()` or per-call `rk_error_message(err, buf, len)` to retrieve a human-readable description.

- Memory management:
  - Any allocation returned to the caller is freed by the caller via `rk_buffer_free(void* p, size_t len)` or type-specific `*_free`.
  - No borrowed references cross the boundary. We only copy-out.
  - Wrap every exported function in `catch_unwind` and map panics to `RK_ERR_PANIC`.

- Data transport:
  - Primitives and raw byte buffers are returned directly.
  - Complex structures are serialized as CBOR `Vec<u8>`; the FFI returns those bytes.
  - This avoids exposing `HashMap`, `Vec<Vec<u8>>`, `Option<String>`, etc. over the ABI.

---

## CBOR Contracts (Canonical, Versioned)

Use canonical CBOR encoding. Each top-level map contains `v` (u16) for schema versioning.

### EnvelopeEncryptedData (EED)
- Key: `v: 1`
- `d` (bstr): encrypted data (nonce||ciphertext, AES-GCM-256)
- `n` (tstr|null): network_id
- `nk` (bstr): encrypted envelope key for network (may be empty bstr when absent)
- `pk` (map<tstr,bstr>): profile_encrypted_keys (profile_id → encrypted key)

### SetupToken (ST)
- `v: 1`
- `npk` (bstr): node_public_key (SEC1 uncompressed)
- `napk` (bstr): node_agreement_public_key (SEC1 uncompressed)
- `csr` (bstr): CSR in DER
- `nid` (tstr): node_id (compact ID)

### NodeCertificateMessage (NCM)
- `v: 1`
- `cert` (bstr): node certificate DER
- `ca` (bstr): CA certificate DER
- `meta` (map):
  - `iat` (u64): issued_at (epoch seconds)
  - `days` (u32): validity_days
  - `p` (tstr): purpose

### NetworkKeyMessage (NKM)
- `v: 1`
- `nid` (tstr): network_id
- `npub` (bstr): network public key (SEC1 uncompressed)
- `enc` (bstr): encrypted network scalar (ECIES)
- `info` (tstr): derivation/info string (human-readable)

### Persisted States
- `MobileKeyManagerState` and `NodeKeyManagerState` will be serialized as CBOR blobs using their internal serde impls (with `ciborium`). Consumers treat them as opaque bytes.

Encoding rules:
- Omit fields that are not present (avoid explicit nulls unless needed). For optional string `n`, use absent vs. present.
- Use canonical ordering.

---

## Proposed C API Surface (v1)

Note: names are indicative; header will be generated via cbindgen.

### Common
- `RKAPI RkErrorCode rk_error_message(RkErrorCode code, char* out, size_t out_len);`
- `RKAPI void rk_buffer_free(uint8_t* p, size_t len);`

### Mobile
- `RKAPI RkErrorCode rk_mobile_new(RkMobile** out_mobile);`
- `RKAPI void rk_mobile_free(RkMobile* mobile);`
- Identity:
  - `RKAPI RkErrorCode rk_mobile_initialize_user_root_key(RkMobile*, uint8_t** out, size_t* out_len); // returns user_root_agreement_public`
  - `RKAPI RkErrorCode rk_mobile_get_user_root_public_key(RkMobile*, uint8_t** out, size_t* out_len);`
- Profiles:
  - `RKAPI RkErrorCode rk_mobile_derive_user_profile_key(RkMobile*, const char* label, uint8_t** out, size_t* out_len);`
- Networks:
  - `RKAPI RkErrorCode rk_mobile_install_network_public_key(RkMobile*, const uint8_t* pk, size_t pk_len);`
  - `RKAPI RkErrorCode rk_mobile_generate_network_data_key(RkMobile*, char** out_id, size_t* out_id_len);`
  - `RKAPI RkErrorCode rk_mobile_get_network_public_key(RkMobile*, const char* network_id, uint8_t** out, size_t* out_len);`
- Envelope (CBOR):
  - `RKAPI RkErrorCode rk_mobile_encrypt_with_envelope(RkMobile*, const uint8_t* data, size_t data_len, const char* network_id_or_null, const uint8_t* const* profile_keys, const size_t* profile_lens, size_t profiles_count, uint8_t** out_cbor, size_t* out_cbor_len);`
  - `RKAPI RkErrorCode rk_mobile_decrypt_with_profile(RkMobile*, const uint8_t* eed_cbor, size_t eed_len, const char* profile_id, uint8_t** out, size_t* out_len);`
  - `RKAPI RkErrorCode rk_mobile_decrypt_with_network(RkMobile*, const uint8_t* eed_cbor, size_t eed_len, uint8_t** out, size_t* out_len);`
- CA/Certs (CBOR):
  - `RKAPI RkErrorCode rk_mobile_process_setup_token(RkMobile*, const uint8_t* st_cbor, size_t st_len, uint8_t** out_ncm_cbor, size_t* out_ncm_cbor_len);`
  - `RKAPI RkErrorCode rk_mobile_get_ca_certificate_der(RkMobile*, uint8_t** out, size_t* out_len);`
- State:
  - `RKAPI RkErrorCode rk_mobile_export_state(RkMobile*, uint8_t** out, size_t* out_len);`
  - `RKAPI RkErrorCode rk_mobile_from_state(const uint8_t* state_cbor, size_t len, RkMobile** out_mobile);`

### Node
- `RKAPI RkErrorCode rk_node_new(RkNode** out_node);`
- `RKAPI void rk_node_free(RkNode* node);`
- Identity:
  - `RKAPI RkErrorCode rk_node_get_public_key(RkNode*, uint8_t** out, size_t* out_len);`
  - `RKAPI RkErrorCode rk_node_get_node_id(RkNode*, char** out, size_t* out_len);`
- CSR/Certs (CBOR):
  - `RKAPI RkErrorCode rk_node_generate_csr(RkNode*, uint8_t** out_st_cbor, size_t* out_len);`
  - `RKAPI RkErrorCode rk_node_install_certificate(RkNode*, const uint8_t* ncm_cbor, size_t len);`
  - `RKAPI RkErrorCode rk_node_get_cert_chain_der(RkNode*, uint8_t** out_chain_cbor, size_t* out_len); // array of DER as CBOR array`
  - `RKAPI RkErrorCode rk_node_get_private_key_pkcs8(RkNode*, uint8_t** out, size_t* out_len);`
- Network keys (CBOR):
  - `RKAPI RkErrorCode rk_node_install_network_key(RkNode*, const uint8_t* nkm_cbor, size_t len);`
  - `RKAPI RkErrorCode rk_node_get_network_public_key(RkNode*, const char* network_id, uint8_t** out, size_t* out_len);`
- Envelope (CBOR):
  - `RKAPI RkErrorCode rk_node_encrypt_for_network(RkNode*, const uint8_t* data, size_t data_len, const char* network_id, uint8_t** out_eed_cbor, size_t* out_len);`
  - `RKAPI RkErrorCode rk_node_decrypt_network_data(RkNode*, const uint8_t* eed_cbor, size_t eed_len, uint8_t** out, size_t* out_len);`
- Signing:
  - `RKAPI RkErrorCode rk_node_sign_data(RkNode*, const uint8_t* data, size_t len, uint8_t** out_sig_der, size_t* out_sig_der_len);`
  - `RKAPI RkErrorCode rk_node_verify_peer_signature(RkNode*, const uint8_t* data, size_t data_len, const uint8_t* sig_der, size_t sig_len, const uint8_t* peer_cert_der, size_t cert_len);`
- State:
  - `RKAPI RkErrorCode rk_node_export_state(RkNode*, uint8_t** out, size_t* out_len);`
  - `RKAPI RkErrorCode rk_node_from_state(const uint8_t* state_cbor, size_t len, RkNode** out_node);`

---

## Swift and Kotlin Bindings

Swift:
- Use Swift Package Manager to distribute an `.xcframework` that includes headers generated by cbindgen.
- Map `uint8_t*/len` to `Data`, `char*/len` to `String` via UTF-8.
- Provide thin Swift wrapper classes owning and freeing handles and buffers.

Kotlin/Android:
- Build `.so` per ABI with `cargo-ndk` and package via Gradle.
- Use JNI to call into C API or use JNA if performance is acceptable (JNI preferred).
- Convert `ByteArray` ⇄ `uint8_t*`, `String` ⇄ `char*` (UTF-8).

---

## OpenSSL on Mobile: Risks and Mitigations

Current crate uses `openssl` for CA issuance (SKI/AKI, extensions, signing). On mobile:

- Cross-compilation:
  - iOS: Always use vendored static OpenSSL; system OpenSSL is unavailable. Build slices for arm64 (device) and x86_64/arm64 (simulator) and ship as `.xcframework`.
  - Android: Build per ABI with `cargo-ndk`; statically link vendored OpenSSL.

- Symbol collisions:
  - Apps/libraries may bundle BoringSSL/AWSlc. Statically linking OpenSSL can cause clashes.
  - Mitigations: keep OpenSSL usage limited; consider replacing issuance with a pure-Rust stack if conflicts appear (e.g., `x509-certificate`, `const-oid`, `pkcs8`, `p256`). TLS runtime should continue using rustls.

- Size and licensing:
  - Static OpenSSL increases binary size. Use LTO, strip symbols, and enable minimal features.
  - App Store/export: distribution allowed; ensure export compliance documentation (ECDSA P-256, AES-256-GCM, HKDF-SHA-256).

- FIPS considerations:
  - Standard OpenSSL is not FIPS-certified by default. If FIPS is required, explore platform-specific strategies or AWS-LC FIPS.

Decision for v1: keep OpenSSL for parity; add a `vendored-openssl` feature in this crate that enables `runar-keys/vendored-openssl` to ease mobile builds.

---

## Implementation Plan (next steps)
1. Add CBOR helpers behind `cbor` feature using `ciborium` for:
   - `EnvelopeEncryptedData`, `SetupToken`, `NodeCertificateMessage`, `NetworkKeyMessage`.
2. Implement minimal C ABI slice:
   - `rk_mobile_new/free`, `rk_node_new/free`.
   - `rk_node_get_node_id`, `rk_node_generate_csr` → returns CBOR `SetupToken`.
   - `rk_mobile_process_setup_token` → returns CBOR `NodeCertificateMessage`.
3. Add error mapping (`KeyError` → `RkErrorCode`) and last-error string.
4. Set `crate-type = ["cdylib", "staticlib"]` and integrate `cbindgen` config.
5. CI jobs to build iOS `.xcframework` and Android `.so` per ABI.

---

## Do’s and Don’ts

Do:
- Return owned buffers only; pair with free functions.
- Canonical CBOR, versioned schemas.
- Catch panics at FFI boundary.
- Keep FFI surface minimal and stable; add higher-level wrappers in Swift/Kotlin.

Don’t:
- Expose Rust `Result`, traits, generic containers, `HashMap`, or references across FFI.
- Return pointers into Rust-owned memory.
- Log sensitive materials; add optional callback later if needed.


