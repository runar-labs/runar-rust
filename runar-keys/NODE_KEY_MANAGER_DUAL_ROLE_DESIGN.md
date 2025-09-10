## NodeKeyManager Dual-Role Design (Backend + Frontend/Mobile)

This document specifies Option 2: Keep `MobileKeyManager` strictly as Master/CA and extend `NodeKeyManager` to also serve as the keystore for frontend/mobile peers. All peers (backend and mobile) are full nodes: they must present valid device certificates and perform mutual TLS (mTLS) on every QUIC connection.

This design references only crates and versions already in this repository and uses APIs that are present in the codebase today. No new external crates are introduced.

---

## 🚀 **Core Implementation Principles**

### **Professional Standards & Code Quality**
- **No hacks, no mocks, no workarounds** - Full, professional implementation only
- **State-of-the-art (SOTA) architecture** - Follow industry best practices
- **Zero technical debt** - Clean, maintainable, production-ready code
- **Pass all clippy warnings** - Code must be lint-clean with no `#[allow]` attributes
- **Comprehensive error handling** - Use `Result<>` and `Option<>` properly, no panics

### **Implementation Standards**
- **Clean, organized codebase** - No backward compatibility constraints for new implementation
- **Design-compliant architecture** - Follow the final design specifications exactly
- **Proper refactoring** - Make necessary changes to align with design, not workarounds
- **Single source of truth** - All types defined in runar-keys, no duplicate types
- **Defense in depth** - Multiple validation layers for security

### **Architecture & Design**
- **Proper Rust semantics** - Use `Option<>` for optional values, `Result<>` for errors
- **No backward compatibility breaks** - Clean migration path for all consumers
- **Separation of concerns** - Each component has a single, well-defined responsibility
- **Type safety** - Leverage Rust's type system for compile-time guarantees
- **Performance first** - Prefer references over ownership, avoid unnecessary allocations

### **Implementation Requirements**
- **Full implementation** - No stubs, todos, or placeholder code
- **Comprehensive testing** - All new functionality must be tested
- **Documentation** - All public APIs must be properly documented
- **Error propagation** - Errors must be handled gracefully and propagated appropriately
- **Resource management** - Proper cleanup and resource lifecycle management

### **Code Quality Enforcement**
- **`cargo check` must pass** - No compilation errors
- **`cargo clippy --all-targets --all-features -- -D warnings` must pass** - No clippy warnings
- **`cargo test --all` must pass** - All tests must continue to work
- **`cargo fmt --all`** - Code must be properly formatted
- **No dead code** - Remove unused imports, functions, and variables

---

### Crates and versions in use (checked)
- ECDSA/P-256, PKCS#8, HKDF, AES-GCM, DER/X.509:
  - `p256 = "0.13"` (features: ecdsa, pkcs8, serde, ecdh)
  - `pkcs8 = "0.10"`
  - `hkdf = "0.12"` / `sha2 = "0.10"`
  - `aes-gcm = "0.10"`
  - `x509-parser = "0.16"`
  - `x509-cert = "0.2"`, `spki = "0.7"`, `der = "0.7"`, `rustls-pki-types = "1.x"`
- TLS/QUIC (transporter):
  - `quinn = "0.11"`
  - `rustls = "0.23.28"`
  - `rustls-pki-types = "1.12.0"`

All are already used by the repository. The design stays within these versions and their available APIs.

---

## 1) Goals
- Enforce mTLS across all connections. Every peer presents a device certificate signed by the network CA (or issuing CA) and validates the peer using the same root(s).
- Use `NodeKeyManager` for both roles:
  - Backend nodes (current behavior)
  - Frontend/mobile nodes (new) – including user profile keys for envelope crypto
- Keep `MobileKeyManager` strictly for Master/CA and network-owner operations (issuing node certificates, generating and distributing network data keys). Do not use it as a runtime keystore for transport.

---

## 2) Current capabilities (verified)
- `NodeKeyManager` (file: `runar-keys/src/node.rs`):
  - Has device identity keypair (`EcdsaKeyPair`) and derives a node agreement key (`P256SecretKey`).
  - Generates CSR via `generate_csr()` and installs issued certificates via `install_certificate()`.
  - Provides `get_quic_certificate_config()` returning:
    - `certificate_chain: Vec<rustls_pki_types::CertificateDer<'static>>`
    - `private_key: rustls_pki_types::PrivateKeyDer<'static>`
    - `certificate_validator: CertificateValidator`
  - Envelope crypto for network (agreement) keys and symmetric storage encryption.
  - Tracks profile public keys for encrypting to users but does not store profile agreement secrets for decryption.

- `MobileKeyManager` (file: `runar-keys/src/mobile.rs`):
  - Acts as Master/CA, issues node certificates (`process_setup_token`), manages user-root and derived profile agreement keys, network data keys, and envelope crypto.
  - Not used for transport identities.

- Transporter (file: `runar-transporter/src/transport/quic_transport.rs`):
  - Builds QUIC server/client configs using `quinn` + `rustls`.
  - Client side currently uses `with_no_client_auth()` (must change to present client certs).
  - Server side uses `ServerConfig::with_single_cert(...)` (must change to require client auth).

---

## 3) MobileKeyManager - NO CHANGES NEEDED

The `MobileKeyManager` is already properly designed and follows the correct pattern:
- **`user_root_key: Option<EcdsaKeyPair>`** - Keys are optional
- **`user_root_agreement: Option<P256SecretKey>`** - Keys are optional  
- **`new()` method** - Only initializes structure, no key generation
- **Key generation** - Handled by `initialize_user_root_key()` method

**No changes required** - this is the correct architecture pattern.

## 4) Changes to NodeKeyManager (frontend/mobile support)

Add profile agreement key support (mirroring `MobileKeyManager`), plus a flexible envelope decryption path suitable for mobile/frontend.

### 4.1 Data additions
- Add to `NodeKeyManager` struct:
  - `user_profile_agreements: HashMap<String, p256::SecretKey>`
    - Keyed by profile ID (compact-id of the profile agreement public key)
  - `label_to_pid: HashMap<String, String>`
    - Optional convenience mapping label → profile id, consistent with mobile

Persist these in `NodeKeyManagerState` as PKCS#8 DER (same as existing patterns in both managers).

### 4.2 Derive and store profile agreement keys
- API additions (names chosen to mirror mobile; implementation copies existing logic):
  - `pub fn derive_user_profile_key(&mut self, label: &str) -> Result<Vec<u8>>`
    - Derivation: HKDF-SHA256 over the node master signing key bytes, with the same salt and info as mobile so profile keys are user-root derived only if the node acts as the user device. For a mobile app using `NodeKeyManager`, the node master key is the device’s user master in this role.
    - Use the exact derivation scheme from `MobileKeyManager`:
      - Salt: `b"RunarKeyDerivationSalt/v1"`
      - Info: `"runar-v1:profile:agreement:{label}"` with counter suffix if rejection sampling fails
      - Construct `p256::SecretKey` via `P256SecretKey::from_slice` with rejection sampling
      - Public key bytes: `agreement.public_key().to_encoded_point(false).as_bytes().to_vec()` (uncompressed 65 bytes)
      - PID: `runar_common::compact_ids::compact_id(&public_key_bytes)`
      - Store in `user_profile_agreements` under PID, and `label_to_pid[label] = pid`
    - Return: profile agreement public key bytes (65 bytes)

  - `pub fn decrypt_with_profile(&self, env: &EnvelopeEncryptedData, profile_id: &str) -> Result<Vec<u8>>`
    - Same logic as mobile: locate `env.profile_encrypted_keys[profile_id]`, ECIES decrypt using the corresponding `P256SecretKey`, and AES-GCM decrypt payload.

### 4.3 Envelope decryption precedence
- Update `impl EnvelopeCrypto for NodeKeyManager` `fn decrypt_envelope_data(&self, env: &EnvelopeEncryptedData)` to:
  1) Iterate profile IDs present in `env.profile_encrypted_keys` and attempt `decrypt_with_profile`, returning on first success.
  2) Fallback to network decryption via existing `decrypt_envelope_data` path using network agreement keys.

This mirrors `MobileKeyManager` behavior and enables user-focused decryption on mobile when the `NodeKeyManager` is embedded into the app.

### 4.4 State persistence
- Extend `NodeKeyManagerState` to include:
  - `user_profile_agreements: HashMap<String, Vec<u8>>` (PKCS#8 DER for each profile’s `P256SecretKey`)
  - `label_to_pid: HashMap<String, String>`

- Update `export_state()` and `from_state(...)` accordingly:
  - Export: `sk.to_pkcs8_der()?.as_bytes().to_vec()`
  - Import: `P256SecretKey::from_pkcs8_der(&der)`

All patterns are already present in both managers for other keys and can be reused directly.

---

## 5) Transporter: enforce mTLS

All peers must present a device certificate and validate the peer against trusted CA roots.

### 5.1 Server-side (QUIC server) change
- Current code (example snippet):
  - `let mut server_config = ServerConfig::with_single_cert(certs.clone(), key.clone_key())?;`
  - This does not require client auth.

- Replace with explicit rustls server config requiring client certs, then wrap with Quinn:
  1) Build a `rustls::RootCertStore` containing the network CA(s) you trust for client certificates (same roots you already collect for client validation).
  2) Build a `rustls::server::WebPkiClientVerifier` from that root store:
     - `let client_verifier = rustls::server::WebPkiClientVerifier::builder(root_store).build()?;`
  3) Build a `rustls::ServerConfig` using the builder API:
     - `let rustls_server = rustls::ServerConfig::builder()
         .with_client_cert_verifier(client_verifier)
         .with_single_cert(certs.clone(), key.clone_key())?;`
  4) Convert to Quinn’s rustls crypto config and attach transport config:
     - `use quinn::crypto::rustls::ServerConfig as QuicServerConfig;`
     - `let server_crypto = QuicServerConfig::try_from(rustls_server)?;`
     - `let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));`
     - `server_config.transport_config(transport_config.clone());`

Notes:
- The transporter already builds a `RootCertStore` for client validation; reuse the same pattern for client-verifier roots.
- Keep TLS 1.3 and existing timeout/transport settings unchanged.

### 5.2 Client-side (QUIC client) change
- Current code (example):
  - `let rustls_client_config = RustlsClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();`

- Replace with client-auth config (mirror existing `with_no_client_auth()` call pattern):
  - `let rustls_client = RustlsClientConfig::builder()
         .with_root_certificates(root_store)
         .with_client_auth_cert(certificate_chain, private_key)?;`
  - Convert to Quinn and apply transport config (existing code already does this for the client):
     - `use quinn::crypto::rustls::ClientConfig as QuicClientConfig;`
     - `let mut client_config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_client)?));`
     - `client_config.transport_config(transport_config);`

The certificate chain and private key are obtained from `NodeKeyManager::get_quic_certificate_config()` (already implemented and used elsewhere in the repo).

---

## 6) Certificate Authority topology (network CA Node)

To scale issuance for mobile installs, introduce CA Node(s) that hold an Issuing CA (Intermediate) signed by the Root/Master CA. This avoids relying on the Master mobile app for routine issuance.

### 6.1 Roles
- Root/Master CA (offline/admin): Signs Issuing CA certificates; not used for day-to-day issuance.
- Issuing CA (on CA Node): Signs device CSRs for:
  - Backend nodes (existing flow)
  - Mobile/frontend nodes (new)

### 6.2 Enrollment flow for mobile/frontend nodes
1) App creates `NodeKeyManager` on first run; generates device identity keypair automatically (already done in `NodeKeyManager::new`).
2) App calls `NodeKeyManager::generate_csr()` → produces DER CSR with subject `CN={compact_id(device_public_key)}` (already implemented).
3) App sends CSR to CA Node over HTTPS/QUIC using server-auth only for this endpoint (bootstrap), and includes an enrollment token (time-limited, signed/authorized by network admin/back-end).
4) CA Node validates token and CSR, signs device certificate using the Issuing CA.
5) App receives and installs certificate via `NodeKeyManager::install_certificate(...)` with the CA certificate included (already supported).
6) From then on, transporter uses full mTLS in both directions.

### 6.3 Revocation and rotation
- Prefer short-lived device certificates (e.g., 7–30 days) and mandate periodic re-enrollment.
- Optionally publish CRL/OCSP from CA Node; align transporter policy if/when on-line revocation checking is introduced.

---

## 7) API summary (new/changed)

In `runar-keys/src/node.rs` (`NodeKeyManager`):
- New fields:
  - `user_profile_agreements: HashMap<String, P256SecretKey>`
  - `label_to_pid: HashMap<String, String>`
- Persistence additions:
  - In `NodeKeyManagerState`: `user_profile_agreements: HashMap<String, Vec<u8>>`, `label_to_pid: HashMap<String, String>`
  - Update `export_state()` and `from_state()` accordingly.
- New methods:
  - `pub fn derive_user_profile_key(&mut self, label: &str) -> Result<Vec<u8>>`
    - Derivation identical to `MobileKeyManager` (HKDF with salt `RunarKeyDerivationSalt/v1` and info `runar-v1:profile:agreement:{label}`; rejection sampling for P-256 scalar)
  - `pub fn decrypt_with_profile(&self, env: &EnvelopeEncryptedData, profile_id: &str) -> Result<Vec<u8>>`
    - ECIES unwrap + AES-GCM decryption
- Change `impl EnvelopeCrypto for NodeKeyManager`:
  - `fn decrypt_envelope_data(&self, env: &EnvelopeEncryptedData) -> Result<Vec<u8>>` to attempt profile-based decryption first, then network.

In `runar-transporter/src/transport/quic_transport.rs`:
- Client: replace `.with_no_client_auth()` with `.with_client_auth_cert(certificate_chain, private_key)` using values from `get_quic_certificate_config()`.
- Server: construct a `rustls::ServerConfig` that requires client auth (RootCertStore from CA(s)), then pass it to Quinn via `ServerConfig::with_crypto(...)`.

All used types (`CertificateDer`, `PrivateKeyDer`, `RootCertStore`, Quinn/Rustls builder patterns) are already present and used in the repository at the versions listed above.

---

## 8) Security & operational notes
- Separation of concerns maintained: `MobileKeyManager` stays Master/CA; runtime keystore is `NodeKeyManager` for all peers.
- No generic/shared device certificates; each device has its own identity and certificate.
- Enrollment token verification on CA Node is mandatory.
- Prefer short-lived certs and periodic rotation.
- Harden CA Nodes (HSM/TEE recommended), audit issuance, and support key rollover.

---

## 9) Migration plan
1) Implement NodeKeyManager profile agreement storage and decryption (Section 3).
2) Switch transporter to mTLS on both client and server (Section 4).
3) Introduce CA Node issuance endpoints and admin token flow (Section 5).
4) Update tests:
   - Add mobile/frontend tests that use `NodeKeyManager` to derive a profile key, enroll for a device cert via a mocked CA Node, and connect to a test backend with full mTLS.
5) Keep existing end-to-end tests green (node setup flows remain unchanged).


---

## 10) Initialization & Node ID lifecycle (unified, no eager key generation)

Align `NodeKeyManager` lifecycle with `MobileKeyManager`: do not generate keys in `new()`. Generate keys on demand and store/read `node_id` separately to fix the state loading dependency cycle.

### 10.1 Struct field changes (optional keys during init)
- Change selected fields to optional until generated/loaded:
  - `node_key_pair: Option<EcdsaKeyPair>` (was required)
  - `node_agreement_secret: Option<P256SecretKey>` (derived from master; optional until keys exist)
  - `storage_key: Option<Vec<u8>>` (HKDF-derived from master; optional until keys exist)
  - Existing optional fields stay unchanged: `node_certificate: Option<X509Certificate>`, `ca_certificate: Option<X509Certificate>`, `certificate_validator: Option<CertificateValidator>`

### 10.2 Public API additions/changes
- `pub fn new(logger: Arc<Logger>) -> Result<Self>`
  - Initialize struct ONLY; do not generate keys.
  - Leave the above fields as `None`.

- `pub fn generate_keys(&mut self) -> Result<()>`
  - Move current key generation from `new()` here:
    - Create `EcdsaKeyPair::new()` and assign to `node_key_pair`.
    - Derive `storage_key` via HKDF-SHA-256 using the node master signing key bytes (same salt/info currently used):
      - Salt: `b"RunarKeyDerivationSalt/v1"`
      - Info: `b"runar-v1:node-identity:storage"`
    - Derive `node_agreement_secret` via `derivation::derive_agreement_from_master(&signing_key, b"runar-v1:node-identity:agreement")`.
    - After generating keys, update the logger node id: `logger.set_node_id(compact_id(public_key_bytes))`.

- `pub fn get_node_id(&self) -> Option<String>`
  - Return `None` if keys are not available yet.

- `pub fn get_node_public_key(&self) -> Option<Vec<u8>>`
  - Return `None` if keys are not available yet.

- `pub fn get_storage_key(&self) -> Option<&[u8]>`
  - Return `None` if not derived yet.

Note: Callers that need a node identity must either load state first or call `generate_keys()` when state is absent.

### 10.3 Separate node_id persistence to break load cycle
- Problem today: `probe_and_load_state()` needs `node_id` to locate the persisted file (via `Role::Node { node_id }`), but `node_id` depends on loaded keys.
- Solution: persist `node_id` in a separate, unencrypted file under the same base directory used by `PersistenceConfig`.

- Add helpers inside `NodeKeyManager`:
  - `fn load_node_id_from_file(&self, cfg: &PersistenceConfig) -> Option<String>`
    - Path: `cfg.base_dir.join("node_id.txt")`
    - If present, read to string and return `Some(id)`, else `None`.
  - `fn save_node_id_to_file(&self, cfg: &PersistenceConfig, node_id: &str) -> Result<()>`
    - Ensure parent dir, write `node_id` to `node_id.txt`.

- Update `probe_and_load_state()` flow:
  1) If `(device_keystore, persistence)` not configured, return `Ok(false)` as today.
  2) Read `node_id` using `load_node_id_from_file(&cfg)`.
     - If `None`, return `Ok(false)` (no state on disk).
  3) Call `load_state(&keystore, &cfg, &Role::Node { node_id: &node_id })`.
  4) If bytes present, deserialize `NodeKeyManagerState` and reconstruct `Self` (as current `from_state` does), including re-deriving `node_agreement_secret` from the master key.
  5) Update logger node id.
  6) Return `Ok(true)` on success.

- Update `flush_state()`:
  - After serializing state and writing via `save_state(..., &Role::Node { node_id: &node_id }, ...)`, also call `save_node_id_to_file(&cfg, &node_id)`.

- Update persistence wipe (`wipe_persistence()`):
  - In addition to existing wipe for `Role::Node { node_id }`, delete `node_id.txt` if present.

### 10.4 Impacted call sites (high-level)
- FFI and test utilities must follow the lifecycle:
  1) Construct `NodeKeyManager::new(logger)`
  2) `probe_and_load_state()` → if `true`, keys are loaded; if `false`, call `generate_keys()`
  3) After keys exist, set logger node id (handled in `generate_keys()` and after successful load)
- All places directly assuming `get_node_id()` returns `String` must switch to handling `Option<String>`.

### 10.5 Rationale
- Matches `MobileKeyManager` pattern (no eager key generation).
- Fixes the chicken-and-egg dependency for state loading.
- Improves FFI and test predictability and aligns the two managers’ lifecycles.

---

## 11) Breaking changes and migration

### 11.1 API changes
- `NodeKeyManager::new()` no longer generates keys.
- `get_node_id() -> Option<String>`
- `get_node_public_key() -> Option<Vec<u8>>`
- `get_storage_key() -> Option<&[u8]>`

### 11.2 Required updates
- Test utilities and tests that construct `NodeKeyManager` must call `generate_keys()` when `probe_and_load_state()` returns `false`.
- FFI layer must be updated to reflect the new lifecycle and to set logger node id after keys are available.
- Persistence layer: ensure `node_id.txt` handling is implemented alongside existing state I/O.

These items complement the dual-role/profile changes and transporter mTLS enforcement in earlier sections, producing a coherent, end-to-end design.

---

## 12) Comprehensive Impact Analysis

### 12.1 Files That Need Changes

#### **runar-keys/src/node.rs**
- Change `node_key_pair: EcdsaKeyPair` to `node_key_pair: Option<EcdsaKeyPair>`
- Move key generation logic from `new()` to `generate_keys()`
- Update all methods that assume keys exist
- Add `load_node_id_from_file()` and `save_node_id_to_file()` methods
- Update `probe_and_load_state()` to load node_id from separate file
- Update `flush_state()` to save node_id to separate file
- Update `wipe()` to delete node_id file
- Add profile agreement key support (Section 4)

#### **runar-keys/src/mobile.rs**
- **NO CHANGES NEEDED** - Already follows correct pattern

#### **runar-ffi/src/lib.rs**
- Update `rn_keys_init_as_node()` to not generate keys
- Update `rn_keys_node_get_keystore_state()` to call `generate_keys()` when needed
- Fix logger update logic to work with new lifecycle

#### **runar-nodejs-api/src/lib.rs**
- Update to handle optional keys
- Fix field access patterns

#### **runar-test-utils/src/lib.rs** - **CRITICAL IMPACT**
- **`create_test_node_keys()`** - Must call `generate_keys()` after `NodeKeyManager::new()`
- **`create_node_test_config()`** - Must call `generate_keys()` after `NodeKeyManager::new()`
- **`create_networked_node_test_config()`** - Must call `generate_keys()` after `NodeKeyManager::new()`
- **`MobileSimulator::create_node_config()`** - Must call `generate_keys()` after `NodeKeyManager::new()`

#### **All Test Files - COMPREHENSIVE IMPACT**
- **runar-keys/tests/end_to_end_test.rs** - 4 instances of `NodeKeyManager::new()`
- **runar-keys/tests/certs_integration_test.rs** - 6 instances of `NodeKeyManager::new()`
- **runar-serializer/tests/encryption_test.rs** - 1 instance of `NodeKeyManager::new()`
- **runar-serializer/tests/container_negative_test.rs** - 1 instance of `NodeKeyManager::new()`
- **runar-cli/tests/e2e_init_test.rs** - 1 instance of `NodeKeyManager::new()`
- **runar-cli/tests/simple_init_test.rs** - 1 instance of `NodeKeyManager::new()`
- **runar-cli/src/init.rs** - 1 instance of `NodeKeyManager::new()`
- **runar-node-tests/src/network/quic_transport_test.rs** - 13 instances of `NodeKeyManager::new()`

#### **runar-transporter/src/transport/quic_transport.rs**
- Update to enforce mTLS on both client and server (Section 5)

#### **Total Impact: 28+ files need updates**

### 12.2 Breaking Changes

1. **`NodeKeyManager::new()`** - No longer generates keys
2. **`get_node_id()`** - Now returns `Option<String>` instead of `String`
3. **`get_node_public_key()`** - Now returns `Option<Vec<u8>>` instead of `Vec<u8>`
4. **`get_storage_key()`** - Now returns `Option<&[u8]>` instead of `&[u8]`
5. **All test utilities** - Must call `generate_keys()` after `NodeKeyManager::new()`
6. **All test files** - Must follow proper data flow pattern
7. **`probe_and_load_state()`** - Must be updated to handle `Option<String>` from `get_node_id()`

### 12.3 NO Backward Compatibility
- **All impacted code must be updated** to use the proper data flow
- **No migration path** - clean break with old pattern
- **Test utilities must be updated** - this will fix most tests automatically

---

## 13) Implementation Plan

### Phase 1: Core NodeKeyManager Changes
1. Update `NodeKeyManager` structure and `new()` method
2. Add `generate_keys()` method
3. Update `probe_and_load_state()` logic
4. Update all methods that assume keys exist
5. Add `load_node_id_from_file()` and `save_node_id_to_file()` methods

### Phase 2: Test Utilities Updates - **CRITICAL FIRST**
1. Update `runar-test-utils/src/lib.rs` - **This will fix most tests automatically**
2. Update all test utility functions to call `generate_keys()`
3. Test the updated utilities

### Phase 3: Profile Agreement Key Support
1. Add profile agreement key fields to `NodeKeyManager`
2. Implement `derive_user_profile_key()` method
3. Implement `decrypt_with_profile()` method
4. Update envelope decryption precedence
5. Update state persistence for profile keys

### Phase 4: Transporter mTLS Enforcement
1. Update server-side to require client certificates
2. Update client-side to present client certificates
3. Test mTLS enforcement

### Phase 5: FFI Layer Updates
1. Update `rn_keys_init_as_node()` to not generate keys
2. Update `rn_keys_node_get_keystore_state()` to handle key generation
3. Fix logger update logic

### Phase 6: API Layer Updates
1. Update NodeJS API to handle optional keys
2. Update remaining test files that don't use test utilities
3. Update documentation

### Phase 7: Testing & Validation
1. Run all tests to ensure compatibility
2. Test key generation scenarios
3. Test state loading scenarios
4. Validate logger consistency
5. Test profile key functionality
6. Test mTLS enforcement

---

## 14) CA Node Infrastructure – Detailed Design (QUIC-only)

This section specifies a complete, QUIC-based CA Node infrastructure, including enrollment APIs, token system, issuing CA management, revocation, lifecycle, and operations. All interactions use QUIC via our existing transporter (quinn + rustls), building on our request/response patterns and CBOR serialization.

### 14.1 Transport and endpoints
- Transport: QUIC using `quinn = "0.11"` and `rustls = "0.23.28"` (already in repo). TLS 1.3 only.
- Two separate QUIC servers required:
  - Bootstrap server (server-auth only): clients do not yet have device certs. Authorize via Enrollment Tokens + rate limits.
  - Authenticated server (full mTLS): all other CA operations require client certs.
- QUIC settings: reuse transporter's `TransportConfig` (idle timeout, keep-alive). No new knobs required.

Binary Protocol over QUIC:
- Message Header (8 bytes): `[Message Type (u32)] + [Payload Length (u32)]`
- Message Structure: `[Header(8 bytes)] + [CBOR Payload]`
- All requests include `network_id` field in CBOR payload

Endpoints (binary protocol over QUIC):
- Bootstrap server (server-auth only):
  - `CsrEnrollRequest` (0x0001) → `CsrEnrollResponse` (0x1001)
  - `ChainRequest` (0x0002) → `ChainResponse` (0x1002)
- Authenticated server (mTLS required):
  - `RenewRequest` (0x0003) → `RenewResponse` (0x1003)
  - `RevokeRequest` (0x0004) → `RevokeResponse` (0x1004)
  - `CrlRequest` (0x0005) → `CrlResponse` (0x1005)
  - `StatusRequest` (0x0006) → `StatusResponse` (0x1006)

Error handling (CBOR):
```rust
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ErrorResponse {
    pub code: String,  // e.g., "invalid_token", "csr_invalid", "rate_limited"
    pub message: String,
    pub reason: Option<String>, // e.g., "csr_cn_mismatch", "replay_detected", "admin_not_authorized"
}
```

**Error codes and messages:**
- `unauthorized` (401): Missing/invalid mTLS for endpoints that require it (renew, revoke, crl/status if restricted).
- `forbidden` (403): Token invalid, token revoked, replay detected, admin SKI not allowed.
- `bad_request` (400): CSR CN mismatch, malformed CSR, algorithm mismatch, network_id mismatch.
- `conflict` (409): Duplicate enrollment for same device within a restricted window (if you enforce uniqueness).
- `rate_limited` (429): Exceeded rate limit for remote address or token.
- `internal` (500): Unexpected errors.

**Specific error reasons:**
- For CSR CN continuity failures: return `bad_request` with reason `"csr_cn_mismatch"`.
- For token replay: return `forbidden` with reason `"replay_detected"`.
- For admin SKI not permitted (admin endpoints only): `forbidden` with `"admin_not_authorized"`.

**Where to return these:**
- Server prechecks return wire-level `CaError` immediately.
- CANode returns internal errors mapped by the server to `CaError`.

Rate limiting (bootstrap server):
- Sliding-window counters keyed by (remote_addr, token_id) with burst/sustained limits (e.g., 5/min, 30/hour). Implement with in-memory maps and timestamps; no new crates.

HA and discovery:
- Multiple CA Nodes per network are supported. Each CA Node publishes presence at `$registry/ca/{network_id}/announces` with bind addresses and capabilities. Clients pick any announced node.

CA Node server authentication (bootstrap) – top options:
1) Issuing CA TLS server cert (recommended)
   - Pros: Single trust root (Root/Issuing). Clients embed Root/Issuing CA to authenticate CA Nodes immediately.
   - Cons: App must embed Root (or Issuing) CA; update on CA rotation.
2) Public Web PKI cert for bootstrap bind
   - Pros: No embedded root needed for bootstrap.
   - Cons: Two trust roots; operational overhead; not aligned with closed-network model.

Recommendation: option 1.

### 14.2 Enrollment token system (no new crates)

Token body (CBOR):
```rust
#[derive(serde::Serialize, serde::Deserialize)]
pub struct EnrollmentTokenBody {
    pub token_id: String,         // 16 random bytes hex
    pub network_id: String,       // compact_id of owner network
    pub subject_hint: Option<String>,
    pub not_before: u64,          // UNIX seconds
    pub expires_at: u64,          // UNIX seconds
    pub nonce: [u8; 16],          // anti-replay
    pub permissions: Vec<String>, // ["enroll"], future: ["renew"]
}
```

Signed envelope:
```rust
#[derive(serde::Serialize, serde::Deserialize)]
pub struct EnrollmentToken {
    pub body: EnrollmentTokenBody,
    pub signature: Vec<u8>,   // ECDSA P-256 DER
    pub signer_id: String,    // compact_id of EA public key
}
```

Signing/verification:
- Use existing P-256 ECDSA (`p256`) and our `EcdsaKeyPair` style. Serialize `body` with CBOR (serde_cbor), sign bytes to DER.
- CA Node verifies with pre-configured Enrollment Authority (EA) public keys by `signer_id`.

Issuer key options:
1) Dedicated Enrollment Authority key (recommended)
   - Pros: separation of duties; compromise doesn't expose Issuing CA.
   - Cons: manage one more key.
2) Reuse Issuing CA key for tokens
   - Pros: fewer keys.
   - Cons: mixes roles; larger blast radius.

Distribution and generation:
- Admin tool (out-of-band) builds `EnrollmentTokenBody`, signs with EA key, delivers `EnrollmentToken` to user (QR/deeplink/backend). No new crates.

Validation steps on CA Node:
1) Verify DER signature over CBOR(body) using EA pubkey.
2) Check `network_id` matches configured network.
3) Enforce `not_before <= now <= expires_at`.
4) Rate-limit by (remote_addr, token_id) and (remote_addr, subject_hint).
5) **CRITICAL**: Anti-replay cache - detect and drop repeated use of the same enrollment token/nonce pair within a TTL. Implement primary anti-replay at the server layer for performance (early drop before CA processing), backed by an in-memory TTL cache keyed by `(token_id, nonce)`. Use a periodic cleanup task.

Token revocation:
- Maintain in-memory denylist of `token_id` with TTL. Admin can push signed revocation messages over mTLS to invalidate early.

### 14.3 Device-based Renewal Authorization (CRITICAL)

**Required behavior:**
- Renewals are initiated by the device over an mTLS-authenticated connection.
- Authorize by continuity: CSR CN must equal `compact_id(peer_device_public_key)` extracted from the mTLS peer leaf certificate.

**Exact approach:**
- The server MUST extract the peer leaf certificate from the TLS session and pass it to `CANode::handle_renew` as part of a structured context. Do not trust any application-layer peer_id string.
- Inside `CANode::handle_renew`, recompute `compact_id` from the provided peer certificate's subject public key info (SPKI) and compare to the CSR's CN. Reject on mismatch.

**Implementation details:**
- Extract the compact_id from the peer certificate's public key inside CANode. The server should pass the verified peer leaf certificate DER (or the full chain) to CANode. Do not pass a bare "peer compact_id" string from the server to CANode as the sole proof. This avoids TOCTOU and parameter spoofing and centralizes policy in CANode.
- Additionally, the server MAY perform a lightweight precheck (compute compact_id from peer cert and compare to CSR CN) to fail fast before calling CANode. But CANode must enforce it authoritatively.

**Inputs to CANode for renew:**
```rust
pub struct RenewRequestContext {
    pub peer_leaf_cert_der: Vec<u8>,
    pub csr_der: Vec<u8>,
    pub network_id: String,
    // ... other fields
}
```

**In CANode, parse peer cert, extract P-256 public key, compute `compact_id`, compare to CSR CN (already parsed while validating CSR). Reject with a specific error when mismatch.**

### 14.4 CRL-lite Signing (CRITICAL)

**Required behavior:**
- Sign the CBOR serialization of the revocation list body (with the `signature` field excluded) using the Issuing CA's P-256 key with SHA-256.
- Include raw DER-encoded ECDSA signature bytes in the `signature` field.

**Implementation details:**
- Use the raw DER bytes of the ECDSA signature (ASN.1 DER of (r,s)). Do not hex-encode. We're already using a binary protocol with CBOR framing; keep the signature as a `Vec<u8>`.
- Include `sig_alg` metadata (e.g., `p256-sha256-der`) and the signer's SKI (`signer_ski`) in the structure for deterministic verification.

**Verification:**
- Clients/peers verify by:
  - Validating the Issuing CA chain against embedded Root.
  - Checking that `signer_ski` matches the Issuing CA cert SKI.
  - Reserializing the CRL-lite body without the signature, verifying the DER signature with the Issuing CA public key.

### 14.5 Rate Limiting using Remote Address (IMPORTANT)

**Required behavior:**
- Rate limiting must be keyed by the actual remote address, not a placeholder.

**Implementation details:**
- Capture the remote address at the connection level and thread it into each handler call as part of a `RequestContext` (e.g., `{ remote_addr: SocketAddr, peer_leaf_cert_der: Option<Vec<u8>>, … }`). This is the cleanest boundary and avoids per-stream confusion.
- Rate-limit by `(remote_ip, endpoint_kind)`; additionally, for enrollment, include `(token_id)` to block replay bursts by the same token across streams/sessions. Use a token bucket or sliding window with configurable limits.

**Placement:**
- Implement rate limiting in the server layer (transport). It prevents CPU-heavy CA work from being reached, reducing DoS surface.

### 14.6 Type Alignment for Binary Protocol (IMPORTANT)

**Required behavior:**
- Wire protocol types are transport-facing and must include `network_id`, versioning, and message discriminants.
- Internal CA types remain decoupled and are used by CANode.

**Implementation details:**
- Use `runar-keys::ca_node_types` as the single source of truth for all CA operations.
- No wire types needed - client and server are both pure Rust in same codebase.
- Add `network_id` and `version` fields to existing types in `runar-keys::ca_node_types`.
- Remove duplicate type definitions - use only the types defined in `runar-keys`.

**Serialization:**
- Keep CBOR (`ciborium`) as specified in the design (binary protocol). Avoid ad-hoc binary framing; CBOR is already standard in the repo.

### 14.7 Server Certificate Chains (NICE TO HAVE, recommended)

**Required behavior:**
- Always present the full chain `[leaf, issuing_ca]` for better interop and path building—even though clients embed Root.

**Implementation details:**
- Yes: modify both the bootstrap server and the authenticated server to present the full chain by using the rustls API that accepts a chain (`with_single_cert(chain, key)` where `chain` includes leaf then issuing).
- This improves clients that don't preload intermediates and avoids extra fetch logic.

### 14.8 API specifications (Binary Protocol over QUIC)

Message Types:
```rust
enum CaMessageType {
    // Bootstrap requests
    CsrEnrollRequest = 0x0001,
    ChainRequest = 0x0002,
    
    // Bootstrap responses  
    CsrEnrollResponse = 0x1001,
    ChainResponse = 0x1002,
    
    // Authenticated requests
    RenewRequest = 0x0003,
    RevokeRequest = 0x0004,
    CrlRequest = 0x0005,
    StatusRequest = 0x0006,
    
    // Authenticated responses
    RenewResponse = 0x1003,
    RevokeResponse = 0x1004,
    CrlResponse = 0x1005,
    StatusResponse = 0x1006,
    
    // Error response
    ErrorResponse = 0x2000,
}
```

Request/Response Types (all include network_id):
```rust
// Bootstrap requests
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CsrEnrollRequest {
    pub network_id: String,
    pub csr_der: Vec<u8>,
    pub enrollment_token: EnrollmentToken,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ChainRequest {
    pub network_id: String,
}

// Bootstrap responses
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CsrEnrollResponse {
    pub certificate_der: Vec<u8>,
    pub issuing_ca_der: Vec<u8>,
    pub root_ca_der: Option<Vec<u8>>,
    pub expires_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ChainResponse {
    pub issuing_ca_der: Vec<u8>,
    pub root_ca_der: Option<Vec<u8>>,
}

// Authenticated requests
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RenewRequest {
    pub network_id: String,
    pub csr_der: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct RevokeRequest {
    pub network_id: String,
    pub certificate_serial: Vec<u8>,
    pub reason: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct CrlRequest {
    pub network_id: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct StatusRequest {
    pub network_id: String,
}

// Authenticated responses
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RenewResponse {
    pub certificate_der: Vec<u8>,
    pub issuing_ca_der: Vec<u8>,
    pub expires_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct RevokeResponse {
    pub ok: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct CrlResponse {
    pub issuing_ca_serial_hex: String,
    pub generated_at: u64,
    pub revoked_serials: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct StatusResponse {
    pub issuing_subject: String,
    pub issuing_serial_hex: String,
    pub not_before: u64,
    pub not_after: u64,
}
```

Protocol Flow:
- Bootstrap server (server-auth only):
  - `CsrEnrollRequest` (0x0001) → `CsrEnrollResponse` (0x1001)
  - `ChainRequest` (0x0002) → `ChainResponse` (0x1002)
- Authenticated server (mTLS required):
  - `RenewRequest` (0x0003) → `RenewResponse` (0x1003)
  - `RevokeRequest` (0x0004) → `RevokeResponse` (0x1004)
  - `CrlRequest` (0x0005) → `CrlResponse` (0x1005)
  - `StatusRequest` (0x0006) → `StatusResponse` (0x1006)

Validation:
- Bootstrap endpoints: network_id validation + enrollment token verification + rate limiting
- Authenticated endpoints: network_id validation + mTLS client cert validation + SKI allowlist for admin operations

### 14.4 Issuing CA certificate management

Creation/import:
- Use existing `CertificateAuthority`:
  - `CertificateAuthority::from_existing(ca_key_pair, ca_certificate)` to load an Issuing CA signed by Root.
  - Or `CertificateAuthority::new(...)` to generate keys, then sign the CSR offline with Root before use.

Storage/protection:
- Persist Issuing CA key/cert using existing keystore/persistence (same as key managers). If platform HSM/TEE later, delegate signing (future work, no new crates now).

Chain distribution/validation:
- Provide via `ChainRequest` (0x0002) → `ChainResponse` (0x1002). Clients install chain in `NodeKeyManager::install_certificate(...)` which already validates signatures.

Multiple Issuing CAs:
- Support publishing multiple chains; clients trust any rooted at configured Root(s).

Issuing CA renewal:
- Prepare new Issuing CA; publish both chains during overlap; retire old after migration.

### 14.5 Revocation model (pragmatic)

Approach:
1) Short-lived device certs (7–30 days)
2) CRL-lite over QUIC (CBOR), signed by Issuing CA or dedicated revocation key

CRL-lite structure:
```rust
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CrlResponse {
    pub issuing_ca_serial_hex: String,
    pub generated_at: u64,
    pub revoked_serials: Vec<Vec<u8>>, // big-endian
    pub signature: Vec<u8>,            // ECDSA P-256 DER (raw DER bytes)
    pub signer_ski: Vec<u8>,          // Subject Key Identifier of signer
    pub sig_alg: String,              // e.g., "p256-sha256-der"
}
```
- Endpoint: `CrlRequest` (0x0005) → `CrlResponse` (0x1005) (mTLS)
- Clients fetch on startup and then periodically (e.g., 10 min). Cache in memory and persist if desired.
- Transporter enforcement: after QUIC handshake, before finalizing peer connection, compare presented peer cert serial to cached denylist; drop connection if revoked. Use `NodeKeyManager::get_certificate_info()` to read peer subject/serial and a small adapter in transporter to consult the cache.

OCSP option (not chosen now): requires additional responder logic and likely new crates; defer to future.

### 14.6 Certificate lifecycle management

Monitoring:
- CA Node tracks expirations for issued certs; emits `$ca/{network_id}/events/expiring` for thresholds (14d/7d/3d).
- Nodes also check via `get_certificate_status()` and log warnings at thresholds.

Automatic renewal:
- Nodes initiate renewal within 7 days of expiry via `RenewRequest` (0x0003) → `RenewResponse` (0x1003) (mTLS). Policy may require key rotation.

### 14.7 Network integration and discovery

- CA Nodes publish `$registry/ca/{network_id}/announces` with:
  - bootstrap_bind, authenticated_bind, issuing_subject, issuing_serial_hex, features: [enroll, renew, revoke, crl].
- Clients subscribe or query to select a CA Node.
- Multi-network: one process can serve multiple networks; network_id is validated per request.

### 14.8 Security and operations

HSM/TEE options:
1) Software-only (current baseline)
   - Pros: simplest; no new deps.
   - Cons: higher exposure.
2) External HSM/TEE (future)
   - Pros: protects CA private key.
   - Cons: integration work; hardware costs.

Audit logging:
- INFO on success (enroll/renew/revoke): node_id, serial, token_id hash, network_id.
- WARN/ERROR on invalid token/CSR, rate-limit, signature failures.

Key rollover:
- Rotate EA and Issuing CA periodically (6–12 months) or on compromise. Advertise next issuer during overlap.

Monitoring & health:
- `StatusRequest` (0x0006) → `StatusResponse` (0x1006) returns uptime, counters, last CRL generation.

Backup & recovery:
- Back up Issuing CA persisted state offline. Recovery verifies subject/serial consistency before serving.

### 14.9 Dataflows (end-to-end)

1) Bootstrap enrollment (server-auth only)
   - Client: `NodeKeyManager::generate_csr()` + receive `EnrollmentToken` out-of-band.
   - Send `CsrEnrollRequest` (0x0001) → receive `CsrEnrollResponse` (0x1001).
   - Install via `NodeKeyManager::install_certificate(...)`. From now on, full mTLS.

2) Renewal (mTLS)
   - Client: send `RenewRequest` (0x0003) within renewal window.
   - CA Node: validate mTLS identity vs CSR CN; return `RenewResponse` (0x1003).

3) Revocation (mTLS)
   - Admin: send `RevokeRequest` (0x0004) (authorized cert).
   - CA Node: update CRL-lite and publish; clients fetch and transporter enforces denylist.

4) Chain fetch (server-auth only)
   - Client: `ChainRequest` (0x0002) → `ChainResponse` (0x1002) to bootstrap trust.

All structures and cryptographic operations use existing crates in the repo; no new dependencies are introduced.

---

## 15) End-to-End Test Specification – Mobile Enrollment via CA Node (QUIC)

Purpose: validate the full QUIC-based CA infrastructure by enrolling a brand-new mobile app (using `NodeKeyManager` in frontend role), issuing its device certificate via a CA Node, and then participating with mTLS. This extends the existing `end_to_end_test.rs` scenario.

### 15.1 Preconditions (reusing existing e2e steps)
- Master mobile (owner):
  - `MobileKeyManager::new(logger)`
  - `initialize_user_root_key()`
  - `generate_network_data_key()` → `network_public_key`, `network_id = compact_id(network_public_key)`
- Backend nodes (at least one):
  - `NodeKeyManager::new(logger)` → `generate_keys()`
  - CSR issuance via Master mobile:
    - Node: `generate_csr()`
    - Mobile: `process_setup_token(...)` → `NodeCertificateMessage`
    - Node: `install_certificate(NodeCertificateMessage)`
- Result: backend nodes are mTLS-capable; Master mobile owns network and CA from earlier steps (as per current e2e).

### 15.2 Phase 1 – Elect CA Node and install Issuing CA
- Elect one enrolled backend node to act as CA Node.
- Two supported options for issuance authority:
  - Option A (recommended): Issuing CA (intermediate) signed by Root/Master CA
    - Create Issuing CA keypair and CA certificate (CA=true, path_len=0, KeyUsage keyCertSign+cRLSign). Root signs the Issuing CA CSR offline.
    - Install on CA Node:
      - `install_issuing_ca(issuing_ca_key_pair, issuing_ca_certificate, root_ca_certificate, ea_public_keys)`
  - Option B (early bring-up only): Use Root CA directly on CA Node
    - Securely transfer Root CA key+cert (encrypted using node agreement key) and call the same install API.
    - Not recommended for production, but validates the rest of the flow.
- Assertions:
  - CA Node `status()` exposes issuing subject, serial, validity window.
  - Chain validates: Issuing → Root (or leaf==root in Option B).

Required certificate API (design):
- Add CA-profile signing to existing `CertificateAuthority` for Issuing CA:
  - `sign_ca_certificate_request_with_serial(ca_csr_der, validity_days, Some(serial))` → CA cert (BasicConstraints CA=true, path_len=0; KeyUsage keyCertSign+cRLSign; SKI present).

### 15.3 Phase 2 – Enrollment Token issuance (out-of-band)
- Admin tooling generates a token using an Enrollment Authority (EA) ECDSA P-256 key (no new crate needed):
  - Build `EnrollmentTokenBody { token_id, network_id, subject_hint, not_before, expires_at, nonce, permissions:["enroll"] }` (CBOR).
  - Sign `CBOR(body)` with EA key → DER signature.
  - Produce `EnrollmentToken { body, signature, signer_id = compact_id(ea_public_key) }`.
- Provide EA public key to the CA Node via `configure_enrollment_authority(vec![ea_public_key])`.
- Assertions:
  - Token window valid; `network_id` matches.
  - CA Node recognizes `signer_id` and verifies signature with EA public key.

### 15.4 Phase 3 – New Mobile App (frontend role) prepares CSR
- New app uses `NodeKeyManager`:
  - `let mut mobile_node = NodeKeyManager::new(logger)?;`
  - `mobile_node.generate_keys()?;`
  - `let csr = mobile_node.generate_csr()?;` // CN = compact_id(device public key)
- Assertions:
- CSR parseable with `x509-parser` and CN matches device compact_id.

### 15.5 Phase 4 – Enrollment over QUIC (server-auth only)
- Client sends binary message: `[Header(8)] + [CBOR(CsrEnrollRequest)]`
  - `CsrEnrollRequest { network_id, csr_der: csr.csr_der, enrollment_token }`
- CA Node handler steps:
  1) Verify token signature (EA public key) and time window.
  2) Anti-replay and rate-limit checks (per remote+token_id/subject_hint).
  3) Parse CSR; validate CN equals `compact_id(public_key)` extracted from CSR.
  4) Issue device leaf certificate from Issuing CA (not CA), 7–30 days validity.
  5) Respond `[Header(8)] + [CBOR(CsrEnrollResponse)]` with `{ certificate_der, issuing_ca_der, root_ca_der: Some(root_der), expires_at }`.
- Client installs cert:
  - Convert to `NodeCertificateMessage` and call `mobile_node.install_certificate(...)`.
- Assertions:
  - `mobile_node.get_certificate_status() == CertificateStatus::Valid`.
  - `get_quic_certificate_config()` returns chain [leaf, issuing/root] and parseable private key via `PrivateKeyDer::try_from(...)`.
  - X.509 checks: BasicConstraints notCA, KeyUsage digitalSignature, EKU includes clientAuth/serverAuth per policy.

### 15.6 Phase 5 – Participate as peer under mTLS
- Build root store for transporter from Issuing/Root CA (from CA Node or config).
- Optional live transport validation (if wired):
  - Server requires client auth (`WebPkiClientVerifier::builder(root_store)`); client presents `with_client_auth_cert(chain, key)`.
  - Verify mutual acceptance and that subjects match compact_ids.

### 15.7 Phase 6 – Renewal (mTLS)
- Trigger renewal when within renewal window (e.g., T-7d):
  - Send `[Header(8)] + [CBOR(RenewRequest)]` with `{ network_id, csr_der }` over mTLS.
  - CA Node validates mTLS identity vs CSR CN; issues new leaf cert.
  - Client installs new cert; validate `CertificateStatus::Valid` and updated serial/validity.

### 15.8 Phase 7 – Revocation + CRL-lite propagation
- CA Node revokes old device certificate via `[Header(8)] + [CBOR(RevokeRequest)]` with `{ network_id, certificate_serial, reason }` from an authorized admin cert (mTLS).
- CA Node publishes CRL-lite over QUIC: `[Header(8)] + [CBOR(CrlResponse)]` (signed by Issuing CA or a dedicated revocation key).
- Client fetches and caches denylist.
- Transporter enforcement hook (post-handshake): deny connections whose peer serial appears in CRL-lite cache.
- Assertions:
  - CRL-lite contains the revoked serial.
  - Connection attempt using revoked cert is rejected (if hook implemented), or the denylist is present (design validated).

### 15.9 Phase 8 – Profile keys (frontend/mobile role)
- Derive a profile agreement key on `mobile_node`:
  - `let personal_pub = mobile_node.derive_user_profile_key("personal")?;`
- Envelope interop:
  - Existing node encrypts with envelope for `personal_pub`.
  - `mobile_node.decrypt_with_profile(env, &compact_id(&personal_pub))?` returns plaintext.
- Assertions: encryption/decryption round-trip.

### 15.10 Pseudocode skeleton (design)
```rust
#[tokio::test]
async fn test_e2e_mobile_enrollment_via_ca_node_quic() -> Result<()> {
  // 0) Reuse existing e2e: master mobile + network + enrolled backend nodes

  // 1) Elect CA Node and install Issuing CA
  // ca_node.install_issuing_ca(issuing_ca_key_pair, issuing_ca_cert, root_ca_cert, ea_pubkeys)?;

  // 2) Enrollment token (out-of-band)
  // let token = sign_enrollment_token(&ea_key, &body)?;
  // ca_node.configure_enrollment_authority(vec![ea_key.public_key_bytes()]);

  // 3) New mobile (frontend role)
  let mut mobile_node = NodeKeyManager::new(create_logger())?;
  mobile_node.generate_keys()?;
  let csr = mobile_node.generate_csr()?;

  // 4) Enroll over QUIC (server-auth only)
  let enroll_req = CsrEnrollRequest { network_id: "network1".to_string(), csr_der: csr.csr_der.clone(), enrollment_token: token };
  let enroll_resp = ca_node.handle_enroll(enroll_req)?; // in-memory handler for test
  let msg = NodeCertificateMessage::from_enroll_response(&enroll_resp);
  mobile_node.install_certificate(msg)?;
  assert_eq!(mobile_node.get_certificate_status(), CertificateStatus::Valid);

  // 5) Validate QUIC config
  let cfg = mobile_node.get_quic_certificate_config()?;
  assert!(!cfg.certificate_chain.is_empty());
  let _ = PrivateKeyDer::try_from(cfg.private_key.secret_der().to_vec())?;

  // 6) Renewal (mTLS)
  let renew_req = RenewRequest { network_id: "network1".to_string(), csr_der: mobile_node.generate_csr()?.csr_der };
  let renew_resp = ca_node.handle_renew(renew_req)?;
  let msg = NodeCertificateMessage::from_renew_response(&renew_resp);
  mobile_node.install_certificate(msg)?;

  // 7) Revocation + CRL-lite
  let old_serial = /* from first leaf cert */;
  let _ = ca_node.handle_revoke(RevokeRequest { network_id: "network1".to_string(), certificate_serial: old_serial, reason: "compromise".into() })?;
  let crl = ca_node.handle_crl_request(CrlRequest { network_id: "network1".to_string() })?;
  assert!(crl.revoked_serials.iter().any(|s| s == &old_serial));

  // 8) Profile keys
  let personal = mobile_node.derive_user_profile_key("personal")?;
  let env = existing_node.encrypt_with_envelope(b"hello", None, vec![personal.clone()])?;
  let pt = mobile_node.decrypt_with_profile(&env, &compact_id(&personal))?;
  assert_eq!(pt, b"hello");
  Ok(())
}
```

### 15.11 Design validation and gaps
- Required new certificate API: CA-profile signing for Issuing CA (CA=true, path_len=0, KeyUsage keyCertSign+cRLSign). No new crates.
- CA Node service (test harness): `install_issuing_ca(...)`, `configure_enrollment_authority(...)`, handlers for `enroll/renew/revoke/crl/status` using existing crypto libs.
- Transporter denylist enforcement: small post-handshake hook to consult CRL-lite cache before marking peer connected.
- NodeKeyManager frontend additions from Section 4 must be implemented (profile agreements + decrypt precedence).

---

## 16) Policy decisions and their impact (defaults and alternatives)

This section expands the remaining policy choices with detailed rationale, dataflows affected, and top options. Defaults are suitable for initial rollout and can be revised per network policy.

### 16.1 Leaf EKU policy scope (Selected: Option A)

Context:
- QUIC over rustls uses TLS 1.3. A peer may act as server and client at different times (true P2P). Today, tests assume leaf certs are usable for both roles.

Option A (selected): EKU = clientAuth + serverAuth on all device leaf certs
- What it does: one device certificate supports both TLS client and TLS server roles.
- Dataflows impacted:
  - Enrollment/Renewal: CA issues leaf with both EKUs.
  - Transport handshake: rustls validates EKU per role; the same certificate passes both server and client checks.
- Pros:
  - Simpler key management; single cert per device regardless of role.
  - Fits P2P usage where roles can switch dynamically.
- Cons:
  - Slightly broader usage than least-privilege if a device should never act as server.

Option B: Separate profiles – client-only and server-only device certs
- What it does: devices get role-specific certs or two certs if they must serve both roles.
- Dataflows impacted:
  - Enrollment: client requests must specify profile; CA issues EKU-appropriate leaf.
  - Transport: app must choose the correct cert per role and handle storage of multiple certs.
- Pros:
  - Least-privilege alignment; tighter scope.
- Cons:
  - More complex provisioning and runtime selection; larger operational surface.

Final decision: Option A. This is a peer-to-peer system; devices may act as both client and server.

### 16.2 CRL-lite fetch interval (Selected: Option A)

Context:
- We propose a signed CBOR denylist (CRL-lite) fetched by peers and enforced post-handshake by transporter.

Option A (selected): 10 minutes
- What it does: peers fetch CRL-lite on startup and every ~10 minutes.
- Dataflows impacted:
  - CA Node: generates and serves CRL-lite upon change; otherwise cached copy served.
  - Client: schedules periodic fetch; on update, refresh in-memory denylist.
- Pros:
  - Balanced staleness vs. load; suitable for most networks.
- Cons:
  - Up to 10-minute window where a revoked cert could still connect (unless proactively disconnected).

Option B: 1–5 minutes
- Pros:
  - Tighter revocation freshness.
- Cons:
  - Higher load on CA endpoints; more churn.

Final decision: Option A (10 minutes) with backoff on failures; allow per-network override.

### 16.3 Admin authorization matching for CA control endpoints (Selected: Option A)

Context:
- Admin-only endpoints (e.g., revoke) over mTLS need authorization checks beyond successful TLS.

Option A (selected): Allowlist by Subject Key Identifier (SKI)
- What it does: configure a set of admin SKIs; on mTLS, extract peer cert SKI and match.
- Dataflows impacted:
  - CA Node: on `$ca/{network_id}/revoke` and similar, read SKI from peer cert and compare.
- Pros:
  - Stable across CN/subject formatting changes; resilient to subject collisions.
- Cons:
  - Requires extracting SKI from cert (which we already parse elsewhere).

Option B: Allowlist by subject string (exact match)
- Pros:
  - Simple to configure/read.
- Cons:
  - Brittle to formatting changes; potential for ambiguity if subjects are not unique.

Final decision: Option A (SKI allowlist) enforced over mTLS. This provides strong authentication because:
1) mTLS proves possession of the admin certificate private key (TLS layer), and
2) SKI allowlist authorizes only specific admin identities at the application layer.

Optional (not required by default): request-body signing for non-repudiation
- If additional provenance is desired for auditability beyond mTLS, we can require admins to sign the request payload using their device identity key.
- Mechanism:
  - Include `AdminSignedEnvelope { payload_cbor_sha256: [u8;32], timestamp: u64, signature_der: Vec<u8> }` alongside the admin request.
  - CA Node verifies `signature_der` with the mTLS peer certificate public key and checks timestamp skew.
- Impact: Adds explicit application-level signatures; useful for offline audit trails. Not strictly necessary for security when mTLS + SKI allowlist are enforced.

### 16.4 Issuing CA overlap window length before cutover (Selected: Option A)

Context:
- When rotating Issuing CA, both old and new chains should be accepted for a period to allow smooth migration.

Option A (selected): 30 days overlap
- What it does: CA Node publishes both chains; clients accept either chain for 30 days.
- Dataflows impacted:
  - `$ca/{network_id}/chain` returns both or switches at mid-point; issuance uses new CA after a date; verification allows both.
- Pros:
  - Plenty of time for intermittently connected devices to update.
- Cons:
  - Longer window where two issuers are trusted.

Option B: 7–14 days overlap
- Pros:
  - Faster convergence to a single issuer.
- Cons:
  - Risk of stranding long-offline devices.

Final decision: Option A (30 days). Suitable for mobile-heavy networks; configurable per deployment.

### 16.5 Which CA to embed at bootstrap (for server-auth to CA Node) (Selected: Option A)

Context:
- New clients must authenticate the CA Node on the bootstrap bind before they have device certs.

Option A (selected): Embed Root CA
- What it does: ship Root CA cert in the app; bootstrap bind uses an Issuing/leaf chain anchored at Root.
- Dataflows impacted:
  - App install: Root CA stored in trust set.
  - CA Node: presents server cert chaining to Root.
- Pros:
  - Stable trust anchor across Issuing CA rotations.
- Cons:
  - App updates required if Root changes (rare by design).

Option B: Embed current Issuing CA
- Pros:
  - Smaller trust surface; faster revocation of a compromised Issuing CA by app update.
- Cons:
  - Requires app updates on every Issuing CA rotation; operationally heavier.

Final decision: Option A (Root). Provides long-lived stability; Issuing CA rotations do not require app updates.

---

## 17) X.509 profiles and SKI extraction – exact details

This section enumerates exact extension OIDs, criticality, and validation rules for both Issuing CA and Device Leaf certificates, plus precise SKI/AKI extraction and matching rules. All validation is performed using the existing `x509-parser = "0.16"` already used in tests.

### 17.1 OIDs and constants (for reference)
- Subject Key Identifier (SKI): 2.5.29.14
- Authority Key Identifier (AKI): 2.5.29.35
- Basic Constraints: 2.5.29.19
- Key Usage: 2.5.29.15
- Extended Key Usage (EKU): 2.5.29.37
  - serverAuth: 1.3.6.1.5.5.7.3.1
  - clientAuth: 1.3.6.1.5.5.7.3.2
- Signature algorithm: ECDSA with SHA-256 → 1.2.840.10045.4.3.2

### 17.2 Issuing CA certificate profile (intermediate)
- BasicConstraints: critical, CA=true, pathLenConstraint=0
- KeyUsage: critical, keyCertSign=true, cRLSign=true; all others false
- SubjectKeyIdentifier: present (20 bytes typical)
- AuthorityKeyIdentifier: present (keyIdentifier matches Root’s SKI)
- Signature algorithm: ECDSA-SHA256 (1.2.840.10045.4.3.2)
- Subject/Issuer: Issuer is Root; Subject is Issuing CA DN

Validation on import at CA Node:
1) Parse with `x509-parser`; assert BasicConstraints and KeyUsage per above.
2) Verify AKI of Issuing CA matches SKI of Root CA when both are present.
3) Accept only ECDSA-SHA256 signatures.

### 17.3 Device leaf certificate profile
- BasicConstraints: critical, CA=false (notCA)
- KeyUsage: critical, digitalSignature=true; keyEncipherment=false; cRLSign=false; keyCertSign=false; keyAgreement=false
- ExtendedKeyUsage: non-critical, contains both serverAuth and clientAuth
- SubjectKeyIdentifier: present (20 bytes typical)
- AuthorityKeyIdentifier: present; must equal Issuing CA SKI
- Signature algorithm: ECDSA-SHA256 (1.2.840.10045.4.3.2)
- Subject DN: `CN={compact_id(device_public_key)},O=Runar Node,C=US` (consistent with existing CSR subject)

Validation on install (`NodeKeyManager::install_certificate` path):
1) Use CA public key to verify leaf signature.
2) Assert BasicConstraints/KeyUsage/EKU per above.
3) Assert AKI(leaf) == SKI(issuing CA); if Root used directly, AKI(leaf) == SKI(root CA).
4) Assert CN contains `compact_id(node_public_key)` (current behavior).

### 17.4 SKI and AKI extraction using x509-parser
- SKI: extension OID 2.5.29.14 yields 20-byte key identifier (SHA-1 of subject public key, per common practice).
- AKI: extension OID 2.5.29.35 may include keyIdentifier; we match on that field.

Pseudocode (already consistent with tests):
```rust
use x509_parser::prelude::FromDer;
use x509_parser::extensions::ParsedExtension;

let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der_bytes)?;
let mut maybe_ski: Option<Vec<u8>> = None;
let mut maybe_aki: Option<Vec<u8>> = None;
for ext in cert.extensions() {
    match ext.parsed_extension() {
        ParsedExtension::SubjectKeyIdentifier(ski) => {
            maybe_ski = Some(ski.0.to_vec()); // typically 20 bytes
        }
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            if let Some(kid) = &aki.key_identifier { maybe_aki = Some(kid.0.to_vec()); }
        }
        _ => {}
    }
}
// For admin SKI allowlist: hex::encode(maybe_ski.unwrap()) compare against configured set
```

Where needed, compare SKI byte arrays directly or hex-encode using `hex = "0.4"` (already in repo).

---

## 18) CA Node admin auth – handler wiring and verification flow

Admin-only endpoints (e.g., `$ca/{network_id}/revoke`) enforce two layers:
1) Transport-layer authentication (mTLS): rustls validates the admin client certificate chain against Root/Issuing roots.
2) Application-layer authorization: SKI allowlist on the peer’s leaf certificate.

### 18.1 Obtaining peer certificate (transporter/Quinn/rustls)
- At connection acceptance, use the rustls-backed Quinn crypto session to access peer certificates:
  - In rustls 0.23, `tls_connection.peer_certificates()` returns `Option<&[CertificateDer]>` after handshake.
  - In Quinn 0.11 with rustls backend, wrap the `rustls::Connection` via `quinn::crypto::rustls` and plumb the chain up to the request handling layer (design change in transporter: expose peer cert chain on per-connection context).
- The CA service layer reads the peer leaf certificate DER from this context for each request.

### 18.2 SKI allowlist check
Steps:
1) Parse the peer leaf DER with `x509-parser` and extract SKI (Section 17.4).
2) Hex-encode or compare raw bytes against the configured admin SKI allowlist for the `network_id`.
3) If not matched, return `CaErrorResponse { code: "forbidden", message: "admin SKI not authorized" }` and close the connection.

### 18.3 Optional request-body signing (non-repudiation)
- Structure appended to admin requests:
```rust
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AdminSignedEnvelope {
    pub payload_sha256: [u8; 32],    // SHA-256 over CBOR(payload)
    pub timestamp: u64,              // UNIX seconds, max skew e.g., 120s
    pub signature_der: Vec<u8>,      // ECDSA P-256 signature
}
```
- Verification:
  1) Compute SHA-256 over the received CBOR payload and compare to `payload_sha256`.
  2) Extract peer leaf cert public key (from mTLS) and verify `signature_der` over `payload_sha256` using `p256::ecdsa::Verifier`.
  3) Check `timestamp` within allowed skew; keep a short-lived nonce ledger (payload hash + ts) to prevent replay.
- This layer is optional; mTLS + SKI allowlist already provide strong auth. Enable when audit-level non-repudiation is required.

### 18.4 Failure mapping
- Unauthorized admin: `forbidden`
- Bad signature or timestamp skew: `bad_signature`
- Missing peer cert (should not happen after mTLS): `protocol_error`
- All errors returned as `CaErrorResponse` (CBOR) with clear message.

---

## 19) Critical Implementation Fixes (Based on Code Review)

This section contains the detailed implementation answers for critical fixes identified during code review. These fixes are required to make the CA Node implementation robust, design-compliant, and production-ready.

### 19.1 Device-based Renewal Authorization (CRITICAL)

**Current Issue**: `handle_renew` requires admin SKI allowlist and does not validate device identity continuity.

**Required Behavior**:
- Renewals are initiated by the device over an mTLS-authenticated connection
- Authorize by continuity: CSR CN must equal `compact_id(peer_device_public_key)` extracted from the mTLS peer leaf certificate
- Remove admin SKI requirement from renewal (admin SKI only for admin endpoints like revoke)

**Implementation**:
- Server MUST extract the peer leaf certificate from the TLS session and pass it to `CANode::handle_renew` as part of a structured context
- Inside `CANode::handle_renew`, recompute `compact_id` from the provided peer certificate's subject public key info (SPKI) and compare to the CSR's CN
- Reject on mismatch with specific error: `bad_request` with reason `"csr_cn_mismatch"`

**Inputs to CANode for renew**:
```rust
struct RenewRequestContext {
    peer_leaf_cert_der: Vec<u8>,
    csr_der: Vec<u8>,
    network_id: String,
    // ... other fields
}
```

**CANode Implementation**:
1. Parse peer cert, extract P-256 public key
2. Compute `compact_id` from peer cert public key
3. Parse CSR and extract CN
4. Compare CSR CN to computed `compact_id`
5. Reject with specific error if mismatch

### 19.2 CRL-lite Signing (CRITICAL)

**Current Issue**: `generate_crl_lite` sets `signature: vec![]` (TODO placeholder).

**Required Behavior**:
- Sign the CBOR serialization of the revocation list body (with the `signature` field excluded) using the Issuing CA's P-256 key with SHA-256
- Include raw DER-encoded ECDSA signature bytes in the `signature` field
- Include `sig_alg` metadata (e.g., `"p256-sha256-der"`) and the signer's SKI (`signer_ski`) in the structure

**Implementation**:
```rust
struct CaRevocationList {
    // ... existing fields
    signature: Vec<u8>,        // Raw DER-encoded ECDSA signature bytes
    signer_ski: Vec<u8>,       // SKI of the signing key
    sig_alg: String,           // e.g., "p256-sha256-der"
}
```

**Signing Process**:
1. Create CRL-lite body without `signature` field
2. Serialize to CBOR
3. Sign with Issuing CA private key using P-256 ECDSA with SHA-256
4. Include raw DER signature bytes (not hex-encoded)
5. Add `signer_ski` and `sig_alg` metadata

**Verification**:
- Clients verify by validating the Issuing CA chain against embedded Root
- Check that `signer_ski` matches the Issuing CA cert SKI
- Reserialize the CRL-lite body without the signature
- Verify the DER signature with the Issuing CA public key

### 19.3 Rate Limiting using Remote Address (IMPORTANT)

**Current Issue**: Hard-coded placeholder "127.0.0.1:12345" for rate limiting.

**Required Behavior**:
- Rate limiting must be keyed by the actual remote address, not a placeholder
- Rate-limit by `(remote_ip, endpoint_kind)` and `(token_id, nonce)` for enrollment

**Implementation**:
- Capture the remote address at the connection level and thread it into each handler call as part of a `RequestContext`
- Implement rate limiting in the server layer (transport) to prevent CPU-heavy CA work from being reached

**RequestContext Structure**:
```rust
struct RequestContext {
    remote_addr: SocketAddr,
    peer_leaf_cert_der: Option<Vec<u8>>,
    // ... other fields
}
```

**Rate Limiting Strategy**:
- Use token bucket or sliding window with configurable limits
- Key by `(remote_ip, endpoint)` for general rate limiting
- Key by `(token_id, nonce)` for enrollment replay protection
- Implement in server layer for DoS protection

### 19.4 Type Alignment for Binary Protocol (IMPORTANT)

**Current Issue**: Server imports request types from `runar-keys::ca_node_types`, causing type drift.

**Required Behavior**:
- Wire protocol types are transport-facing and must include `network_id`, versioning, and message discriminants
- Internal CA types remain decoupled and are used by CANode
- Single source of truth for all types in runar-keys

**Implementation**:
- Use `runar-keys::ca_node_types` as single source of truth
- Add `network_id` and `version` fields to existing types
- Remove duplicate type definitions in transporter

**Updated Types Structure**:
```rust
// runar-keys/src/ca_node_types.rs - Single source of truth
pub const CA_PROTOCOL_VERSION: u16 = 1;

pub struct CaMessageHeader {
    pub message_type: u32,
    pub payload_length: u32,
}

pub enum CaMessageType {
    CsrEnrollRequest = 1,
    CsrEnrollResponse = 2,
    RenewRequest = 3,
    RenewResponse = 4,
    // ... other message types
}

pub struct CsrEnrollRequest {
    pub network_id: String,
    pub version: u16,
    pub csr_der: Vec<u8>,
    pub token: EnrollmentToken,
}

// ... other wire types
```

**Conversion Pattern**:
```rust
impl From<WireCsrEnrollRequest> for InternalCsrEnrollRequest {
    fn from(wire: WireCsrEnrollRequest) -> Self {
        Self {
            csr_der: wire.csr_der,
            token: wire.token.into(),
            // network_id handled at server layer
        }
    }
}
```

### 19.5 Renewal CSR CN Continuity Checks (IMPORTANT)

**Current Issue**: No CN continuity validation during renewal.

**Required Behavior**:
- Enforce continuity centrally and fail if CSR CN does not match the compact_id derived from the mTLS peer leaf certificate
- Perform authoritative check inside CANode with optional fast-fail precheck in server

**Implementation**:
- CANode performs the authoritative check during `handle_renew`
- Server may perform lightweight precheck for fast failure
- Return clear, typed error when mismatch occurs: `bad_request` with reason `"csr_cn_mismatch"`

**Validation Process**:
1. Parse CSR and extract CN
2. Extract peer certificate public key from mTLS session
3. Compute `compact_id` from peer cert public key
4. Compare CSR CN to computed `compact_id`
5. Reject with specific error if mismatch

### 19.6 Server Certificate Chains (RECOMMENDED)

**Current Issue**: Servers present only leaf certificate, not full chain.

**Required Behavior**:
- Always present the full chain `[leaf, issuing_ca]` for better interop and path building

**Implementation**:
- Modify both bootstrap server and authenticated server to present the full chain
- Use rustls API that accepts a chain: `with_single_cert(chain, key)` where `chain` includes leaf then issuing
- This improves clients that don't preload intermediates

### 19.7 Anti-replay Cache (OPTIONAL)

**Current Issue**: No anti-replay protection for enrollment tokens.

**Required Behavior**:
- Detect and drop repeated use of the same enrollment token/nonce pair within a TTL
- Implement primarily in server layer for performance

**Implementation**:
- In-memory TTL cache keyed by `(token_id, nonce)`
- Periodic cleanup task
- Optional defense-in-depth: semantic replay guard in CANode keyed by `token_id`

### 19.8 Error Handling (SPECIFIC)

**Required Behavior**:
- Define precise error enum for each endpoint
- Propagate to wire-level `CaError` with stable code and message

**Error Codes**:
- `unauthorized` (401): Missing/invalid mTLS for endpoints that require it
- `forbidden` (403): Token invalid, token revoked, replay detected, admin SKI not allowed
- `bad_request` (400): CSR CN mismatch, malformed CSR, algorithm mismatch, network_id mismatch
- `conflict` (409): Duplicate enrollment for same device within restricted window
- `rate_limited` (429): Exceeded rate limit for remote address or token
- `internal` (500): Unexpected errors

**Specific Error Mappings**:
- CSR CN continuity failures: `bad_request` with reason `"csr_cn_mismatch"`
- Token replay: `forbidden` with reason `"replay_detected"`
- Admin SKI not permitted: `forbidden` with `"admin_not_authorized"`

### 19.9 Implementation Priority Order

1. **Critical** (blocking transport E2E):
   - Device-based renewal authorization
   - CRL-lite signing

2. **Important**:
   - Remote address rate limiting
   - Binary protocol wire types alignment

3. **Recommended**:
   - Server certificate chains
   - Anti-replay cache

4. **Testing Updates**:
   - Update primitives E2E test for new renewal auth
   - Update full transport E2E test with real remote addresses
   - Add negative tests for CN mismatch, replay detection
   - Add signature verification for CRL-lite

This implementation approach ensures a robust, design-compliant CA Node that is production-ready and free of shortcuts or workarounds.


