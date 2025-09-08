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

### **Backward Compatibility & Testing**
- **DO NOT change test intent and scenarios** - Tests must continue to validate the same functionality
- **All tests work before this change** - Current features must continue working
- **Additive changes only** - Should not break existing functionality
- **Each change must be justified** - Only changes required by design, not implementation issues
- **Test changes must be minimal** - Only update what's necessary due to API changes

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

