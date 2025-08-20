### FFI keys API and lifecycle — round 2

This proposal focuses on the Key Managers FFI surface and lifecycle, replacing raw import/export with on-device encrypted persistence, and adding the missing operations needed by the upper layers (TS/Bun, Swift, etc.).

### Objectives

- Ensure upper layers never receive raw key manager state bytes.
- Move state persistence, encryption, and loading into the Rust layer.
- Provide a minimal lifecycle probe so upper layers know whether to run first-time setup.
- Add the missing mobile and node operations needed for end-to-end flows.
- Keep the C ABI simple and consistent with existing `RnError` handling.

### Lifecycle redesign (encrypted on-device persistence)

- On startup, upper layer calls a new keystore state probe:
  - `rn_keys_mobile_get_keystore_state(keys, int32_t* out_state, err)`
  - `rn_keys_node_get_keystore_state(keys, int32_t* out_state, err)`
  - `out_state` values:
    - `0` = empty / not initialized
    - `1` = initialized / ready

- Semantics:
  - When called, Rust checks for a persisted state on disk. If present, it decrypts it using a device-keystore-bound key and loads it in-memory, then returns `1`.
  - If not present, returns `0` and does not create any state yet.

- Persistence directory:
  - New setter: `rn_keys_set_persistence_dir(keys, const char* dir, err)`
  - If not set, default per platform:
    - iOS/Android: app-private data dir
    - Linux/macOS: XDG data dir or `$HOME/.local/share/runar`/`$HOME/Library/Application Support/runar`

- Explicit wipe (for dev/testing):
  - `rn_keys_wipe_persistence(keys, err)`

### Immediate removals (no backwards compatibility)

- Remove from header and implementation (not used by any upper layer):
  - `rn_keys_node_export_state`, `rn_keys_node_import_state`
  - `rn_keys_mobile_export_state`, `rn_keys_mobile_import_state`
  - Tests/examples must switch to lifecycle probes and device-keystore-backed persistence.

### New API surface (additions)

Mobile (user) operations:

```c
int32_t rn_keys_mobile_initialize_user_root_key(void *keys, struct RNAPIRnError *err);
int32_t rn_keys_mobile_derive_user_profile_key(void *keys,
                                               const char *label,
                                               uint8_t **out_pk,
                                               size_t *out_len,
                                               struct RNAPIRnError *err);
int32_t rn_keys_mobile_install_network_public_key(void *keys,
                                                  const uint8_t *network_pub,
                                                  size_t len,
                                                  struct RNAPIRnError *err);
```

#### Bun-specific variants

For Bun (`bun:ffi`) ergonomics, we add return-style variants that reuse the same internal implementation to avoid duplication. These variants return the primary value directly (or a pointer), and signal failure by returning a null/negative sentinel while also filling `err`.

- Mobile:
  - `int32_t rn_keys_mobile_initialize_user_root_key_return(void *keys, struct RNAPIRnError *err);` // returns 0 on success, -1 on error
  - `uint8_t *rn_keys_mobile_derive_user_profile_key_return(void *keys, const char *label, size_t *out_len, struct RNAPIRnError *err);`
  - `int32_t rn_keys_mobile_install_network_public_key_return(void *keys, const uint8_t *network_pub, size_t len, struct RNAPIRnError *err);`
  - `uint8_t *rn_keys_mobile_generate_network_data_key_return(void *keys, size_t *out_len, struct RNAPIRnError *err);`
  - `uint8_t *rn_keys_mobile_get_network_public_key_return(void *keys, const char *network_id, size_t *out_len, struct RNAPIRnError *err);`
  - `uint8_t *rn_keys_mobile_create_network_key_message_return(void *keys, const char *network_id, const uint8_t *node_agreement_pk, size_t node_agreement_pk_len, size_t *out_len, struct RNAPIRnError *err);`

- Node:
  - `uint8_t *rn_keys_node_generate_csr_return(void *keys, size_t *out_len, struct RNAPIRnError *err);`
  - `int32_t rn_keys_node_install_network_key_return(void *keys, const uint8_t *key_bytes, size_t len, struct RNAPIRnError *err);`

- Lifecycle/persistence:
  - `int32_t rn_keys_mobile_get_keystore_state_return(void *keys, struct RNAPIRnError *err);` // returns 0/1, -1 on error
  - `int32_t rn_keys_node_get_keystore_state_return(void *keys, struct RNAPIRnError *err);` // returns 0/1, -1 on error
  - `int32_t rn_keys_set_persistence_dir_return(void *keys, const char *dir, struct RNAPIRnError *err);` // 0 on success, -1 on error
  - `int32_t rn_keys_wipe_persistence_return(void *keys, struct RNAPIRnError *err);` // 0 on success, -1 on error
  - `int32_t rn_keys_enable_auto_persist_return(void *keys, bool enabled, struct RNAPIRnError *err);` // 0 on success, -1 on error
  - `int32_t rn_keys_flush_state_return(void *keys, struct RNAPIRnError *err);` // 0 on success, -1 on error
  - `struct RNDeviceKeystoreCaps rn_keys_get_keystore_caps_return(void *keys, struct RNAPIRnError *err);` // on error, set `err->code` and return `{0}`

Notes:
- Memory management remains the same; returned buffers must be freed by `rn_free` and strings by `rn_string_free`.
- Each `_return` function forwards to the canonical C-conventional function to keep a single code path.

Mobile (network master) operations:

```c
int32_t rn_keys_mobile_generate_network_data_key(void *keys,
                                                 uint8_t **out_key,
                                                 size_t *out_len,
                                                 struct RNAPIRnError *err);
int32_t rn_keys_mobile_get_network_public_key(void *keys,
                                              const char *network_id,
                                              uint8_t **out_pk,
                                              size_t *out_len,
                                              struct RNAPIRnError *err);
int32_t rn_keys_mobile_create_network_key_message(void *keys,
                                                  const char *network_id,
                                                  const uint8_t *node_agreement_pk,
                                                  size_t node_agreement_pk_len,
                                                  uint8_t **out_msg_cbor,
                                                  size_t *out_len,
                                                  struct RNAPIRnError *err);
```

Node operations:

```c
// already present
int32_t rn_keys_node_generate_csr(void *keys, uint8_t **out_st_cbor, size_t *out_len, struct RNAPIRnError *err);

// new: install network symmetric key (distinct from certificate install)
int32_t rn_keys_node_install_network_key(void *keys,
                                         const uint8_t *key_bytes,
                                         size_t len,
                                         struct RNAPIRnError *err);
```

Lifecycle probes and persistence configuration:

```c
int32_t rn_keys_mobile_get_keystore_state(void *keys, int32_t *out_state, struct RNAPIRnError *err);
int32_t rn_keys_node_get_keystore_state(void *keys, int32_t *out_state, struct RNAPIRnError *err);
int32_t rn_keys_set_persistence_dir(void *keys, const char *dir, struct RNAPIRnError *err);
int32_t rn_keys_wipe_persistence(void *keys, struct RNAPIRnError *err);
```

Notes:
- All new functions follow existing conventions: return `0` on success, set `err` otherwise, and never return partially-initialized outputs.
- All outputs use the existing alloc pattern (`rn_free`/`rn_string_free`).

### Keystore integration plan: callback-based now; native backends later

Goal: ensure the per-device encryption key never leaves the OS keystore and is not exposed to upper layers. Rust never sees the device key and only handles plaintext state in memory briefly.

Callback-based (reference only; NOT planned for implementation): upper layer registers encryption/decryption callbacks backed by iOS Keychain/Secure Enclave or Android Keystore. Rust calls these to encrypt/decrypt the serialized key manager state before writing/after reading from disk. We chose to implement native backends directly instead.

Required C ABI (v1):

```c
// AEAD-capable callbacks with optional AAD. Ciphertext format is opaque to Rust and must include
// whatever the platform needs (IV/nonce, tag, version). Rust simply stores the returned bytes.

typedef int32_t (*RNDeviceEncryptFn)(void *ctx,
                                     const uint8_t *plain,
                                     size_t plain_len,
                                     const uint8_t *aad,
                                     size_t aad_len,
                                     uint8_t **out_cipher,
                                     size_t *out_len,
                                     struct RNAPIRnError *err);

typedef int32_t (*RNDeviceDecryptFn)(void *ctx,
                                     const uint8_t *cipher,
                                     size_t cipher_len,
                                     const uint8_t *aad,
                                     size_t aad_len,
                                     uint8_t **out_plain,
                                     size_t *out_len,
                                     struct RNAPIRnError *err);

// Register platform keystore. Must be called before any persistence happens.
int32_t rn_keys_register_device_keystore(void *keys,
                                         void *encrypt_ctx,
                                         RNDeviceEncryptFn encrypt_fn,
                                         void *decrypt_ctx,
                                         RNDeviceDecryptFn decrypt_fn,
                                         struct RNAPIRnError *err);

// Optional: enable/disable automatic persistence when state mutates,
// and force a flush on demand.
int32_t rn_keys_enable_auto_persist(void *keys, bool enabled, struct RNAPIRnError *err);
int32_t rn_keys_flush_state(void *keys, struct RNAPIRnError *err);

// Optional: query keystore capabilities to inform UX (e.g., biometric required, hardware-backed, etc.).
typedef struct RNDeviceKeystoreCaps {
  uint32_t version; // struct version, start at 1
  uint32_t flags;   // bitfield: 1=hardware_backed, 2=biometric_gate, 4=screenlock_required, 8=strongbox
} RNDeviceKeystoreCaps;

int32_t rn_keys_get_keystore_caps(void *keys,
                                  struct RNDeviceKeystoreCaps *out_caps,
                                  struct RNAPIRnError *err);
```

AAD policy (Rust-provided):
- Rust passes AAD to bind ciphertext to context and prevent cross-role replay:
  - Format: `"runar:keys_state:v1|role=<mobile|node>|node_id=<id>|network_id=<opt>"`
NOTE network_id should not ploay a role here.. a node can have muultple network ids.. and is shuood not be related at all to these operations here.. node id yes..w e can use to properly label this by node-id whci is unique per node/mobile and never changes..

  - Node: includes `node_id`,  Mobile: omits `node_id`.
  - Upper layer must feed AAD unchanged to decrypt; AAD is public but integrity-protected by AEAD.

Rust persistence semantics:
- On state change (e.g., install certificate, initialize root, install network key), if auto-persist is enabled, Rust serializes state to bytes, calls `encrypt_fn` with AAD, and writes the returned ciphertext to the configured directory atomically (`.tmp` + rename).

- On keystore state probe, Rust attempts to read ciphertext, calls `decrypt_fn` with the same AAD, reconstructs state in memory, and zeroizes plaintext buffers after use.
- If no keystore is registered, persistence functions return an error in `release`; in `debug`, a feature-guarded software fallback can be enabled (see below).

Security and error handling:
- Callbacks must be constant-time regarding key usage and ensure nonces are unique per key (platform APIs typically handle this). Ciphertext must encapsulate IV/nonce and tag.
- On any callback error, Rust will not write to disk and will surface the error via `RnError`.
- Rust zeroizes plaintext state buffers after encrypt/decrypt and before drop.

Dev-only fallback (feature `ffi_dev_soft_keystore`):
- For local development only, enable a software AES-GCM keystore (key derived from a process-provided secret). Not compiled in production builds.

Native backends (to implement now):
- Implement a `DeviceKeystore` trait in Rust with platform backends:
  - Apple: Keychain + Secure Enclave wrap; store symmetric key or wrapped blob; access with `kSecAttrAccessibleWhenUnlocked`.
  - Android: Android Keystore AES/GCM with StrongBox when available; app-scoped key with screen lock/biometric policies.
- When available, upper layers can skip registering callbacks; Rust selects native backend automatically.

Implementation order: Apple first (immediate), Android next. See `runar-keys/NATIVE_KEYSTORE_BACKENDS.md` for the detailed design and placement in `runar-keys` (not in `runar-ffi`).

Layering note:
- Persistence, keystore, and key lifecycle belong in `runar-keys` for clear separation of concerns and testability.
- `runar-ffi` should stay as a thin ABI layer that marshals inputs/outputs and defers logic to `runar-keys`.

### Mobile and Node flows (high-level)

Mobile first run:
1. `rn_keys_mobile_get_keystore_state` → `0`
2. `rn_keys_mobile_initialize_user_root_key`
3. (optional) `rn_keys_mobile_generate_network_data_key`
4. Persisted automatically by Rust using device keystore on next safe point.

Mobile subsequent runs:
1. `rn_keys_mobile_get_keystore_state` → `1` (Rust loads/decrypts state automatically)

Node first run:
1. `rn_keys_node_get_keystore_state` → `0`
2. `rn_keys_node_generate_csr` → send to mobile, receive cert message
3. `rn_keys_node_install_certificate`
4. (if needed) `rn_keys_node_install_network_key`

Node subsequent runs:
1. `rn_keys_node_get_keystore_state` → `1`

### Removal plan and migration

- Keep `*_export_state`/`*_import_state` compiled by default for one release behind a feature flag `ffi_legacy_state_io`.
- Add the new lifecycle APIs alongside, switch all examples/tests in `runar-ffi` and TS/Swift layers to the new flow.
- Remove legacy functions once downstreams migrate.

### Feasibility: iOS and Android keystore from Rust

Yes. Two workable paths:
- Via callbacks (Approach A): upper layer (Swift/Kotlin) already has first-class access to Keychain/Keystore and can supply encrypt/decrypt operations that never expose the key to Rust or JS. Rust only sees ciphertext.
- Via native backends (Approach B): leverage Rust FFI to call platform APIs. Existing crates cover parts (e.g., `security-framework` on Apple; JNI/NDK bindings on Android). For AES‑GCM, Android Keystore supports symmetric keys that never leave TEE; on Apple, typical practice is storing symmetric keys in Keychain and using Secure Enclave for wrapping/attestation when asymmetric keys are required.

Both approaches keep the device key on-device and out of upper layers.

### Next steps

- Add the new function declarations to `runar-ffi/include/runar_ffi.h` and stubs in `runar-ffi/src/lib.rs`.
- Implement keystore state probe and persistence with a pluggable `DeviceKeystore` (start with callbacks).
- Deprecate legacy state import/export and update tests/examples to use the new lifecycle.