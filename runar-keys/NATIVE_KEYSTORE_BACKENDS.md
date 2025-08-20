### Native device keystore backends

This document details how to implement native device keystore support in `runar-keys`, not in `runar-ffi`. The FFI layer should remain thin and reuse `runar-keys` APIs.

Goals:
- Keep device encryption keys inside the OS-provided keystore. Keys never leave the device or cross into JS.
- Provide AEAD (e.g., AES-GCM) to protect serialized key manager state with integrity.
- Support AAD binding to context: `"runar:keys_state:v1|role=<mobile|node>|node_id=<id>"`.
- Make persistence automatic and robust across crashes using atomic writes.

### Architecture

- Add a `DeviceKeystore` trait in `runar-keys`:
  - `encrypt(plain: &[u8], aad: &[u8]) -> Result<Vec<u8>>`
  - `decrypt(cipher: &[u8], aad: &[u8]) -> Result<Vec<u8>>`
  - `capabilities() -> DeviceKeystoreCaps`

- Provide an internal `Persistence` module:
  - `save(role, node_id_opt, state_bytes)` → uses keystore.encrypt + atomic write
  - `load(role, node_id_opt)` → read + keystore.decrypt + parse
  - Paths under configurable base dir; default per platform as in the FFI doc.

- Integrate into `MobileKeyManager` and `NodeKeyManager`:
  - On state mutation, if auto-persist is enabled, trigger `Persistence::save` with the latest state.
  - On keystore probe, call `Persistence::load` and rehydrate keys.

### Apple backend (to implement now)

Approach: Use `keychain-services = "0.1.1"` to access Keychain/Secure Enclave. Generate a Secure Enclave EC keypair and use it to wrap an AES-256 key (generated in Rust). Store the wrapped blob in Keychain and unwrap on demand. Perform AEAD with `aes-gcm` (already in deps). Use `zeroize` to wipe secrets.

Steps:
- Prefer `keychain-services` crate (no custom FFI) for `SecKey`, `SecAccessControl`, and Keychain item APIs.
- Create or fetch a Secure Enclave keypair with `kSecAttrTokenIDSecureEnclave`, access control flags as needed.
- Wrap/unwrap the AES key using `SecKeyCreateEncryptedData` / `SecKeyCreateDecryptedData` with ECIES + AES-GCM.
- AEAD with `aes-gcm` and random 12-byte nonce; format: `version | nonce | tag | ciphertext`.
- Capabilities reflect Secure Enclave usage and ACL flags.

Testing:
- Unit tests in `runar-keys` with a mock keystore.
- Integration tests under `#[cfg(target_os = "macos")]`/`#[cfg(target_os = "ios")]`.
 - Ensure correct entitlements:
   - macOS sandboxed/iOS: Keychain access requires code signing; Secure Enclave access may prompt user presence if configured. Missing entitlements yield `errSecMissingEntitlement`.
   - Configure Access Control (biometry/passcode) via `SecAccessControl` flags when generating the private key.

### Android backend (later)

Approach: Use Android Keystore via NDK/JNI. Generate AES key with purposes ENCRYPT/DECRYPT and GCM mode. Enable StrongBox when available.

Steps:
- JNI bindings (via `jni` crate) to call `KeyGenParameterSpec` and `KeyStore` APIs.
- Generate app-scoped AES key alias `com.runar.keys.state.aead.v1` with `setBlockModes(GCM)`, `setEncryptionPaddings(NONE)`, `setUserAuthenticationRequired(true)` when desired.
- Use `Cipher` GCM to encrypt/decrypt state; persist IV and tag with ciphertext.
- Capabilities reflect StrongBox availability and authentication gating.

### Placement and layering

- All keystore logic and persistence live in `runar-keys`.
- `runar-ffi` exposes only thin shims that call into `runar-keys` for lifecycle and I/O.
- This keeps platform-specific code out of the FFI crate and centralizes security-sensitive logic in the core library.

### Dependency and feature flags

- Add optional deps in `runar-keys/Cargo.toml`:
  - `keychain-services = "0.1.1"`
  - `zeroize = "1"`
- Feature `apple-keystore` enables the Apple backend and pulls optional deps.
- No conflict with existing crypto deps: we already use `aes-gcm` and P-256 primitives; `keychain-services` only wraps Apple Security APIs.

### Linux backend (to implement now for CI and TS/Bun)

Approach: Use system keyring (Secret Service/KWallet) via the `keyring` crate to store an app-scoped AES-256 key. Perform AEAD in Rust with `aes-gcm` using the same format and AAD policy as Apple.

Rationale:
- Works across most Linux environments and in CI (headless). Falls back gracefully if no keyring provider is available.
- Not hardware-backed, but isolates the AES key from app storage. Good for development and automated testing.

Crates:
- `keyring = "1"` (optional) — cross-platform secret storage (Secret Service/KWallet on Linux, also supports Windows Credential Manager).
- `aes-gcm` (already in deps) for AEAD.
- `zeroize = "1"` (optional) for wiping unwrapped keys.

Feature flags:
- `linux-keystore` enables the Linux backend and pulls `keyring` and `zeroize`.

Key storage strategy:
- Service: `"com.runar.keys"`
- Account: `"state.aead.v1"` (or include role/node_id for multi-node testing)
- Stored secret: 32-byte random AES key. Retrieved at runtime for AEAD.
- If item missing: generate a new AES-256 key and store it.

Ciphertext and AAD:
- Same as Apple: `version | nonce | tag | ciphertext` with AAD `"runar:keys_state:v1|role=<mobile|node>|node_id=<id>"`.

API surface in `runar-keys`:
- Implement `LinuxDeviceKeystore` that satisfies `DeviceKeystore`.
- `new(service: &str, account: &str)` constructs a backend bound to a namespaced entry.
- Internally uses `keyring::Entry` read/set to retrieve or create the AES key.

FFI integration (planned):
- `rn_keys_register_linux_device_keystore(keys, const char* service, const char* account, err)`
- Reuse existing persistence APIs (`rn_keys_set_persistence_dir`, `rn_keys_enable_auto_persist`, `rn_keys_*_get_keystore_state`).

Testing in CI:
- Default to `service = "com.runar.keys"`, `account = "state.aead.v1"`.
- Ensure the CI image has a Secret Service provider (e.g., `gnome-keyring` or `kwallet`) or rely on `keyring` crate’s fallback if available. For headless CI, consider `org.freedesktop.secrets` mock or a temporary in-memory provider.

Security notes:
- This backend is not a TEE and does not offer hardware-backed guarantees. It is acceptable for development/CI and Linux desktop use. For production Linux servers, consider dedicated HSM/KMS integration later.

### Windows backend (later)

Approach: Use Windows Credential Manager via the `keyring` crate to store the AES-256 key; perform AEAD in Rust with `aes-gcm`.

Crates and features:
- `keyring` optional dep, feature `windows-keystore` to enable the backend.

API and AAD:
- Same as Linux; reuse `DeviceKeystore` with a `WindowsDeviceKeystore` implementation.

### Open items

- Finalize error taxonomy for keystore failures (transient vs permanent).
- Decide on key rotation policy and versioning for the AEAD key material.
- Add metrics hooks for persistence success/failure rates.


