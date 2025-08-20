# Runar Node.js API Design

## Overview

This crate, `runar-nodejs-api`, provides Node.js bindings for the Runar system using the `napi-rs` framework. The goal is to expose APIs similar to those in the `runar-ffi` crate, which are used for Swift and Kotlin integrations, but adapted to Node.js best practices. This includes using asynchronous promises for operations that may involve I/O or computation, object-oriented classes for stateful components, proper error handling with JavaScript errors, and TypeScript type definitions for better developer experience.

The design is based on:
- Existing FFI APIs from `runar-ffi/include/runar_ffi.h` and `runar-ffi/src/lib.rs`.
- Node.js API standards: Prefer async APIs, use Buffers for binary data, throw errors for failures.
- napi-rs documentation and best practices: Use `#[napi]` macros for functions and classes, support async with `Promise`, handle threadsafety for shared state, generate `.d.ts` files automatically.

No assumptions are made; all mappings are derived from the FFI signatures and napi-rs capabilities (e.g., from napi-rs docs: https://napi.rs/docs/, emphasizing async patterns, class exports, and error propagation).

## Dependencies

In `Cargo.toml`:
```toml
[dependencies]
napi = { version = \"2\", default-features = false, features = [\"napi8\", \"async\"] }
napi-derive = \"2\"
tokio = { version = \"1\", features = [\"full\"] }  # For async runtime, as in FFI
runar-keys = { path = \"../runar-keys\" }  # Reuse core logic
runar-transporter = { path = \"../runar-transporter\" }
serde_cbor = \"0.11\"  # For CBOR handling, matching FFI
```

Build process: Use `napi build --platform` to generate the `.node` file for Node.js consumption.

## Key Design Principles

- **Asynchronicity**: All potentially blocking or async operations (e.g., network, crypto) return Promises. Sync operations are minimal.
- **State Management**: Use classes like `Keys`, `Transport`, `Discovery` to hold state, mirroring FFI handles (e.g., `RNAPIFfiKeysHandle`).
- **Data Types**:
  - Binary data (e.g., keys, CBOR): Use Node.js `Buffer`.
  - Strings: UTF-8 strings.
  - Errors: Custom `RunarError` extending `Error`, with code and message from `RNAPIRnError`.
- **Error Handling**: Throw `RunarError` with properties matching FFI's `RnError` (code, message).
- **Thread Safety**: Use `napi::threadsafe_function` if needed for callbacks/events, but prefer polling or async awaits.
- **Events**: For polling-based FFI (e.g., `rn_transport_poll_event`), expose an async `pollEvent()` method returning Promise<Buffer | null>.
- **CBOR**: Handle CBOR serialization/deserialization in Rust, exposing Buffers to JS.
- **Platform Considerations**: Skip or adapt platform-specific FFI functions (e.g., Apple/Linux keystores) for Node.js; use Node's `keytar` if needed, but mirror FFI signatures where possible.
- **Best Practices**:
  - Follow napi-rs async patterns: Use `async fn` with `#[napi]`.
  - Generate TypeScript defs: Use `napi build --dts`.
  - Testing: Unit tests in Rust, integration in JS.
  - Performance: Avoid unnecessary copies; use `napi::bindgen_prelude::Buffer`.

## API Mapping

The APIs are grouped into classes corresponding to FFI components.

### RunarError (Custom Error)

Extends `Error`, with `code: number`, `message: string`.

### Keys Class

`#[napi]`
class Keys {
  constructor();  // Creates new KeysInner, similar to `rn_keys_new_return`

  // Persistence
  async setPersistenceDir(dir: string): Promise<void>;  // Maps to `rn_keys_set_persistence_dir_return`
  async enableAutoPersist(enabled: boolean): Promise<void>;  // `rn_keys_enable_auto_persist_return`
  async wipePersistence(): Promise<void>;  // `rn_keys_wipe_persistence_return`
  async flushState(): Promise<void>;  // `rn_keys_flush_state_return`

  // Keystore State
  async nodeGetKeystoreState(): Promise<number>;  // `rn_keys_node_get_keystore_state_return`
  async mobileGetKeystoreState(): Promise<number>;  // `rn_keys_mobile_get_keystore_state_return`
  async getKeystoreCaps(): Promise<{version: number, flags: number}>;  // `rn_keys_get_keystore_caps`

  // Registration (adapt for Node.js; may use stubs or node-specific impl)
  async registerAppleDeviceKeystore(label: string): Promise<void>;  // Stub or skip if not macOS/iOS
  async registerLinuxDeviceKeystore(service: string, account: string): Promise<void>;  // Stub or use keytar

  // Encryption/Decryption
  async encryptWithEnvelope(data: Buffer, networkId: string | null, profilePks: Buffer[]): Promise<Buffer>;  // Returns CBOR EED
  async decryptEnvelope(eedCbor: Buffer): Promise<Buffer>;
  async encryptLocalData(data: Buffer): Promise<Buffer>;
  async decryptLocalData(encrypted: Buffer): Promise<Buffer>;
  async encryptForPublicKey(data: Buffer, recipientPk: Buffer): Promise<Buffer>;  // CBOR EED
  async encryptForNetwork(data: Buffer, networkId: string): Promise<Buffer>;  // CBOR EED
  async decryptNetworkData(eedCbor: Buffer): Promise<Buffer>;
  async encryptMessageForMobile(message: Buffer, mobilePk: Buffer): Promise<Buffer>;
  async decryptMessageFromMobile(encrypted: Buffer): Promise<Buffer>;

  // Mobile/Node Specific
  async mobileInitializeUserRootKey(): Promise<void>;
  async mobileDeriveUserProfileKey(label: string): Promise<Buffer>;  // PK
  async mobileInstallNetworkPublicKey(networkPk: Buffer): Promise<void>;
  async mobileGenerateNetworkDataKey(): Promise<string>;  // Network ID string
  async mobileGetNetworkPublicKey(networkId: string): Promise<Buffer>;  // PK
  async mobileCreateNetworkKeyMessage(networkId: string, nodeAgreementPk: Buffer): Promise<Buffer>;  // CBOR
  async nodeInstallNetworkKey(nkmCbor: Buffer): Promise<void>;
  async nodeGetPublicKey(): Promise<Buffer>;
  async nodeGetNodeId(): Promise<string>;
  async nodeGenerateCsr(): Promise<Buffer>;  // CBOR SetupToken
  async mobileProcessSetupToken(stCbor: Buffer): Promise<Buffer>;  // CBOR NodeCertificateMessage
  async nodeInstallCertificate(ncmCbor: Buffer): Promise<void>;

  // Misc
  setLabelMapping(mappingCbor: Buffer): void;  // Sync, as in FFI
  setLocalNodeInfo(nodeInfoCbor: Buffer): void;  // Sync
}

### Transport Class

`#[napi]`
class Transport {
  constructor(keys: Keys, optionsCbor: Buffer);  // Maps to `rn_transport_new_with_keys_return`

  async start(): Promise<void>;  // `rn_transport_start`
  async pollEvent(): Promise<Buffer | null>;  // `rn_transport_poll_event`, returns CBOR event or null if none
  async connectPeer(peerInfoCbor: Buffer): Promise<void>;
  async disconnectPeer(peerNodeId: string): Promise<void>;
  async isConnected(peerNodeId: string): Promise<boolean>;
  async updateLocalNodeInfo(nodeInfoCbor: Buffer): Promise<void>;
  async request(path: string, correlationId: string, payload: Buffer, destPeerId: string, profilePk: Buffer): Promise<void>;  // Async, response via pollEvent
  async publish(path: string, correlationId: string, payload: Buffer, destPeerId: string): Promise<void>;
  async completeRequest(requestId: string, responsePayload: Buffer, profilePk: Buffer): Promise<void>;
  async stop(): Promise<void>;
  getLocalAddr(): string;  // Sync
}

### Discovery Class

`#[napi]`
class Discovery {
  constructor(keys: Keys, optionsCbor: Buffer);  // `rn_discovery_new_with_multicast_return`

  async init(optionsCbor: Buffer): Promise<void>;  // Optional re-init
  async bindEventsToTransport(transport: Transport): Promise<void>;
  async startAnnouncing(): Promise<void>;
  async stopAnnouncing(): Promise<void>;
  async shutdown(): Promise<void>;
  async updateLocalPeerInfo(peerInfoCbor: Buffer): Promise<void>;
}

## Implementation Notes

- **Async Runtime**: Use a shared Tokio runtime for all async operations, as in FFI.
- **Handle Mapping**: Each class wraps an Arc<Inner> similar to FFI structs (e.g., KeysInner).
- **CBOR Handling**: Use `serde_cbor` in Rust; JS passes/receives Buffers.
- **Events**: Poll-based to match FFI; for more Node.js idiomatic, could add EventEmitter, but stick to poll for consistency.
- **Security**: Ensure all crypto ops are thread-safe; use napi-rs env for JS interactions.
- **Testing**: Mirror FFI tests, add JS integration tests.
- **Packaging**: The crate builds to a `.node` file; publish to npm with prebuilds for platforms.

This design ensures factual mapping from FFI while optimizing for Node.js usage.
