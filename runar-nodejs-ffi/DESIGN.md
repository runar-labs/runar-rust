# runar-nodejs-ffi: NodeJS/TypeScript Node + Serializer over runar_ffi

Goal: Implement the Node runtime and serializer in TypeScript for CI and E2E coverage, binding to the Rust core (keys + transporter) exposed by `runar_ffi`.

- Crates used via FFI: `runar_ffi` (exposes `runar-keys` + `runar-transporter`)
- JS packages (proposed):
  - `@runar/ffi` – thin dynamic loader/bindings for `runar_ffi` (C ABI)
  - `@runar/serializer` – TypeScript serializer with decorators (envelope construction, metadata)
  - `@runar/node` – TypeScript node runtime (services, messaging, discovery integration)

## Architecture

- FFI Binding Strategy
  - Use `node-ffi-napi` and `ref-napi` to call `runar_ffi` C functions directly
  - Map pointers to `void*` handles (`FfiKeysHandle`, `FfiTransportHandle`) as opaque Buffer pointers
  - All complex payloads as `Buffer` containing canonical CBOR per `runar_ffi/DESIGN.md`
  - Memory management:
    - Returned buffers -> copy into Node Buffers, then call `rn_free(ptr,len)`
    - Returned strings -> `rn_string_free(char*)`
  - Errors:
    - Every FFI call passes `RnError*` (allocated on the JS side); on non-zero return, convert to JS Error with code+message
    - Fallback: `rn_last_error(out, out_len)` for last-error diagnostics

- Runtime
  - Shared Tokio runtime is owned by `runar_ffi` (Option C); Node does not embed any Rust runtime
  - Event delivery via polling: a lightweight JS loop calls `rn_transport_poll_event` on a timer or in a Worker thread to avoid blocking the main loop
  - Optional future: callback-based delivery (not required for v1)

- Node Lifecycle (TS)
  - Keys
    - Create keys handle: `rn_keys_new`
    - State persistence: export/import state CBOR; host encrypts with OS keyring (or configurable key) and stores blob
  - Transport
    - Construct via `rn_transport_new_with_keys` with options CBOR
    - Start/Stop with `rn_transport_start/stop`
    - Connectivity: `connect_peer`, `disconnect_peer`, `is_connected`
    - Messaging: `request`, `publish`, `complete_request`
    - Local info updates: `update_local_node_info`
  - Events (poll):
    - `PeerConnected`, `PeerDisconnected`, `RequestReceived`, `EventReceived`, `ResponseReceived`
    - All as CBOR buffers decoded in JS to typed objects

## TypeScript Serializer (Decorators)

- Requirements
  - Provide an ergonomic TS equivalent to `runar-serializer-macros` using decorators for encryption metadata
  - Use `experimentalDecorators` + `emitDecoratorMetadata` with `reflect-metadata`

- Decorator API (proposal)
  - `@EncryptedClass(options?: { network?: string })` – marks a class as encrypted entity
  - `@EncryptedField(options?: { label?: string; profileRecipients?: (() => Buffer[]) })` – marks an encrypted field; optional label maps to label resolver
  - `@PlainField()` – explicit opt-out field when needed
  - Metadata Registry: runtime map of class -> fields and encryption policy

- Serialization Flow
  - `serialize(entity): Buffer` -> produce CBOR map with schema version, metadata and plain fields; gather encrypted fields into a payload structure
  - `encryptEnvelope(data: Buffer, opts): Buffer` -> uses FFI (keys) to produce Envelope (EED) CBOR
    - v1: Add envelope helpers to `runar_ffi` (rn_keys_encrypt_with_envelope / rn_keys_decrypt_envelope)
    - Fallback: call request/response transport-level encrypt if available (not preferred)
  - `deserialize(Buffer): any` -> parse envelope, call FFI decrypt, reconstruct object and assign fields

- Label Resolver & Profiles
  - TS side provides label mapping for field labels to label identifiers (strings); transported to Rust only if needed
  - Recipients: pass profile public keys (Buffers) and optional network id to FFI envelope encrypt

## Package Layout (Node)

- `@runar/ffi`
  - Loads the platform-specific `runar_ffi` (`.so/.dylib/.dll`) built by Rust
  - Provides typed wrappers for each C function with Buffer/boolean/string conversions
  - Handles pointer lifetime and frees returned buffers
  - Exports CBOR schema helpers and error class (`RnError`)

- `@runar/serializer`
  - Exports decorators and serializer API
  - Depends on `@runar/ffi` for envelope encrypt/decrypt
  - Minimal runtime-only metadata registry

- `@runar/node`
  - Exposes the JavaScript node runtime:
    - Keys manager host (state save/restore via host keystore)
    - Transport lifecycle
    - Event loop/poller (Worker thread recommended)
    - High-level request/response API for services
  - Converts typed TS models to CBOR and back

## Build & Distribution

- Build artifacts
  - The Rust workspace builds `librunar_ffi` for each target; CI publishes per-OS/arch artifacts
  - `@runar/ffi` looks up the correct binary (from packaged artifacts or user override path)
  - Use `prebuildify` or similar for packaging artifacts per platform

- Testing
  - Vitest tests spin up two transports with temporary ports, exchange requests, and assert event sequencing
  - State persistence test: export CBOR, encrypt with Node keyring-based AES-GCM (optional), import and resume

## Error Handling & Safety

- All FFI calls wrap error out; when non-zero, throw `RunarFfiError { code, message }`
- Use `rn_last_error` for diagnostics when message not provided
- Ensure all returned buffers are freed with `rn_free` and strings with `rn_string_free`

## Security Defaults

- Use strict TLS/PKI via keys; never expose insecure verifiers
- Message size/timeouts come from options CBOR; defaults set in Rust

## Task Checklist

- Bootstrapping
  - [ ] Create `@runar/ffi` (TS) with bindings to `runar_ffi`
  - [ ] Implement memory/error helpers; map C types to `ref-napi` types
  - [ ] Provide dynamic loader with platform resolution and override env

- Transport bridge (TS wrappers)
  - [ ] Wrap: new_with_keys/free/start/stop/local_addr
  - [ ] Wrap: connect_peer/disconnect/is_connected
  - [ ] Wrap: request/publish/complete_request
  - [ ] Wrap: update_local_node_info
  - [ ] Poller loop: decode CBOR events to typed TS objects

- Keys bridge (TS wrappers)
  - [ ] Wrap: keys_new/free/node_get_public_key/node_get_node_id
  - [ ] Wrap: node_generate_csr/mobile_process_setup_token/node_install_certificate
  - [ ] Wrap: node_export/import_state, mobile_export/import_state
  - [ ] (v2) Envelope helpers: encrypt_with_envelope/decrypt_envelope

- Serializer (`@runar/serializer`)
  - [ ] Decorator metadata registry using `reflect-metadata`
  - [ ] Serialize/deserialize to canonical CBOR
  - [ ] Envelope encryption/decryption via `@runar/ffi` (when available)

- Node runtime (`@runar/node`)
  - [ ] Keys + Transport lifecycle
  - [ ] Event dispatcher to user callbacks or Rx stream
  - [ ] High-level request/response API in TS

- CI
  - [ ] Build `runar_ffi` binaries per OS/arch in Rust CI and publish artifacts
  - [ ] Node CI consumes artifacts, runs Vitest e2e

## Notes

- Keep JS glue minimal; push crypto and networking to `runar_ffi`
- Prefer Buffers and CBOR end-to-end; avoid JSON in hot paths
- Use Workers for event polling if main thread needs to stay responsive


