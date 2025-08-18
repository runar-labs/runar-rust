

I reviewed the current `runar-transporter` public surface (`lib.rs`, `transport/*`, `discovery/*`, `network_config.rs`) for FFI readiness and long-term cross-platform stability. Below are concrete issues, footguns, and a proposed interface shape that will let us expose QUIC transport and discovery via a robust, minimal, CBOR-first FFI while keeping node behavior in native code.

### What’s good already
- **Clear separation**: Discovery and transport are separate modules (`discovery` vs `transport`), and transport exposes node-level callbacks for requests/events/peer state without embedding node semantics.
- **CBOR on the wire**: Network framing already uses CBOR for `NetworkMessage`/`HandshakeData`. That aligns with our FFI plan to pass complex values as CBOR bytes.
- **Asynchrony model**: Transport’s interface is futures-based and callback-capable; QUIC implementation has well-structured accept/request/publish flows, duplicate-connection resolution, and micro-retry/backoff.
- **TLS/QUIC grounding**: Uses Quinn/Rustls with clear places to plug in runar-keys for certs/PKI.

### FFI readiness review: gaps and footguns
- **Traits and generics across FFI**: `NetworkTransport` and `NodeDiscovery` are Rust traits with async methods and trait-object callbacks. These cannot be exported across a C ABI. We need a handle-based API with `extern "C"` functions.
- **Rust types in options**: `SocketAddr`, `Duration`, `Option<T>`, `Vec<String>`, `CertificateDer<'static>`, `PrivateKeyDer<'static>` are not FFI-friendly. They must not cross FFI boundaries.
- **Callback shape**: Current callbacks are `Arc<dyn Fn(...) -> Future>`. This is not safe to call across FFI threads or runtimes (Node/Swift/Kotlin). We need a host-thread-safe event bridge:
  - Either polling: host calls `poll_next_event(handle, out_buf)` to drain a queue
  - Or C ABI callbacks: `extern "C" fn(ctx, ...)` invoked by a single-threaded FFI dispatcher
- **Blocking cross-FFI response path**: `request_callback` currently returns `ResponseMessage`. In JS/Swift/Kotlin this can deadlock or violate threading. We need a deferred-completion model:
  - Deliver `RequestReceived {request_id, cbor_bytes}` event to host
  - Host later calls `complete_request(handle, request_id, response_cbor_bytes)`
- **Security verifier footgun**:
  - `SkipServerVerification` and `dangerous().with_custom_certificate_verifier(...)` are present. The custom verifier only checks SAN/CN equals node-id; it does not validate chain/trust/expiry/revocation. This must be behind a feature gated to tests/dev-only and off by default. Production must validate with runar-keys PKI.
- **Message size limit inconsistency**: `read_message` caps to 1MB hard, while `TransportOptions.max_message_size` exists but isn’t enforced. Align the framing limit with configured `max_message_size`.
- **Inconsistent message types**: Both `NetworkMessageType` enum and numeric constants (e.g., `MESSAGE_TYPE_REQUEST`) exist; code uses only numeric constants. Remove or gate the enum; standardize on numeric codes for wire/FFI stability.
- **Payload model mismatch**: Comment says “List of payloads,” but `NetworkMessage` contains a single `payload: NetworkMessagePayloadItem`. Fix comment or introduce a vector; for FFI, prefer a single payload per message for simplicity.
- **Address handling**: `connect_peer` uses only the first address in `PeerInfo.addresses`. Prefer iteration with fallback/backoff across addresses.
- **Hard-coded timeouts**: A 2s handshake reply timeout is hard-coded. Move it to options for FFI control.
- **Tokio runtime ownership**: The crate assumes a Tokio runtime exists. For FFI clients, we need a contained runtime owned by the transporter and a clean shutdown path.
- **Memory ownership**: No allocator/free helpers are defined. For cross-language buffers we must expose `alloc/free` or host-managed buffers to avoid leaks and UB.
- **Logging**: Currently uses `Logger` macros. FFI hosts will want either:
  - A C callback sink with level filtering; or
  - A simple level-config and stdout/stderr output.
- **Discovery portability**: UDP multicast is not always available (iOS entitlements, Android permissions, enterprise networks). Treat multicast as optional. FFI must allow zero discovery providers without breaking transport.

### Separation of concerns (final target)
- **Transport layer (Rust)**: QUIC connections, handshake, message framing, retries, backoff, connection liveness, peer map, request/response delivery, event publish, encryption hook points (runar-serializer + runar-keys).
- **Discovery layer (Rust)**: Emits discovery events (discovered/updated/lost) only; no peer registry/tie-breaking baked in.
- **Node layer (native)**: Service routing, correlation management beyond transport, request handling logic, retries above transport if desired, application logging, metrics.
- **Crypto/PKI (Rust)**: runar-keys for cert chain creation/validation, key storage; runar-serializer for envelope encryption. Transport trusts this layer via opaque handles.

### Proposed FFI surface (C ABI, CBOR-first)
Add a sibling crate `runar-transporter-ffi` (feature `ffi`) with `#[no_mangle] extern "C"` functions and `#[repr(C)]` types. Everything async must be callback- or queue-driven.

- Handles and lifecycle
  - `TransportHandle* runar_transport_new(const uint8_t* options_cbor, size_t options_len, ErrorOut* err)`
  - `void runar_transport_free(TransportHandle*)`
  - `int runar_transport_start(TransportHandle*, ErrorOut* err)`
  - `int runar_transport_stop(TransportHandle*, ErrorOut* err)`
  - `const char* runar_transport_local_addr(TransportHandle*)` + `void runar_string_free(const char*)`
  - Optionally: `RuntimeHandle* runar_runtime_new()` / implicit per-transport runtime

- Options (CBOR)
  - All complex configs are CBOR-blobs:
    - `QuicTransportOptionsFFI`: bind_addr string; idle/keepalive ms; handshake_timeout_ms; max_message_size; response_cache_ttl_ms; max_request_retries; cert_chain_der[]; private_key_der; root_certs_der[]; mode flags (insecure_dev, etc.); logging level; optional keystore and label resolver handles or parameters needed to construct them.
    - Discovery config: array of providers. For multicast: group string, interval_ms, timeout_ms, ttl, local_only flag.
  - This keeps the FFI stable and delegates schema evolution to CBOR.

- Discovery
  - `DiscoveryHandle* runar_discovery_new(const uint8_t* options_cbor, size_t len, ErrorOut* err)`
  - `int runar_discovery_start(DiscoveryHandle*, ErrorOut* err)`
  - `int runar_discovery_stop(DiscoveryHandle*, ErrorOut* err)`
  - Event delivery:
    - Callback registration: `runar_discovery_set_listener(DiscoveryHandle*, DiscoveryCallback cb, void* ctx)`
      - Event payload: CBOR `DiscoveryEventFFI { kind: u8, peer_info_cbor?: bytes, peer_id?: string }`
    - Or polling: `int runar_discovery_poll_event(DiscoveryHandle*, OutBuf*)`

- Transport operations
  - Connection:
    - `int runar_transport_connect_peer(TransportHandle*, const uint8_t* peer_info_cbor, size_t len, ErrorOut* err)` where CBOR is `PeerInfo { public_key: bytes, addresses: [string] }`
    - `int runar_transport_disconnect_peer(TransportHandle*, const char* peer_node_id, ErrorOut* err)`
    - `bool runar_transport_is_connected(TransportHandle*, const char* peer_node_id)`
  - Messaging:
    - Request (async): `int runar_transport_request(TransportHandle*, const char* path, const char* correlation_id, const uint8_t* payload, size_t payload_len, const char* dest_peer_id, const uint8_t* profile_pk, size_t pk_len, ErrorOut* err)`
      - Completion via callback: `runar_transport_on_response(TransportHandle*, ResponseCallback cb, void* ctx)` with CBOR response bytes; or
      - Polling: `runar_transport_poll_event` with an event type `ResponseReceived`
    - Publish: `int runar_transport_publish(TransportHandle*, const char* path, const char* correlation_id, const uint8_t* payload, size_t payload_len, const char* dest_peer_id, ErrorOut* err)`
  - Requests IN from network:
    - Delivery via event queue: `RequestReceived { request_id, path, correlation_id, payload, profile_public_key }`
    - Host completes: `int runar_transport_complete_request(TransportHandle*, const char* request_id, const uint8_t* response_payload, size_t len, const uint8_t* profile_pk, size_t pk_len, ErrorOut* err)`
    - This avoids blocking a cross-FFI callback awaiting a future on a host runtime (critical for JS/Swift/Kotlin).
  - Peer events:
    - `PeerConnected { peer_node_id, node_info_cbor }`
    - `PeerDisconnected { peer_node_id }`
  - Node info updates:
    - `int runar_transport_update_local_node_info(TransportHandle*, const uint8_t* node_info_cbor, size_t len, ErrorOut* err)`

- Logging
  - `void runar_set_log_callback(LogCallback cb, void* ctx)`
  - Or simple: `void runar_set_log_level(int level)`

- Memory and errors
  - `#[repr(C)] struct OutBuf { uint8_t* ptr; size_t len; }`
  - `void runar_free(OutBuf)`
  - `#[repr(C)] struct ErrorOut { int code; const char* message; }` with `void runar_string_free(const char*)`
  - Numeric `ErrorCode` instead of strings across FFI; string retrieval optional for diagnostics.

### Changes to make in `runar-transporter` before (or during) FFI
- **Introduce an FFI-safe event queue**:
  - Internally, replace direct node callbacks with an event bus abstraction with bounded channels.
  - Keep current Rust callbacks for in-Rust usage, but FFI path goes through the queue.
- **Add a deferred request path**:
  - Internally route inbound requests to the queue and allow response completion via a map keyed by `request_id` with a oneshot sender. Keep current callback path for pure-Rust users.
- **Gate insecure TLS**:
  - Move `SkipServerVerification` and the `dangerous()` verifier under a feature like `insecure_dev`. Default: strict verification via runar-keys PKI.
- **Respect configured message size**:
  - Use `TransportOptions.max_message_size` to validate both inbound and outbound frames.
- **Use all addresses in `PeerInfo`**:
  - Iterate addresses on connect with backoff/jitter until one succeeds; optionally shuffle to avoid thundering herd.
- **Time-outs in options**:
  - Expose `handshake_response_timeout_ms`, `open_stream_timeout_ms` in options; remove hard-codes.
- **Stabilize message types**:
  - Remove or hide `NetworkMessageType` enum; keep numeric codes only and document them.
- **Fix payload comment**:
  - Update `NetworkMessage` doc-comment to “single payload” or extend to a vector consistently.
- **Tokio runtime containment**:
  - Create an owned runtime per transport (or shared `RuntimeHandle`) and ensure `stop()` drains tasks predictably. Provide clean shutdown for FFI.
- **Logging adapter**:
  - Add a pluggable sink that can proxy to host callback or stdout depending on configuration.
- **Tighten Display/Debug**:
  - Avoid printing sensitive material (keys) in logs. Ensure no accidental secrets are logged.

### CBOR schemas to standardize (host-facing)
- `PeerInfo { public_key: bytes, addresses: [string] }`
- `NodeInfo` (already present in `runar-schemas`): must be versioned and stable for FFI
- `QuicTransportOptionsFFI`: flat struct, numbers/strings/bytes only
- Events:
  - `RequestReceived { request_id, path, correlation_id, payload, profile_public_key, source_peer_id }`
  - `ResponseReceived { correlation_id, payload, source_peer_id }` (for client-side requests)
  - `PeerConnected { peer_node_id, node_info }`
  - `PeerDisconnected { peer_node_id }`
  - `DiscoveryEvent { kind: u8, peer_info?, peer_id? }`

### Platform-specific notes
- iOS/macOS:
  - QUIC over UDP is fine but ensure entitlement/networking constraints; multicast requires Local Network permission on iOS and may be filtered—must be optional.
- Android:
  - Multicast requires `CHANGE_WIFI_MULTICAST_STATE`. Provide opt-out and static discovery provider alternative.
- Node/Bun:
  - Favor polling-based API or a single-threaded dispatch thread that forwards to N-API. Avoid invoking V8 from arbitrary threads.

### Dependency/size cleanup
- `tokio-tungstenite`, `bincode`, `prost` aren’t used by current transport/discovery. Consider removing to reduce binary size for mobile.
- Keep `serde_cbor`, `quinn`, `rustls`, `x509-parser`, `dashmap`.

### Testing and safety
- Add FFI tests with a small C harness (build in CI) to validate:
  - Create/start/stop transport, request/publish round-trip, discovery event flow, memory ownership.
- Fuzz the CBOR decoders for `NetworkMessage` and `HandshakeData`.

### Next steps I suggest
- Add a new `runar-transporter-ffi` crate and wire a minimal handle-based surface as described.
- Implement the internal event queue and deferred-request completion path.
- Gate insecure TLS with a feature and integrate runar-keys verification hooks by default.
- Align message size checks with options; make handshake timeouts configurable.
- Iterate addresses in `connect_peer`; expose `connect_timeout_ms` in options.
- Provide header generation (cbindgen) and minimal Swift/Kotlin/Node sample bindings.

Summary
- Converted the current trait-based API into a concrete FFI plan: opaque handles, CBOR for all complex values, event queue + deferred request completion, and explicit memory/error contracts.
- Flagged key footguns: insecure cert verifier, hard-coded timeouts, size-limit mismatch, single-address connect, and cross-FFI async callback risks.
- Proposed small transport changes to stabilize the wire contract and options, plus discovery portability and runtime ownership for safe multi-platform embedding.