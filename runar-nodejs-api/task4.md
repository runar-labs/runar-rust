## Goals
Implement the transporter `/home/rafael/Development/runar-rust/runar-transporter/src/transport/quic_transport.rs` API in NodeJS using proper NAPI best practices.

Logger and other shared/common types lifecycle should follow the same patterns used in the FFI `/home/rafael/Development/runar-rust/runar-ffi`.

The actual transporter API in TypeScript should expose callbacks that mimic the actual QuicTransporter API.

## Design Decision: Polling Pattern (Like Swift/FFI)

After analyzing the requirements and the proven FFI implementation, **we adopt the FFI polling pattern** used successfully by Swift:

### Why Polling Over ThreadsafeFunction?

1. **Proven in Production**: FFI uses polling successfully (Swift, potentially Kotlin)
2. **Simplicity**: Much simpler Rust implementation without ThreadsafeFunction complexity
3. **Reliability**: No risks of TSFN queue overflows, callback lifetime issues, or subtle threading bugs
4. **Code Reuse**: Same architecture as FFI means same behavior, same bug fixes
5. **Testability**: Easier to test and debug
6. **Performance**: Polling overhead (0-10ms) is negligible compared to QUIC operations (10-100ms+)

### Architecture Overview

**Rust/NAPI Layer**: Expose simple polling functions (like FFI)
- `pollEvent()`: Returns CBOR-encoded events (requests, events, peer notifications)
- `completeRequest()`: Complete pending requests by request_id
- Bridge Rust callbacks to mpsc channel (exactly like FFI)

**TypeScript Layer**: Wrap polling with clean callback-based API
- Internal polling loop (setInterval at 10ms)
- Decode CBOR events and dispatch to registered callbacks
- Handle request timeouts
- Provide idiomatic TypeScript API

**See Documentation:**
- `TRANSPORTER_DESIGN.md` - Complete design specification with architecture, APIs, and event formats
- `IMPLEMENTATION_PLAN.md` - Detailed implementation tasks with timeline and file structure


### Detailed Design: NodeJS Transporter Callback Bridge (napi-rs v3)

#### 1) Rust API surface to mirror (callbacks semantics)

```179:201:runar-transporter/src/transport/mod.rs
/// Callback type for message handling with future
pub type MessageCallback =
    Arc<dyn Fn(NetworkMessage) -> BoxFuture<'static, Result<()>> + Send + Sync>;

/// Callback type for connection status changes
pub type ConnectionCallback =
    Arc<dyn Fn(String, bool) -> BoxFuture<'static, Result<()>> + Send + Sync>;

pub type PeerConnectedCallback =
    Arc<dyn Fn(String, NodeInfo) -> BoxFuture<'static, ()> + Send + Sync>;

pub type PeerDisconnectedCallback = Arc<dyn Fn(String) -> BoxFuture<'static, ()> + Send + Sync>;

pub type GetLocalNodeInfoCallback =
    Arc<dyn Fn() -> BoxFuture<'static, Result<NodeInfo>> + Send + Sync>;

// REMOVED: RequestMessage, ResponseMessage, EventMessage - using NetworkMessage directly

pub type RequestCallback =
    Arc<dyn Fn(NetworkMessage) -> BoxFuture<'static, Result<NetworkMessage>> + Send + Sync>;

pub type EventCallback =
    Arc<dyn Fn(NetworkMessage) -> BoxFuture<'static, Result<()>> + Send + Sync>;
```

- **Required JS parity**:
  - **onRequest**: receives a request and must cause a response to flow back to Rust.
  - **onEvent**: fire-and-forget notification.
  - **onPeerConnected**: notification with `(peer_id, node_info)`.
  - **onPeerDisconnected**: notification with `(peer_id)`.
  - **getLocalNodeInfo**: internal callback returning `NodeInfo`.

#### 2) NodeJS API surface (TypeScript)
- Expose the already-declared `Transport` methods in `index.d.ts`:
  - **Callback registration**: `onRequest`, `onEvent`, `onPeerConnected`, `onPeerDisconnected`, plus removal methods and `setCallbackTimeout/getCallbackTimeout`.
  - **Request/Publish**: `request(...) -> Promise<Uint8Array>`, `publish(...) -> Promise<void>`.
  - **Peer mgmt**: `connectPeer`, `isConnected`, `isConnectedToPublicKey`.
  - **Utilities**: `getLocalAddr`, `updatePeers`, `start`, `stop`, `completeRequest(...)`.

#### 3) Bridge strategy
- Use `napi::ThreadsafeFunction<T, ErrorStrategy::CalleeHandled>` with `ThreadsafeFunctionCallMode::NonBlocking` for all fire-and-forget callbacks (event/peer). Keep `T` simple: structs composed of `String`, `Vec<u8>`, and `Vec<Vec<u8>>` which map cleanly to JS via `Uint8Array` and arrays.
- For request callbacks (which must return a value to Rust), do NOT wait for a JS return from `ThreadsafeFunction`. Instead, mirror the FFI proven pattern:
  - Generate a `request_id` inside Rust request handler.
  - Insert a `oneshot::Sender<NetworkMessage>` into a concurrent `pending_requests` map keyed by `request_id`.
  - Deliver a JS-facing event via `ThreadsafeFunction` carrying all request fields + `request_id`.
  - JS code will later call exported `completeRequest(request_id, payload, profilePublicKeys)` to fulfill the pending request; Rust looks up the sender and replies to the original transport.

This ensures correctness and avoids misusing `ThreadsafeFunction` for roundtrips.

#### 4) CallbackManager design (Rust side)
- Single `CallbackManager` held behind `Arc<Mutex<...>>` in the addon state.
- Fields:
  - `request_tsfn: Option<ThreadsafeFunction<RequestEnvelope, CalleeHandled>>`
  - `event_tsfn: Option<ThreadsafeFunction<EventEnvelope, CalleeHandled>>`
  - `peer_connected_tsfn: Option<ThreadsafeFunction<PeerConnectedEnvelope, CalleeHandled>>`
  - `peer_disconnected_tsfn: Option<ThreadsafeFunction<PeerDisconnectedEnvelope, CalleeHandled>>`
  - `callback_timeout_ms: u64`
  - `pending_requests: DashMap<String, oneshot::Sender<NetworkMessage>>`
- Envelopes contain only simple fields: `String`, `Vec<u8>`, `Vec<Vec<u8>>`, numbers.
- Provide registration/removal methods called by `onRequest/onEvent/...` that:
  - Create a `ThreadsafeFunction` from the `JsFunction` provided by the user.
  - Store it atomically, replacing any existing instance (and dropping the old TSFN to release).
  - For removal, set the field to `None`.

#### 5) Creating ThreadsafeFunction correctly (napi v3)
- Use the correct API in napi-rs v3 (crate: `napi = "3"`):
  - Create TSFN from a `JsFunction` and `Env`, specifying queue size and `ThreadsafeFunctionCallMode`.
  - Use `call(Ok(payload), NonBlocking)` to schedule delivery.
- Do not attempt to read return values from TSFN; it only returns a `Status` for the scheduling outcome.

#### 6) Invocation flows
- Request flow (Rust -> JS -> Rust):
  1. Transport invokes `request_callback(NetworkMessage)`.
  2. The bridge constructs `RequestEnvelope` and creates a `request_id` (UUID v4) tied to a `oneshot::Sender` inserted into `pending_requests`.
  3. Invoke `request_tsfn.call(Ok(envelope), NonBlocking)`.
  4. JS handler eventually computes a response and calls `completeRequest(request_id, response_payload, profile_public_keys)`.
  5. The addon looks up `pending_requests.remove(request_id)` and sends a `NetworkMessage` via the `oneshot::Sender` to complete the original Rust `RequestCallback` future.
  6. On timeout (no completion within `callback_timeout_ms`), remove the entry and complete with a default/empty response consistent with the FFI behavior.

- Event flow (Rust -> JS):
  - Build `EventEnvelope` and call `event_tsfn.call(Ok(envelope), NonBlocking)`.

- Peer connected/disconnected (Rust -> JS):
  - Build `PeerConnectedEnvelope` / `PeerDisconnectedEnvelope` with simple fields; call the corresponding TSFN.

- Get local node info (Rust-only):
  - Use the existing Rust closure to return `NodeInfo` synchronously-as-async; no JS bridge needed.

#### 7) Data model for envelopes (Rust <-> JS)
- RequestEnvelope:
  - `request_id: String`
  - `path: String`
  - `correlation_id: String`
  - `payload: Vec<u8>`
  - `source_node_id: String`
  - `destination_node_id: String`
  - `profile_public_keys: Vec<Vec<u8>>`
  - `network_public_key: Option<Vec<u8>>`
- EventEnvelope: same as request without `request_id`.
- PeerConnectedEnvelope:
  - `peer_id: String`
  - `node_info: NodeInfoFlat` (flatten to simple fields: `node_public_key: Vec<u8>`, `network_ids: Vec<String>`, `addresses: Vec<String>`, `version: u32`, plus simple `node_metadata` fields)
- PeerDisconnectedEnvelope:
  - `peer_id: String`

Flattening avoids passing complex Rust types across TSFN; the JS side reconstructs the `index.d.ts` shapes (`TransportRequest`, `TransportEvent`).

#### 8) Public addon methods mapping
- `onRequest(cb)`: store new `request_tsfn`; set a boolean `js_request_callback_registered = true`.
- `onEvent(cb)`: store `event_tsfn`.
- `onPeerConnected(cb)`: store `peer_connected_tsfn`.
- `onPeerDisconnected(cb)`: store `peer_disconnected_tsfn`.
- Removal methods: set corresponding field to `None` and `registered` flag to false.
- `setCallbackTimeout(ms)` / `getCallbackTimeout()` update/read `callback_timeout_ms`.
- `completeRequest(request_id, payload, profile_public_keys)`: complete pending request.

All these methods manipulate only the `CallbackManager`; they do not touch the transport internals beyond completing the `oneshot`.

#### 9) Concurrency, safety, and performance
- Use `DashMap<String, oneshot::Sender<NetworkMessage>>` for `pending_requests` to avoid holding locks across awaits and to enable lock-free reads.
- Clone `Arc<Logger>`, `Arc<ThreadsafeFunction<...>>`, and other Arcs before async blocks; never hold a mutex guard across `.await`.
- Use `ThreadsafeFunctionCallMode::NonBlocking` to avoid blocking the libuv thread.
- Size the TSFN queue appropriately (e.g., `max_queue_size = 1024`) and handle backpressure: if `call` returns an error status, log once per interval and drop the event; never spin.
- Avoid unnecessary allocations: build envelopes with `with_capacity` for vectors when sizes are known; pass references where possible internally.

#### 10) Error handling and timeouts
- TSFN `.call(...)` returns a status: on failure, log an error with single-line structured context and continue.
- For requests, implement a timeout (default 5s, configurable) using `tokio::time::timeout` around the `oneshot::Receiver`. On timeout, remove the entry and return a default empty response (consistent with the FFI fallback) so the transport does not hang.
- Do not double-log errors: propagate structured errors upward where appropriate.

#### 11) Alignment with existing FFI pattern
- The request roundtrip mirrors the FFI implementation (generate request_id, send event, await `completeRequest`). Ensure channel sends use `.await` where required internally to avoid race conditions discovered previously.
- The event and peer notifications are fire-and-forget via TSFN, no waits.

#### 12) Lifecycle & teardown
- On `Transport.stop()` or addon drop:
  - Set `running = false`.
  - Clear all TSFNs by setting to `None` so napi can release them.
  - Drain `pending_requests`: send default responses to avoid dangling futures.
- Ensure `CallbackManager` outlives the transport tasks and is owned by the addon root.

#### 13) Implementation checklist (one change at a time)
- Add `CallbackManager` with TSFN fields and `pending_requests` map.
- Implement registration/removal methods; validate only one active TSFN per callback type.
- Bridge the transporter callbacks to use the manager (including `.await` on any internal channel sends where applicable).
- Implement `completeRequest(...)` to resolve awaiting senders.
- Flatten `NodeInfo` into simple fields for TSFN payloads.
- Add comprehensive tests in TS mirroring FFI transport tests; include timeout assertions (≤ 45s) and ensure all callbacks fire and request completion works.

#### 14) Success criteria
- All JS callbacks are invoked from real Rust events via TSFN, without logs-only placeholders.
- Request callbacks complete via `completeRequest` reliably under load and with timeouts.
- No deadlocks or awaits while holding locks; no queue overflows; no data races.
- `cargo check`, clippy, and tests pass; no absolute path violations; formatted code.

---

## Design Comparison: Polling vs ThreadsafeFunction

### Original Approach (ThreadsafeFunction - This Document Above)

**Architecture:**
- Use `napi::ThreadsafeFunction<T, ErrorStrategy::CalleeHandled>` to bridge Rust callbacks directly to JS
- For requests: Generate request_id, use TSFN to deliver request, await `completeRequest()` via oneshot channel
- For events: Fire-and-forget via TSFN
- For peer notifications: Fire-and-forget via TSFN

**Pros:**
- Direct callback invocation (no polling loop)
- Potentially lower latency (0ms vs 0-10ms)

**Cons:**
- **Complex**: ThreadsafeFunction API is tricky to use correctly
- **Risk of queue overflow**: TSFN has fixed queue size, can drop events under load
- **Callback lifetime issues**: Hard to manage TSFN lifecycle correctly
- **No code reuse**: Different from FFI, must maintain two implementations
- **Hard to test**: TSFN behavior hard to unit test
- **Hard to debug**: Subtle threading bugs possible
- **Not proven**: No production usage in our codebase

### Adopted Approach (Polling - See TRANSPORTER_DESIGN.md)

**Architecture:**
- Use `mpsc::channel` to collect events (exactly like FFI)
- Expose `pollEvent()` NAPI method that calls `rx.try_recv()`
- TypeScript wrapper polls at 10ms interval via `setInterval`
- Decode CBOR and dispatch to user callbacks

**Pros:**
- **Simple**: Straightforward Rust and TypeScript code
- **Proven**: Used successfully in FFI (Swift, potentially Kotlin)
- **Reliable**: No queue overflow (unbounded mpsc), no TSFN lifetime issues
- **Code reuse**: Same architecture as FFI, bug fixes benefit both
- **Easy to test**: Can unit test polling, event dispatch, timeouts independently
- **Easy to debug**: Clear separation, easy to trace events
- **Robust**: No subtle threading bugs

**Cons:**
- Polling overhead: 0-10ms added latency
- Small CPU overhead (try_recv in loop)

### Performance Analysis

**QUIC Operations Baseline:**
- Network RTT: 1-100ms
- TLS handshake: 10-50ms
- Request processing: 1-100ms+

**Polling Overhead:**
- 10ms polling interval
- Worst case: 10ms added latency
- Best case: 0ms (event ready immediately)
- Average: 5ms added latency

**Conclusion:** 5ms average added latency is **negligible** compared to QUIC operations (10-100ms+). The reliability and simplicity benefits far outweigh this small overhead.

### Decision

**We adopt the polling approach** for the following reasons:

1. **Proven reliability** (FFI production usage)
2. **Simplicity** (easier to implement and maintain)
3. **Code reuse** (share architecture with FFI)
4. **Testability** (much easier to test)
5. **Negligible performance impact** (5ms vs 10-100ms operations)

The ThreadsafeFunction approach is **not recommended** due to complexity, reliability risks, and lack of code reuse benefits.

---

## POC Implementation Status ✅

**POC Created and Tested Successfully!**

### Files Created:
- `src/transport_poc.rs` - Rust/NAPI polling implementation
- `src/transport_poc_wrapper.ts` - TypeScript wrapper with callback API
- `tests/transport_poc.test.ts` - Comprehensive test suite (16 tests)

### Test Results: **16/16 PASS** ✅

```
✅ Basic lifecycle (start/stop)
✅ Request callback flow
✅ Multiple concurrent requests (3 simultaneous)
✅ Request timeout handling (100ms timeout)
✅ Callback error handling
✅ Event callback flow
✅ Multiple events
✅ Polling configuration
✅ Pending requests tracking
✅ High-frequency requests (50 concurrent)
✅ Acceptable latency (<50ms)
```

### Key Findings:
- ✅ Polling pattern works reliably
- ✅ Request/response roundtrip functions correctly
- ✅ Timeout handling works as expected
- ✅ Error handling is robust
- ✅ Performance is acceptable (handled 50 concurrent requests)
- ✅ Latency overhead is negligible

### Recommendation: **PROCEED WITH FULL IMPLEMENTATION**

**Next Steps:**
1. ✅ POC validated - polling design works
2. Integrate with real QuicTransport (replace simulate methods)
3. Complete TypeScript API (add remaining methods)
4. Port FFI transport tests
5. Production deployment

**Note:** The ThreadsafeFunction design above (sections 1-14) is **archived for reference only**. The POC proves the polling pattern is the correct approach.