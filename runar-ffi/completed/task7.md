# FFI Transport Events: Typed Structs and Channel Design (Proposal)

## 1) Current Design (Problems)
- Single events channel: `mpsc::Sender<Vec<u8>>` with `Vec<u8>` payloads encoded as CBOR maps.
- Consumers call a single `rn_transport_poll_event` which returns an opaque byte buffer.
- Event producers (discovery binders, transport callbacks, request/response helpers) all serialize heterogeneous maps into the same channel.

Issues:
- ABI/FFI consumers must decode CBOR and switch on map keys; brittle and error-prone.
- No compile-time schema: changes to payload maps break downstream silently.
- Mixed event types compete on the same queue, forcing complex demuxing and priority ambiguity.
- Hard to offer per-type backpressure, buffering, or metrics.
- Testing is cumbersome; payload validation is runtime-only.

## 2) Requirements (as requested)
- Define a proper struct per event type (stable Rust types), but FFI returns CBOR bytes.
- Use a channel per event type: only one data type is sent on that channel.
- Provide one poll method per event type (no generic poll that returns heterogeneous data).
- Keep within FFI crate (no cross-crate changes now).
- Preserve performance, avoid unnecessary allocations, maintain thread-safety, and no panics.

## 3) Event Types (scope in FFI today)
- Peer lifecycle:
  - PeerConnected(node_id, node_info)
  - PeerDisconnected(node_id)
- Discovery events (via bind-to-transport adapter):
  - Discovered(peer_info)
  - Updated(peer_info)
  - Lost(node_id)
- Messaging:
  - Request(received_request)
  - Event(received_event)
  - Response(outgoing request completion notification)

## 4) Proposed Typed FFI Structs
**FFI API remains byte arrays (CBOR)**: Each poll method returns a single `uint8_t* cbor_data` and `size_t cbor_len`, but each method is associated with a specific Rust type that serializes to/from CBOR.

**Rust Internal Types** (serialized to CBOR for FFI):
- `PeerConnectedEvent { node_id: String, node_info: NodeInfo }`
- `PeerDisconnected` → CBOR string: the `node_id`
- `DiscoveryDiscovered` → `PeerInfo` (serialized directly to CBOR)
- `DiscoveryUpdated` → `PeerInfo` (serialized directly to CBOR)
- `DiscoveryLost` → CBOR string: the `node_id`
- `TransportRequestEvent { request_id: String, source: String, dest: String, path: String, payload: Vec<u8> }`
- `TransportEventEvent { source: String, dest: String, path: String, payload: Vec<u8> }`
- `TransportResponseEvent { request_id: String, status: i32, payload: Vec<u8> }`

**FFI Poll API** (one per type, all return CBOR bytes):
```c
int32_t rn_transport_poll_peer_connected(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_peer_disconnected(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_discovery_discovered(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_discovery_updated(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_discovery_lost(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_request(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_event(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_response(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
```

- For string-only events (`peer_disconnected`, `discovery_lost`): CBOR is a single text string.
- For discovery discovered/updated: CBOR is the `PeerInfo` encoding (no wrapper).

**Benefits**:
- **Type Safety**: Each poll method guarantees a specific Rust type is serialized to CBOR
- **Simplicity**: Single-field events use CBOR strings; no unnecessary wrappers
- **Testing**: Can deserialize CBOR back to the specific Rust type for validation
- **Cross-Language**: C/other consumers know exactly what type to deserialize from CBOR
- **Schema Evolution**: Each type can evolve independently with proper versioning

**Memory**: All `*out_cbor` returned via poll are allocated by FFI and must be freed with `rn_free(out_cbor, out_len)`.

## 5) Channel Topology (Decision)

### Multiple channels (one per type)
- TransportInner holds a separate `mpsc::Sender<T>`/`Receiver<T>` pair per event:
  - peer_connected_tx/rx: Sender<PeerConnectedEvent>, etc.
  - peer_disconnected_tx/rx: Sender<String>
  - discovery_discovered_tx/rx: Sender<PeerInfo>
  - discovery_updated_tx/rx: Sender<PeerInfo>
  - discovery_lost_tx/rx: Sender<String>
  - request_tx/rx, event_tx/rx, response_tx/rx: structured events
- FFI poll methods per type lock their dedicated receiver and try-recv.

Pros:
- Type safety: each channel carries exactly one Rust type → mapped 1:1 to CBOR.
- Per-type backpressure and buffering; noisy categories cannot starve others.
- Simpler consumer model: consumer only polls what it cares about.

Cons:
- More channels (handles) to manage internally; slight memory and bookkeeping overhead.
- Cross-cutting producers must know the right channel to send to (but this mirrors the event taxonomy and is straightforward).

Decision: Use multiple channels (one per event type).

## 6) Rust Internal Types (non-FFI)
Define internal Rust structs that serialize to CBOR for FFI consumption:
- `PeerConnectedEvent { node_id: String, node_info: NodeInfo }`
- `String` for PeerDisconnected (node_id)
- `PeerInfo` for DiscoveryDiscovered/DiscoveryUpdated
- `String` for DiscoveryLost (node_id)
- `TransportRequestEvent { request_id: String, source: String, dest: String, path: String, payload: Vec<u8> }`
- `TransportEventEvent { source: String, dest: String, path: String, payload: Vec<u8> }`
- `TransportResponseEvent { request_id: String, status: i32, payload: Vec<u8> }`

**Serialization**: Each type implements `Serialize` for CBOR encoding when sent to FFI consumers.
**Testing**: Can deserialize CBOR back to the specific type for round-trip validation.

## 7) TransportInner Changes
- Replace:
  - events_tx: mpsc::Sender<Vec<u8>>
  - events_rx: Mutex<mpsc::Receiver<Vec<u8>>>
- With channels per type, e.g.:
  - peer_connected_tx/rx: mpsc::Sender<PeerConnectedEvent> / Mutex<mpsc::Receiver<PeerConnectedEvent>>
  - peer_disconnected_tx/rx: mpsc::Sender<String> / Mutex<mpsc::Receiver<String>>
  - discovery_discovered_tx/rx: mpsc::Sender<PeerInfo> / Mutex<mpsc::Receiver<PeerInfo>>
  - discovery_updated_tx/rx: mpsc::Sender<PeerInfo> / Mutex<mpsc::Receiver<PeerInfo>>
  - discovery_lost_tx/rx: mpsc::Sender<String> / Mutex<mpsc::Receiver<String>>
  - request_tx/rx, event_tx/rx, response_tx/rx
- Capacity: keep the existing 1024 default; can vary per type if needed later.

## 8) Producers Wiring
- Discovery binding (`rn_discovery_bind_events_to_transport`):
  - Map DiscoveryEvent::{Discovered,Updated} to discovery_*_tx.send(PeerInfo).
  - Map DiscoveryEvent::Lost(node_id) to discovery_lost_tx.send(node_id).
- Transport callbacks:
  - peer_connected → peer_connected_tx
  - peer_disconnected(node_id) → peer_disconnected_tx.send(node_id)
  - request callback → request_tx
  - event callback → event_tx
- Outgoing request completion path (`rn_transport_request`) → response_tx.

## 9) FFI Poll APIs (one per type)
- Poll methods are non-blocking; return 0 with null/0 when no event present (current pattern):

```c
int32_t rn_transport_poll_peer_connected(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_peer_disconnected(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_discovery_discovered(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_discovery_updated(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_discovery_lost(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_request(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_event(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
int32_t rn_transport_poll_response(void* transport, uint8_t** out_cbor, size_t* out_len, struct RnError* err);
```

- For string-only events: encode as CBOR text string.
- For discovery discovered/updated: encode as CBOR `PeerInfo` directly.
- For multi-field events: encode their structured Rust types.

- Each function:
  - Validates handle and output pointers.
  - `try_recv()` on the matching receiver.
  - On Ok(event): serialize event to CBOR, allocate buffer, copy CBOR bytes, return 0.
  - On Empty: set `*out_cbor = NULL` and `*out_len = 0`, return 0.
  - On Closed: set `RN_ERROR_OPERATION_FAILED` and return error.

- Memory management:
  - All `*out_cbor` buffers are allocated by FFI and must be freed with `rn_free(out_cbor, out_len)`.
  - No separate free functions needed - single `rn_free` handles all CBOR buffers.

## 10) Multiple Channels vs Single Channel (Answer)
- Multiple channels are OK and appropriate here:
  - Clear separation of concerns per event type.
  - No heterogeneity → simpler FFI and consumers.
  - Independent buffering/backpressure per stream.
- Advantage of reusing the same channel:
  - Fewer queue allocations/bookkeeping.
  - Single consumer loop (if we had a background dispatcher).
  - But it forces heterogeneity and demux complexity, undermining your typed-struct requirement.
- Achieving typed structs with a single channel:
  - Use an internal enum + dedicated demux thread to fan-out to typed queues.
  - At the FFI boundary you still need per-type poll functions reading typed sub-queues.
  - Net: you still end up with multiple typed queues; the single channel becomes an unnecessary intermediate hop.

Conclusion: Prefer multiple channels (one per event type) directly.

## 11) Error Handling & Logging
- No unwraps; RWLocks/Mutexes errors turned into `RN_ERROR_OPERATION_FAILED` with clear messages.
- Non-blocking `try_recv()` semantics preserved to avoid blocking FFI consumers.
- Unified logging per poll call with trace level for observability.

## 12) Performance Considerations
- mpsc per type with bounded capacity (e.g., 1024) to avoid unbounded memory growth.
- Zero-copy across FFI is not feasible with safe ownership; use single allocation per variable-length field.
- Avoid CBOR re-encoding internally; we forward existing CBOR where already produced (e.g., `PeerInfo`, `NodeInfo`).

## 13) Migration Plan (FFI crate only)
1. Introduce internal typed event structs and channel fields in `TransportInner` (with simplified payloads for string-only and `PeerInfo` events).
2. Wire producers to send into new channels.
3. Implement new per-type poll functions and update the header to the CBOR-returning signatures.
4. Remove `rn_transport_poll_event` heterogeneous API (no backward-compat as per rules).
5. Update tests to consume typed poll APIs and validate CBOR by deserializing to the expected Rust types (including simple string and `PeerInfo`).
6. Run `cargo fmt`, `clippy` with `-D warnings`, and all tests.

## 14) Open Questions
- Should we batch-poll (drain N events) to reduce FFI crossing overhead? (Can be added later.)
- Priority between channels when consumers poll sporadically? (Up to consumer; per-type polling empowers them.)
- Do we need blocking waits with timeouts? (Could add `*_wait(timeout_ms)` variants.)

## 15) Summary Recommendation
- Implement per-event typed channels in `TransportInner` and matching per-type poll APIs.
- Remove the heterogeneous CBOR `Vec<u8>` event bus.
- Each poll method returns CBOR bytes of a specific Rust type (strings for node_id-only, `PeerInfo` for discovery discovered/updated, structured for others).
- Use existing `rn_free(out_cbor, out_len)` for memory management - no additional free functions needed.
- Leverage existing CBOR schemas (`PeerInfo`, `NodeInfo`) and keep single-field events as CBOR text strings for simplicity.

## 16) Backward Compatibility Policy (Explicit)
- No backward compatibility. This is a full refactor.
- Remove the legacy heterogeneous `rn_transport_poll_event` API and the single `events_tx/events_rx` queue.
- Only the new per-type channels and per-type CBOR poll methods are supported.
- Update all FFI headers, tests, and examples to the new APIs; reject any legacy usage.
- No shims, no deprecation period, no feature flags. Keep code clean and organized with a single canonical path.
