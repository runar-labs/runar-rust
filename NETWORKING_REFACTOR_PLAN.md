## Networking Refactor Plan (Node, Transport, Discovery)

### Status Snapshot (current)
- Core architecture in place: `PeerDirectory`, stateless Discovery, lifecycle callbacks, nonce/role-based duplicate-connection resolution.
- Transport hardening: request path transient-retry; stop() clears `peers`/`connection_id_to_peer_id`/dial state; inbound/outbound handshake v2 (nonces); idempotent connect with placeholder; connection tasks cleanup with grace and down-debounce.
- Tests: `quic_transport_test::test_transport_message_header_bounds_checking` passes. `quic_transport_test::test_quic_transport` under stabilization; moved to single-initiator and bounded waits.
- Node reconnection test will resume once transport test is green.

### Goals
- Single source of truth for peers and capabilities in `Node`.
- Stateless discovery providers: no peer caches, no suppression; emit events only.
- Deterministic, idempotent connection handling in Transport (handles races, dedupes connections).
- Explicit lifecycle callbacks (up/down) from Transport → Node.
- Idempotent capability sync on handshake; robust re-registration after reconnect.
- Remove ad-hoc logic (e.g., lexicographic initiator); no hacks, no backwards-compat constraints.
- Adopt industry best practices from modern P2P stacks (libp2p/Bitcoin/devp2p):
  - Nonce-based duplicate-connection tie-breaker in handshake.
  - One-connection-per-peer with scoring/hysteresis to avoid flapping.
  - Per-peer dial backoff with jitter; cancel outbound when a good inbound arrives.
  - Smart dialing (avoid repeatedly dialing bad addresses; prefer recent successes/observed reachability).
  - Stateless discovery with liveness (Discovered/Updated/Lost) and receiver-side filtering.

### New Architecture
- `PeerDirectory` (inside `Node`):
  - Holds `PeerRecord { connected: bool, last_capabilities_version: i64, last_seen_at: Instant }` keyed by `peer_id`.
  - The only place tracking peers/capabilities. `known_peers` is replaced by this.

- Discovery (stateless):
  - Trait emits events `DiscoveryEvent::{Discovered(PeerInfo), Updated(PeerInfo), Lost(peer_id)}`.
  - Providers do not cache or suppress; they simply surface network signals (e.g., multicast announces, TTL expirations).
  - No `remove_discovered_peer` API.

- Transport:
  - Provides `ConnectionLifecycleCallback` with `on_up(peer_id)` and `on_down(peer_id, reason)`.
  - Deduplicates simultaneous connections deterministically in handshake via a tie-break rule using a cryptographically strong per-connection nonce.
  - `connect(peer_info)` is idempotent; if already connected, returns Ok without side effects.
  - Per-peer dial manager: backoff with jitter, cancel outstanding dials when inbound accepted, and limit concurrent dials.
  - Handshake always carries `NodeInfo { version }`, enabling capability version checks.
  - Connection manager keeps a single Active connection per peer; when duplicates exist, choose the deterministic winner and close the loser gracefully with hysteresis to prevent thrash.

- Node orchestration:
  - Subscribes to discovery events; applies per-peer debounce (e.g., 300–500ms) and per-peer connect mutex.
  - On `Discovered/Updated`:
    - If `connected == true`: ignore.
    - Else: schedule `connect(peer_info)`.
  - On `on_up(peer_id)`: mark connected, request/apply capabilities via handshake path; diff with `PeerDirectory` and update registry.
  - On `on_down(peer_id)`: mark disconnected; remove remote services/subscriptions; await next discovery event for reconnect.

### Public API Changes (Breaking)
- Discovery trait changes (example sketch):
  ```rust
  pub enum DiscoveryEvent { Discovered(PeerInfo), Updated(PeerInfo), Lost(String) }

  #[async_trait]
  pub trait NodeDiscovery: Send + Sync {
      async fn start(&self) -> Result<()>;
      async fn stop(&self) -> Result<()>;
      async fn subscribe(&self, listener: Arc<dyn Fn(DiscoveryEvent) -> Pin<Box<dyn Future<Output=()> + Send>> + Send + Sync>) -> Result<()>;
      async fn update_local_node_info(&self, new_node_info: NodeInfo) -> Result<()>;
  }
  ```
  - Remove: `remove_discovered_peer`.

- Transport trait changes (example sketch):
  ```rust
  pub type ConnectionLifecycleCallback = Arc<dyn Fn(String, ConnectionState, Option<String>) -> Pin<Box<dyn Future<Output=()> + Send>> + Send + Sync>;

  pub enum ConnectionState { Up, Down }

  pub trait NetworkTransport: Send + Sync {
      async fn start(self: Arc<Self>) -> Result<(), NetworkError>;
      async fn stop(&self) -> Result<(), NetworkError>;
      async fn connect_peer(self: Arc<Self>, peer: PeerInfo) -> Result<(), NetworkError>; // idempotent
      async fn is_connected(&self, peer_id: &str) -> bool;
      async fn set_lifecycle_callback(&self, cb: ConnectionLifecycleCallback);
      // request/publish unchanged
  }
  ```

### Implementation Steps (No-minimal approach)
1) Node: Introduce `PeerDirectory`
   - Replace `known_peers` with `PeerDirectory` and migrate all uses.
   - Centralize capability version tracking and connected flag.

2) Discovery: Stateless providers
   - Refactor `MulticastDiscovery` and `MemoryDiscovery` to remove peer caches and suppressions.
   - Implement `subscribe(listener)` that emits `DiscoveryEvent`s on announce (Discovered/Updated) and TTL expiration (Lost).
   - Update all call sites and tests to the new event API.

3) Transport: Deterministic handshake and lifecycle
  - Add tie-break handshake fields: `node_id`, `nonce` (secure random per-connection).
  - Deterministic rule: if both sides have connections, compute a total order over `(local_id, local_nonce, remote_id, remote_nonce)` and both sides keep the same winner; close the other gracefully. Add small hysteresis window to avoid oscillation.
  - Ensure only a single `on_up` and `on_down` fires per transition. [done via task-grace and debounce]
  - Make `connect_peer` idempotent. [done]
  - Per-peer dial control: exponential backoff with jitter; cancel outbound dial when inbound reaches `Connected`; cap concurrent dials; prefer addresses with recent success (smart dialing). [backoff+cancel done; smart dialing deferred]

4) Node: Orchestration and debouncing
   - Per-peer async mutex to guard connect attempts.
   - Debounce discovery events per peer (drop bursts, coalesce to one connect attempt).
   - On `on_up`, call capability sync (handshake path already sends/receives `NodeInfo`).
   - On `on_down`, cleanup service registry and subscriptions linked to that peer.
   - Ignore Discovered/Updated for peers already marked connected.

5) Capability processing
   - Ensure `process_remote_capabilities` diffs and updates `PeerDirectory.last_capabilities_version`. [in progress]
   - Re-register remote services/action handlers and subscriptions idempotently. [in progress]

6) Test suite updates (API changes only)
   - Update tests to new Discovery API while preserving intent and scenarios.
   - Add new tests:
     - Simultaneous connect race → single surviving connection, `on_up` fires once on the winner only; loser closes cleanly. [partially covered; stabilizing]
     - Reconnect after restart: discovery event → connect → handshake → remote handlers restored.
     - Capability update versioning across reconnect.
     - Dial backoff and cancelation: inbound arrives while outbound in-flight → outbound canceled deterministically.
     - Duplicate connection scoring/hysteresis prevents flapping under repeated races.

7) Observability
   - Structured logs for connection races, lifecycle transitions, and capability diffs.
   - Logs for backoff decisions, dial cancelations, and duplicate-resolution decisions (including both nonces and winner/loser ids).
   - Metrics (optional) for connects, disconnects, retries, duplicate resolutions. (metrics is out of scope for now.. focus on having proper logs so we can debug issues going forward.)

8) Operational hardening
   - Graceful shutdown of QUIC endpoints and short retry loop on UDP bind to tolerate fast restarts.
   - Persist peerbook data needed for smart dialing (last success/failure timestamps) if/when we add persistence.

### Acceptance Criteria
- All existing network tests (updated for API) pass, including reconnection and multicast tests.
- Deterministic nonce-based resolution of duplicate connections verified by new tests with no split-brain (both sides keep the same connection) and no flapping.
- After disconnect and restart, remote services are re-registered and calls succeed.
- Outbound dial backoff with jitter is observable and respected; inbound acceptance cancels redundant outbound in-flight dials.
- Only one Active connection per peer at steady state; loser connection closes cleanly and lifecycle events fire exactly once per transition.

### Migration Notes
- This refactor is intentionally breaking. Update:
  - Discovery trait implementors and call sites.
  - Node internal peer tracking (`PeerDirectory`).
  - Transport lifecycle wiring in `Node::start_networking`.
  - Tests to use `DiscoveryEvent` stream/callbacks.

- [x] Create `PeerDirectory` and integrate across `Node`.
- [x] Refactor Discovery trait to stateless events; remove caches and `remove_discovered_peer`.
- [x] Update `MulticastDiscovery` and `MemoryDiscovery` to emit `DiscoveryEvent`s (Discovered/Updated/Lost).
- [x] Transport: nonce-based handshake tie-breaker and deterministic duplicate resolution.
- [~] Transport: finalize idempotent `connect_peer` semantics (edge cases) and unify inbound/outbound cancel. [mostly done; continue stabilizing handshake race]
- [x] Transport: implement per-peer dial backoff with jitter and dial cancelation on inbound.
- [x] Transport: add lifecycle callback and fire `Up/Down` reliably.
- [x] Node: implement per-peer connect mutex and debounce.
- [x] Node: wire lifecycle callbacks to capability sync and cleanup.
- [ ] Ensure `process_remote_capabilities` is idempotent and tracked in `PeerDirectory` (finalize version tracking/diffing).
- [ ] Update all affected tests for new Discovery API (complete sweep).
- [ ] Add tests: duplicate-resolution, backoff/cancelation, restart reconnection, capability versioning, anti-flap.
- [x] Observability: structured logs for duplicate-resolution; [~] add dial backoff logs.
- [ ] Run full test suite; fix regressions.

### Recent Design Decisions (new)
- `replace_or_keep_connection` returns bool and updates `connection_id_to_peer_id` for the new connection id; losers are closed only if their conn id differs from the new one (prevents self-close when replacing placeholders).
- Inbound `bi_accept_loop`: parse v2 `HandshakeData` (nonce+role), fall back to v1 `NodeInfo`. After deciding winner, skip further processing on the losing inbound.
- Outbound handshake returns responder nonce; after success, we call `replace_or_keep_connection` to converge to a single active connection.
- Transient races handled by:
  - Request path: up to 3 transparent retries on `closed/connection lost/duplicate` with small sleeps.
  - Task cleanup: short grace delay and suppression of `on_down` when a new active conn exists.
- Stop semantics: clear `peers`, `connection_id_to_peer_id`, `dial_backoff`, and `dial_cancel` to avoid stale state across restarts.
- Test approach: use single-initiator dial in transport test and bounded connectivity waits to avoid masking issues with simultaneous dials while we stabilize the race handling.

### Immediate Next Steps
- Add precise logs around handshake/dup-resolution showing `(existing_id, existing nonces)` vs `(candidate_id, candidate nonces)` and winner.
- Guard sending handshake response to only the surviving connection id in inbound path.
- Stabilize `quic_transport_test::test_quic_transport`; then proceed to Node-level reconnection test.

### Notes
- Clippy/style fixes come last, after tests are green, per project rules.


